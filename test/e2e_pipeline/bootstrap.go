/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e_pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// BootstrapConfig captures what `BootstrapVaultDev` needs to wire up:
//   - ManagerAuthPath: where the operator's own login lives (e.g.
//     "kubernetes-mgmt"). Auth method is enabled at this path.
//   - ManagerRole: name of the role bound to the operator's SA inside that
//     auth method (e.g. "vault-operator").
//   - KubernetesHost / KubernetesCACert: target apiserver coordinates for
//     the auth method config (in our e2e harness this is envtest's apiserver).
//   - TokenReviewerJWT: the SA JWT Vault uses for TokenReview when validating
//     operator-side logins.
//   - SABoundNames / SABoundNamespaces: which (ns, name) tuples can log in
//     against the role.
type BootstrapConfig struct {
	ManagerAuthPath   string
	ManagerRole       string
	KubernetesHost    string
	KubernetesCACert  string
	TokenReviewerJWT  string
	SABoundNames      []string
	SABoundNamespaces []string
}

// BootstrapVaultDev wires up the operator's login flow in a freshly-started
// dev Vault. Performed using the dev-mode root token. After this returns,
// `internal/vault.Client` can log in with the SA JWT and proceed as in
// production.
//
// Steps:
//
//  1. Enable kubernetes auth at sys/auth/{ManagerAuthPath}.
//  2. Write its config (kubernetes_host, kubernetes_ca_cert, token_reviewer_jwt).
//  3. Write policy `vault-operator-admin` allowing the operator everything
//     it needs (namespace policy).
//  4. Create role {ManagerRole} bound to (SABoundNames, SABoundNamespaces)
//     with `vault-operator-admin` policy.
func BootstrapVaultDev(ctx context.Context, srv *VaultDevServer, cfg BootstrapConfig) error {
	// 1. Enable auth method.
	if err := vaultPost(ctx, srv, "/v1/sys/auth/"+cfg.ManagerAuthPath, map[string]string{
		"type":        "kubernetes",
		"description": "vault-operator e2e manager auth",
	}); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("enable auth %q: %w", cfg.ManagerAuthPath, err)
	}

	// 2. Write its config.
	if err := vaultPost(ctx, srv, "/v1/auth/"+cfg.ManagerAuthPath+"/config", map[string]interface{}{
		"kubernetes_host":        cfg.KubernetesHost,
		"kubernetes_ca_cert":     cfg.KubernetesCACert,
		"token_reviewer_jwt":     cfg.TokenReviewerJWT,
		"disable_iss_validation": true,
		"disable_local_ca_jwt":   true,
	}); err != nil {
		return fmt.Errorf("write auth config: %w", err)
	}

	// 3. Write operator policy.
	if err := vaultPut(ctx, srv, "/v1/sys/policies/acl/vault-operator-admin", map[string]string{
		"policy": vaultOperatorAdminPolicy,
	}); err != nil {
		return fmt.Errorf("write vault-operator-admin policy: %w", err)
	}

	// 4. Create role.
	if err := vaultPost(ctx, srv, "/v1/auth/"+cfg.ManagerAuthPath+"/role/"+cfg.ManagerRole, map[string]interface{}{
		"bound_service_account_names":      cfg.SABoundNames,
		"bound_service_account_namespaces": cfg.SABoundNamespaces,
		"token_policies":                   []string{"vault-operator-admin"},
		"token_ttl":                        3600,
	}); err != nil {
		return fmt.Errorf("create role %q: %w", cfg.ManagerRole, err)
	}
	return nil
}

// EnableTransitMount mounts the engine as the platform would; the operator cannot.
func EnableTransitMount(ctx context.Context, srv *VaultDevServer, mountPath string) error {
	err := vaultPost(ctx, srv, "/v1/sys/mounts/"+mountPath, map[string]string{
		"type":        "transit",
		"description": "vault-operator e2e transit engine",
	})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("enable transit at %q: %w", mountPath, err)
	}
	return nil
}

// ReadTransitKeyRaw reads a key as dev root, bypassing the client under test.
func ReadTransitKeyRaw(
	ctx context.Context, srv *VaultDevServer, mountPath, name string,
) (map[string]interface{}, error) {
	body, err := vaultGet(ctx, srv, "/v1/"+mountPath+"/keys/"+name)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode transit key %q: %w", name, err)
	}
	return raw.Data, nil
}

// DeleteTransitKeyRaw removes a key out-of-band; deletion must be allowed first.
func DeleteTransitKeyRaw(ctx context.Context, srv *VaultDevServer, mountPath, name string) error {
	if err := vaultPost(ctx, srv, "/v1/"+mountPath+"/keys/"+name+"/config", map[string]interface{}{
		"deletion_allowed": true,
	}); err != nil {
		return fmt.Errorf("allow deletion of %q: %w", name, err)
	}
	return vaultRequest(ctx, srv, http.MethodDelete, "/v1/"+mountPath+"/keys/"+name, nil)
}

// EnsureKVMount checks the shared `secret/` KV-v2 mount exists; vault dev
// already enables it by default. Provided here for clarity and as a fail-fast
// in case the dev banner ever drops it.
func EnsureKVMount(ctx context.Context, srv *VaultDevServer, mountPath string) error {
	resp, err := vaultGet(ctx, srv, "/v1/sys/mounts")
	if err != nil {
		return err
	}
	key := mountPath + "/"
	type entry struct {
		Type string `json:"type"`
	}
	var raw struct {
		Data map[string]entry `json:"data"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return fmt.Errorf("decode sys/mounts: %w", err)
	}
	if e, ok := raw.Data[key]; ok && e.Type == "kv" {
		return nil
	}
	// Fall back to top-level (older API shape).
	var top map[string]entry
	if err := json.Unmarshal(resp, &top); err == nil {
		if e, ok := top[key]; ok && e.Type == "kv" {
			return nil
		}
	}
	return fmt.Errorf("shared KV mount %q not found in vault dev", mountPath)
}

// vaultOperatorAdminPolicy is the HCL body installed by step 3 — the
// production operator policy.
//
// Note on Vault glob syntax: `+` matches a WHOLE path segment (up to `/`),
// NOT a partial match within a segment. So `sys/auth/kubernetes-+` does
// NOT match `sys/auth/kubernetes-ec8a00`. We use whole-segment wildcard
// `+` and rely on naming conventions (`kubernetes-{name}`) for isolation
// between claims.
const vaultOperatorAdminPolicy = `
path "sys/auth/+"               { capabilities = ["create", "read", "update", "delete", "sudo"] }
path "sys/auth/+/*"             { capabilities = ["create", "read", "update", "delete", "sudo"] }
path "auth/+/config"            { capabilities = ["create", "read", "update"] }
path "auth/+/role/*"            { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/+/role"              { capabilities = ["list"] }
path "sys/auth"                 { capabilities = ["read", "list"] }
path "sys/mounts"               { capabilities = ["read", "list"] }
path "sys/policies/acl/*"       { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/acl"         { capabilities = ["list"] }
path "auth/token/renew-self"    { capabilities = ["update"] }
path "auth/token/lookup-self"   { capabilities = ["read"] }

# Transit: keys only. No encrypt/decrypt, rotate, export or delete.
path "transit/keys/+"           { capabilities = ["create", "read", "update"] }
path "transit/keys/+/config"    { capabilities = ["update"] }
`

// vaultPost issues an authenticated POST as the dev root.
func vaultPost(ctx context.Context, srv *VaultDevServer, path string, body interface{}) error {
	return vaultRequest(ctx, srv, http.MethodPost, path, body)
}

// vaultPut issues an authenticated PUT as the dev root.
func vaultPut(ctx context.Context, srv *VaultDevServer, path string, body interface{}) error {
	return vaultRequest(ctx, srv, http.MethodPut, path, body)
}

// vaultGet issues an authenticated GET as the dev root and returns the body.
func vaultGet(ctx context.Context, srv *VaultDevServer, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.Addr+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", srv.RootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vault GET %s: %d %s: %s", path, resp.StatusCode, resp.Status, body)
	}
	return body, nil
}

func vaultRequest(ctx context.Context, srv *VaultDevServer, method, path string, body interface{}) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, srv.Addr+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", srv.RootToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault %s %s: %d %s: %s", method, path, resp.StatusCode, resp.Status, respBody)
	}
	return nil
}

// isAlreadyExists detects the Vault 400 reply when an auth method already
// exists at the given path (idempotency on repeated bootstrap).
func isAlreadyExists(err error) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("path is already in use"))
}
