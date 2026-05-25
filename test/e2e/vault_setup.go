//go:build e2e
// +build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/PRO-Robotech/vault-operator/test/utils"
)

// VaultManifests render the Namespace + Deployment + Service for a Vault
// dev-mode pod inside the Kind cluster. The image (`hashicorp/vault:1.18`) is
// pulled directly from Docker Hub.
//
// Dev mode auto-initialises + unseals + creates `secret/` KV-v2 mount + sets
// the root token to the fixed value below — exactly the bootstrap surface
// the operator expects from a freshly-provisioned Vault.
const (
	vaultNamespace  = "vault-system"
	vaultRootToken  = "dev-root-token"
	vaultImage      = "hashicorp/vault:1.18"
	vaultLocalPort  = "18200"
	vaultPortInPod  = "8200"
	vaultSvcAddress = "http://vault.vault-system.svc:8200"
)

const vaultManifestsYAML = `
apiVersion: v1
kind: Namespace
metadata:
  name: vault-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
  namespace: vault-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
    spec:
      containers:
      - name: vault
        image: hashicorp/vault:1.18
        args:
        - server
        - -dev
        - -dev-root-token-id=dev-root-token
        - -dev-listen-address=0.0.0.0:8200
        ports:
        - containerPort: 8200
        env:
        - name: VAULT_ADDR
          value: http://127.0.0.1:8200
        readinessProbe:
          httpGet:
            path: /v1/sys/health
            port: 8200
          initialDelaySeconds: 3
          periodSeconds: 2
        securityContext:
          capabilities:
            add: ["IPC_LOCK"]
---
apiVersion: v1
kind: Service
metadata:
  name: vault
  namespace: vault-system
spec:
  selector:
    app: vault
  ports:
  - port: 8200
    targetPort: 8200
    name: api
`

// ApplyVaultManifests deploys the Vault Namespace+Deployment+Service into the
// Kind cluster via `kubectl apply -f -`. Idempotent.
func ApplyVaultManifests() error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(vaultManifestsYAML))
	_, err := utils.Run(cmd)
	return err
}

// DeleteVaultManifests removes everything ApplyVaultManifests created.
func DeleteVaultManifests() error {
	cmd := exec.Command("kubectl", "delete", "-f", "-", "--ignore-not-found", "--wait=false")
	cmd.Stdin = bytes.NewReader([]byte(vaultManifestsYAML))
	_, err := utils.Run(cmd)
	return err
}

// WaitVaultReady blocks until the Vault Deployment reports Available.
func WaitVaultReady(timeout time.Duration) error {
	cmd := exec.Command("kubectl", "wait", "deployment/vault",
		"--for", "condition=Available",
		"--namespace", vaultNamespace,
		"--timeout", timeout.String(),
	)
	_, err := utils.Run(cmd)
	return err
}

// PortForward runs `kubectl port-forward svc/vault` in the background and
// returns a stop function. The forward is alive until stop() is called.
//
// We do not use Service ClusterIP from the test (the test runs outside the
// Kind network) — port-forward is the standard way to reach in-cluster
// services from the host.
func PortForward(ctx context.Context) (stop func(), err error) {
	cmd := exec.CommandContext(ctx, "kubectl", "port-forward",
		"-n", vaultNamespace,
		"svc/vault",
		fmt.Sprintf("%s:%s", vaultLocalPort, vaultPortInPod),
	)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start kubectl port-forward: %w", err)
	}
	// Wait until the local port answers.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, dErr := net.DialTimeout("tcp", "127.0.0.1:"+vaultLocalPort, 200*time.Millisecond)
		if dErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	stopFn := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
	if time.Now().After(deadline) {
		stopFn()
		return nil, fmt.Errorf("port-forward to vault never accepted connections")
	}
	return stopFn, nil
}

// VaultLocalAddr is the http URL the test can use to talk to Vault while
// port-forward is active.
func VaultLocalAddr() string {
	return "http://127.0.0.1:" + vaultLocalPort
}

// BootstrapVaultInKind wires up the operator's auth flow inside the Kind
// Vault. Mirrors test/e2e_pipeline/bootstrap.go but uses the locally-
// forwarded address, and reads the in-cluster apiserver coordinates from
// the operator-side reality (kubernetes.default.svc + the in-cluster CA).
//
// The reviewer-JWT used here is an SA token from the Kind cluster itself —
// we mint one via TokenRequest against the "default" SA in the default
// namespace, then assemble auth/{mgmt}/config with it.
func BootstrapVaultInKind(ctx context.Context, kubernetesHost string, kubernetesCACert string, tokenReviewerJWT string, mgmtAuthPath, mgmtRole string, boundNS, boundSA string) error {
	addr := VaultLocalAddr()

	// 1. Enable kubernetes auth.
	if err := vaultPostKind(ctx, addr, "/v1/sys/auth/"+mgmtAuthPath, map[string]string{
		"type":        "kubernetes",
		"description": "vault-operator e2e (kind) manager auth",
	}); err != nil && !strings.Contains(err.Error(), "path is already in use") {
		return fmt.Errorf("enable auth %q: %w", mgmtAuthPath, err)
	}

	// 2. Write config — kubernetes_host + ca + token_reviewer_jwt.
	if err := vaultPostKind(ctx, addr, "/v1/auth/"+mgmtAuthPath+"/config", map[string]interface{}{
		"kubernetes_host":        kubernetesHost,
		"kubernetes_ca_cert":     kubernetesCACert,
		"token_reviewer_jwt":     tokenReviewerJWT,
		"disable_iss_validation": true,
		"disable_local_ca_jwt":   true,
	}); err != nil {
		return fmt.Errorf("write auth config: %w", err)
	}

	// 3. Write vault-operator-admin policy.
	if err := vaultPutKind(ctx, addr, "/v1/sys/policies/acl/vault-operator-admin", map[string]string{
		"policy": vaultOperatorAdminKindPolicy,
	}); err != nil {
		return fmt.Errorf("write vault-operator-admin policy: %w", err)
	}

	// 4. Create role bound to (operator SA, namespace).
	return vaultPostKind(ctx, addr, "/v1/auth/"+mgmtAuthPath+"/role/"+mgmtRole, map[string]interface{}{
		"bound_service_account_names":      []string{boundSA},
		"bound_service_account_namespaces": []string{boundNS},
		"token_policies":                   []string{"vault-operator-admin"},
		"token_ttl":                        3600,
	})
}

// vaultOperatorAdminKindPolicy is the production policy from OPERATOR-SPEC §3.3.
//
// Note on Vault glob syntax: `+` matches a WHOLE path segment (up to `/`),
// NOT a partial match within a segment. So `sys/auth/kubernetes-+` does
// NOT match `sys/auth/kubernetes-ec8a00`. We use whole-segment wildcard
// `+` and rely on naming conventions (`kubernetes-{name}`) for isolation
// between claims.
const vaultOperatorAdminKindPolicy = `
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
`

func vaultPostKind(ctx context.Context, addr, path string, body interface{}) error {
	return vaultRequestKind(ctx, addr, http.MethodPost, path, body)
}

func vaultPutKind(ctx context.Context, addr, path string, body interface{}) error {
	return vaultRequestKind(ctx, addr, http.MethodPut, path, body)
}

func vaultRequestKind(ctx context.Context, addr, method, path string, body interface{}) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, addr+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", vaultRootToken)
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
