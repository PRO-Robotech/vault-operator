/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e_pipeline

import (
	"context"
	"encoding/json"
	"fmt"
)

// vaultSecretOperatorAdminPolicy: write to per-cluster paths + read of the
// source prefix; `delete` is included so the Purge path works in e2e.
const vaultSecretOperatorAdminPolicy = `
path "sys/mounts"                   { capabilities = ["read", "list"] }
path "secret/data/clusters/+/*"     { capabilities = ["create", "update", "read"] }
path "secret/metadata/clusters/+/*" { capabilities = ["read", "list", "delete"] }
path "secret/data/system/*"         { capabilities = ["read"] }
path "secret/metadata/system/*"     { capabilities = ["read", "list"] }
path "auth/token/renew-self"        { capabilities = ["update"] }
path "auth/token/lookup-self"       { capabilities = ["read"] }
`

// BootstrapSecretRole writes the vault-secret-operator-admin policy and creates
// the role bound to the given SA, reusing the kubernetes auth method already
// enabled by BootstrapVaultDev.
func BootstrapSecretRole(
	ctx context.Context, srv *VaultDevServer, authPath, role string, boundNames, boundNamespaces []string,
) error {
	if err := vaultPut(ctx, srv, "/v1/sys/policies/acl/vault-secret-operator-admin", map[string]string{
		"policy": vaultSecretOperatorAdminPolicy,
	}); err != nil {
		return fmt.Errorf("write vault-secret-operator-admin policy: %w", err)
	}
	if err := vaultPost(ctx, srv, "/v1/auth/"+authPath+"/role/"+role, map[string]interface{}{
		"bound_service_account_names":      boundNames,
		"bound_service_account_namespaces": boundNamespaces,
		"token_policies":                   []string{"vault-secret-operator-admin"},
		"token_ttl":                        3600,
	}); err != nil {
		return fmt.Errorf("create role %q: %w", role, err)
	}
	return nil
}

// SeedKV writes a KV-v2 secret as the dev root (the source for copy tests).
func SeedKV(ctx context.Context, srv *VaultDevServer, mount, path string, data map[string]interface{}) error {
	return vaultPost(ctx, srv, "/v1/"+mount+"/data/"+path, map[string]interface{}{"data": data})
}

// ReadKVRoot reads a KV-v2 secret's inner data as the dev root. A non-2xx
// (e.g. 404 after Purge) is returned as an error.
func ReadKVRoot(ctx context.Context, srv *VaultDevServer, mount, path string) (map[string]interface{}, error) {
	body, err := vaultGet(ctx, srv, "/v1/"+mount+"/data/"+path)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode kv data: %w", err)
	}
	return raw.Data.Data, nil
}
