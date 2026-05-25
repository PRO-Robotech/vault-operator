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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/PRO-Robotech/vault-operator/test/utils"
)

// inClusterAPIServerHost is the URL the kube-apiserver presents to in-cluster
// clients. The Kind cluster uses the default kubernetes.default.svc Service.
const inClusterAPIServerHost = "https://kubernetes.default.svc:443"

// FetchClusterRootCA reads the in-cluster CA bundle from the well-known
// `kube-root-ca.crt` ConfigMap present in every namespace.
//
// The CA is needed for both:
//   - VaultConfig kubernetes_ca_cert (so Vault can verify TokenReview replies),
//   - the kubeconfig Secret rendered by RenderInClusterKubeconfigSecret.
//
// We use `kubectl get -o template` instead of `-o jsonpath` because jsonpath's
// dot-escape syntax is brittle through utils.Run's CombinedOutput (any
// stderr noise from kubectl gets mixed in and corrupts the PEM).
func FetchClusterRootCA(namespace string) (string, error) {
	cmd := exec.Command("kubectl", "get", "configmap", "kube-root-ca.crt",
		"-n", namespace, "-o", `go-template={{ index .data "ca.crt" }}`)
	out, err := utils.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("get kube-root-ca.crt in %s: %w", namespace, err)
	}
	ca := strings.TrimSpace(out)
	if !strings.Contains(ca, "BEGIN CERTIFICATE") {
		return "", fmt.Errorf("kube-root-ca.crt in %s did not yield a PEM bundle (got %d bytes)", namespace, len(ca))
	}
	return ca, nil
}

// CreateClusterAdminSA creates an SA + ClusterRoleBinding that grants
// cluster-admin in the Kind cluster, then returns a JWT for it via the
// TokenRequest API.
//
// This SA is what the kubeconfig Secret will authenticate as — the operator
// uses that kubeconfig to SSA the token-reviewer SA + CRB in the "target"
// cluster (which in e2e is the same Kind cluster). For production each
// target cluster gets a narrower kubeconfig issued by certificate-set.
func CreateClusterAdminSA(namespace, name string) (string, error) {
	for _, manifest := range []string{
		fmt.Sprintf(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":%q,"namespace":%q}}`, name, namespace),
		fmt.Sprintf(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":%q},
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"cluster-admin"},
			"subjects":[{"kind":"ServiceAccount","name":%q,"namespace":%q}]}`, name+"-admin", name, namespace),
	} {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = bytes.NewReader([]byte(manifest))
		if _, err := utils.Run(cmd); err != nil {
			return "", err
		}
	}
	// Mint a TokenRequest for the SA via `kubectl create token`.
	cmd := exec.Command("kubectl", "create", "token", name,
		"-n", namespace,
		"--duration=1h",
	)
	out, err := utils.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("create token for %s/%s: %w", namespace, name, err)
	}
	return strings.TrimSpace(out), nil
}

// GrantAuthDelegator binds `system:auth-delegator` to the given SA via a
// ClusterRoleBinding. Vault uses this SA's JWT to call TokenReview on each
// pod login; without `system:auth-delegator` the apiserver denies the call
// with 403 → Vault returns "permission denied" on /login (OPERATOR-SPEC §3.2).
func GrantAuthDelegator(saNamespace, saName, bindingName string) error {
	manifest := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: %s
  namespace: %s
`, bindingName, saName, saNamespace)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(manifest))
	_, err := utils.Run(cmd)
	return err
}

// CreateOperatorSAToken mints a JWT for an existing SA (typically the
// operator's own SA). audience controls what Vault expects in the token's
// `aud` claim during TokenReview.
func CreateOperatorSAToken(namespace, name string, audiences []string) (string, error) {
	args := []string{"create", "token", name, "-n", namespace, "--duration=1h"}
	for _, a := range audiences {
		args = append(args, "--audience="+a)
	}
	cmd := exec.Command("kubectl", args...)
	out, err := utils.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// RenderInClusterKubeconfig produces a kubeconfig YAML (JSON-shaped, which
// is a valid YAML subset) authenticating as the given SA token against the
// in-cluster apiserver.
func RenderInClusterKubeconfig(caPEM, token string) ([]byte, error) {
	cl := map[string]interface{}{"server": inClusterAPIServerHost}
	if caPEM != "" {
		cl["certificate-authority-data"] = base64.StdEncoding.EncodeToString([]byte(caPEM))
	} else {
		cl["insecure-skip-tls-verify"] = true
	}
	doc := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters":   []interface{}{map[string]interface{}{"name": "kind", "cluster": cl}},
		"users": []interface{}{map[string]interface{}{
			"name": "kind",
			"user": map[string]interface{}{"token": token},
		}},
		"contexts": []interface{}{map[string]interface{}{
			"name":    "kind",
			"context": map[string]interface{}{"cluster": "kind", "user": "kind"},
		}},
		"current-context": "kind",
	}
	return json.MarshalIndent(doc, "", "  ")
}

// ApplyKubeconfigSecret puts the rendered kubeconfig into a Secret in the
// claim's namespace, under the conventional "value" key.
func ApplyKubeconfigSecret(name, namespace string, kubeconfig []byte) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
  value: %s
`, name, namespace, base64.StdEncoding.EncodeToString(kubeconfig))

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(manifest))
	_, err := utils.Run(cmd)
	return err
}

// ApplyVaultConfig creates (or updates) a VaultConfig pointing at the in-cluster
// Vault Service.
func ApplyVaultConfig(name, mgmtAuthPath, mgmtRole, sharedKVMount string) error {
	manifest := fmt.Sprintf(`apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata:
  name: %s
spec:
  address: %s
  managerAuth:
    method: kubernetes
    mountPath: %s
    role: %s
  storage:
    kvMountPath: %s
`, name, vaultSvcAddress, mgmtAuthPath, mgmtRole, sharedKVMount)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(manifest))
	_, err := utils.Run(cmd)
	return err
}

// ApplyVaultClaim renders + applies a minimal VaultClaim referencing the
// VaultConfig + kubeconfig Secret created by the earlier helpers.
func ApplyVaultClaim(name, namespace, vaultConfigName, kubeconfigSecret string) error {
	manifest := fmt.Sprintf(`apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata:
  name: %s
  namespace: %s
spec:
  vaultConfigRef:
    name: %s
  clusterRef:
    name: %s
    kubeconfigSecret: %s
  secretsPrefix: clusters/%s
  auth:
    mountPath: kubernetes-%s
    autoCreate: true
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer
        autoCreate: true
      ttl: 24h
  policies:
  - name: %s-vmauth-reader
    rules: |
      path "secret/data/clusters/%s/monitoring/vmauth/*" {
        capabilities = ["read", "list"]
      }
  roles:
  - name: vmauth-reader
    boundServiceAccounts:
      name: vmauth
      namespace: monitoring
    policies: [%s-vmauth-reader]
    tokenTTL: 1h
`, name, namespace, vaultConfigName, name, kubeconfigSecret, name, name, name, name, name)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(manifest))
	_, err := utils.Run(cmd)
	return err
}

// DeleteVaultClaim removes the claim and waits for the finalizer to drop.
func DeleteVaultClaim(name, namespace string) error {
	cmd := exec.Command("kubectl", "delete", "vaultclaim", name,
		"-n", namespace,
		"--ignore-not-found",
		"--wait=true",
		"--timeout=60s",
	)
	_, err := utils.Run(cmd)
	return err
}

// GetVaultClaimPhase shells out to kubectl and returns the current Phase.
// Returns "" when the object is gone.
func GetVaultClaimPhase(name, namespace string) (string, error) {
	cmd := exec.Command("kubectl", "get", "vaultclaim", name,
		"-n", namespace,
		"-o", "jsonpath={.status.phase}",
		"--ignore-not-found",
	)
	out, err := utils.Run(cmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
