//go:build e2e
// +build e2e

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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	mgmtAuthPath  = "kubernetes-mgmt"
	mgmtRole      = "vault-operator"
	operatorNS    = "vault-operator-system"
	operatorSA    = "vault-operator"
	claimNS       = "default"
	claimName     = "ec8a00"
	sharedKVMount = "secret"
)

// TestPipelineE2E exercises the full VaultClaim pipeline against a real
// `vault server -dev` and envtest's kube-apiserver. Skips if either is
// unavailable (vault binary missing / KUBEBUILDER_ASSETS unset).
func TestPipelineE2E(t *testing.T) {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stderr)))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Spawn Vault dev (skip if binary missing).
	vaultSrv, err := NewVaultDevServer(ctx)
	if err != nil {
		if errors.Is(err, ErrVaultBinaryMissing) {
			t.Skipf("vault binary not in PATH; skipping pipeline e2e: %v", err)
		}
		t.Fatalf("start vault dev: %v", err)
	}
	defer func() { _ = vaultSrv.Close() }()

	if err := EnsureKVMount(ctx, vaultSrv, sharedKVMount); err != nil {
		t.Fatalf("ensure KV mount: %v", err)
	}

	// Start envtest.
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	if bin := firstEnvtestBinaryDir(); bin != "" {
		testEnv.BinaryAssetsDirectory = bin
	}

	envCfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("envtest.Start (KUBEBUILDER_ASSETS or bin/k8s missing?): %v", err)
	}
	defer func() { _ = testEnv.Stop() }()

	k8sClient, err := client.New(envCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("k8s client: %v", err)
	}
	kc, err := kubernetes.NewForConfig(envCfg)
	if err != nil {
		t.Fatalf("kube clientset: %v", err)
	}

	// Operator SA in envtest + ClusterRoleBinding to system:auth-delegator
	// so TokenReview against this SA succeeds.
	if err := bootstrapOperatorSA(ctx, k8sClient); err != nil {
		t.Fatalf("bootstrap operator SA: %v", err)
	}

	// Issue a JWT for the operator SA, audience = mgmtAuthPath login url.
	// Default audience (nil): Vault's TokenReview omits audiences, so envtest's
	// apiserver validates against its default api-audiences. A custom "vault"
	// audience would need matching apiserver --api-audiences + Vault config.
	operatorJWT, err := issueSAJWT(ctx, kc, operatorNS, operatorSA, nil)
	if err != nil {
		t.Fatalf("issue operator SA JWT: %v", err)
	}

	// Bootstrap Vault: enable kubernetes-mgmt auth, write operator policy + role.
	caBase64 := base64.StdEncoding.EncodeToString(envCfg.CAData)
	_ = caBase64 // CABundle for kubeconfig rendering only
	if err := BootstrapVaultDev(ctx, vaultSrv, BootstrapConfig{
		ManagerAuthPath:   mgmtAuthPath,
		ManagerRole:       mgmtRole,
		KubernetesHost:    envCfg.Host,
		KubernetesCACert:  string(envCfg.CAData),
		TokenReviewerJWT:  operatorJWT,
		SABoundNames:      []string{operatorSA},
		SABoundNamespaces: []string{operatorNS},
	}); err != nil {
		t.Fatalf("bootstrap vault: %v", err)
	}

	// Mounted by the harness: the operator policy has no sys/mounts write.
	if err := EnableTransitMount(ctx, vaultSrv, "transit"); err != nil {
		t.Fatalf("enable transit mount: %v", err)
	}

	// Build reconcilers using the real factory + real target.ClusterManager.
	factory := &controller.DefaultVaultClientFactory{
		JWTSource: vault.StaticJWTSource(operatorJWT),
	}
	targetMgr := target.NewClusterManager(scheme)

	vcfgReconciler := &controller.VaultConfigReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		VaultFactory: factory,
	}
	claimReconciler := &controller.VaultClaimReconciler{
		Client:        k8sClient,
		Scheme:        scheme,
		VaultFactory:  factory,
		TargetManager: targetMgr,
	}

	// Create VaultConfig pointing at the dev vault.
	vcfg := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address: vaultSrv.Addr,
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
				Method:    vaultv1alpha1.AuthMethodKubernetes,
				MountPath: mgmtAuthPath,
				Role:      mgmtRole,
			},
			Storage: vaultv1alpha1.StorageSpec{KvMountPath: sharedKVMount},
		},
	}
	if err := k8sClient.Create(ctx, vcfg); err != nil {
		t.Fatalf("create VaultConfig: %v", err)
	}

	// Drive VaultConfigReconciler until Reachable + SharedMountFound.
	reconcileUntil(t, ctx, "VaultConfig", 10*time.Second, func() (bool, error) {
		_, rerr := vcfgReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: vcfg.Name}})
		if rerr != nil {
			return false, rerr
		}
		got := &vaultv1alpha1.VaultConfig{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: vcfg.Name}, got); err != nil {
			return false, err
		}
		return isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReachable) &&
			isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound), nil
	})

	// Create kubeconfig Secret in claim's namespace (target == mgmt for e2e).
	kubeconfigYAML, err := renderKubeconfig(envCfg)
	if err != nil {
		t.Fatalf("render kubeconfig: %v", err)
	}
	kcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: claimName + "-infra-kubeconfig", Namespace: claimNS},
		Data:       map[string][]byte{"value": kubeconfigYAML},
	}
	if err := k8sClient.Create(ctx, kcSecret); err != nil {
		t.Fatalf("create kubeconfig Secret: %v", err)
	}

	// Create VaultClaim.
	claim := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: claimName, Namespace: claimNS},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: claimName, KubeconfigSecret: kcSecret.Name},
			SecretsPrefix:  "clusters/" + claimName,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath:  "kubernetes-" + claimName,
				AutoCreate: true,
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{
						Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true,
					},
					TTL: metav1.Duration{Duration: 24 * time.Hour},
				},
			},
			Transit: &vaultv1alpha1.TransitSpec{
				MountPath: "transit",
				Keys: []vaultv1alpha1.TransitKeySpec{
					{Name: claimName + "-l2", Type: "aes256-gcm96"},
				},
			},
			Policies: []vaultv1alpha1.PolicySpec{
				{Name: claimName + "-vmauth-reader", Rules: `path "secret/data/clusters/` + claimName + `/monitoring/vmauth/*" { capabilities = ["read", "list"] }`},
			},
			Roles: []vaultv1alpha1.RoleSpec{
				{
					Name:                 "vmauth-reader",
					BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "vmauth", Namespace: "monitoring"},
					Policies:             []string{claimName + "-vmauth-reader"},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, claim); err != nil {
		t.Fatalf("create VaultClaim: %v", err)
	}

	// Drive VaultClaimReconciler until Ready.
	reconcileUntil(t, ctx, "VaultClaim", 30*time.Second, func() (bool, error) {
		_, rerr := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}})
		if rerr != nil {
			return false, rerr
		}
		got := &vaultv1alpha1.VaultClaim{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, got); err != nil {
			return false, err
		}
		return got.Status.Phase == vaultv1alpha1.PhaseReady, nil
	})

	// Verify Vault state directly through a fresh vault.Client logged in
	// with the operator SA JWT.
	directClient, err := vault.New(vault.Config{
		Address: vaultSrv.Addr, AuthPath: mgmtAuthPath, Role: mgmtRole,
		JWTSource: vault.StaticJWTSource(operatorJWT),
	})
	if err != nil {
		t.Fatalf("build verify client: %v", err)
	}
	if err := directClient.Login(ctx); err != nil {
		t.Fatalf("verify-client login: %v", err)
	}

	mounts, err := directClient.ListAuthMounts(ctx)
	if err != nil {
		t.Fatalf("list auth mounts: %v", err)
	}
	if _, ok := mounts["kubernetes-"+claimName+"/"]; !ok {
		t.Fatalf("expected auth mount kubernetes-%s/ in Vault, got %v", claimName, mounts)
	}
	// --- Transit ---
	keyName := claimName + "-l2"
	liveKey, err := directClient.ReadTransitKey(ctx, "transit", keyName)
	if err != nil {
		t.Fatalf("read transit key %q: %v", keyName, err)
	}
	if liveKey.Type != "aes256-gcm96" {
		t.Errorf("transit key type = %q, want aes256-gcm96", liveKey.Type)
	}
	if liveKey.Exportable || liveKey.AllowPlaintextBackup || liveKey.DeletionAllowed || liveKey.Derived {
		t.Errorf("transit key is not hardened: %+v", liveKey)
	}
	// The 1.20.x docs omit latest_version from the sample response; assert it live.
	if liveKey.LatestVersion != 1 {
		t.Errorf("transit key latest_version = %d, want 1", liveKey.LatestVersion)
	}

	rawKey, err := ReadTransitKeyRaw(ctx, vaultSrv, "transit", keyName)
	if err != nil {
		t.Fatalf("raw read transit key: %v", err)
	}
	if rawKey["deletion_allowed"] != false {
		t.Errorf("raw deletion_allowed = %v, want false", rawKey["deletion_allowed"])
	}

	readyClaim := &vaultv1alpha1.VaultClaim{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, readyClaim); err != nil {
		t.Fatalf("get claim: %v", err)
	}
	if !isConditionTrue(readyClaim.Status.Conditions, "TransitKeysReady") {
		t.Errorf("TransitKeysReady is not True: %+v", readyClaim.Status.Conditions)
	}
	if len(readyClaim.Status.Vault.TransitKeys) != 1 {
		t.Fatalf("status ledger = %+v, want one key", readyClaim.Status.Vault.TransitKeys)
	}
	ledger := readyClaim.Status.Vault.TransitKeys[0]
	if ledger.Name != keyName || ledger.LatestVersion != 1 || !ledger.CreatedByClaim {
		t.Errorf("ledger entry = %+v, want name=%s version=1 createdByClaim=true", ledger, keyName)
	}

	// The policy is the boundary, not the absence of a method.
	if _, err := directClient.Do(ctx, &vault.Request{
		Method: http.MethodPost,
		Path:   "transit/encrypt/" + keyName,
		Body:   map[string]string{"plaintext": "dGVzdA=="},
	}); err == nil {
		t.Error("operator token could encrypt; its policy must exclude the data plane")
	} else if !vault.IsForbidden(err) {
		t.Errorf("encrypt rejected with %v, want 403", err)
	}

	roles, err := directClient.ListKubernetesRoles(ctx, "kubernetes-"+claimName)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "vmauth-reader" {
		t.Fatalf("roles = %v, want [vmauth-reader]", roles)
	}
	policies, err := directClient.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if !containsString(policies, claimName+"-vmauth-reader") {
		t.Fatalf("policy %s-vmauth-reader missing from %v", claimName, policies)
	}

	// Delete VaultClaim → reverse pipeline.
	if err := k8sClient.Delete(ctx, claim); err != nil {
		t.Fatalf("delete VaultClaim: %v", err)
	}
	reconcileUntil(t, ctx, "VaultClaim-delete", 15*time.Second, func() (bool, error) {
		_, rerr := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}})
		if rerr != nil {
			return false, rerr
		}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, &vaultv1alpha1.VaultClaim{})
		return err != nil, nil // gone == done
	})

	// Verify Vault cleanup.
	mountsAfter, err := directClient.ListAuthMounts(ctx)
	if err != nil {
		t.Fatalf("list auth mounts post-delete: %v", err)
	}
	if _, ok := mountsAfter["kubernetes-"+claimName+"/"]; ok {
		t.Errorf("auth mount kubernetes-%s/ still present after delete", claimName)
	}
	policiesAfter, _ := directClient.ListPolicies(ctx)
	if containsString(policiesAfter, claimName+"-vmauth-reader") {
		t.Errorf("policy %s-vmauth-reader still present after delete", claimName)
	}
}

// bootstrapOperatorSA creates the operator's namespace + SA + CRB granting
// system:auth-delegator so TokenReview against the SA's JWT succeeds.
func bootstrapOperatorSA(ctx context.Context, c client.Client) error {
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNS}}); err != nil {
		return err
	}
	if err := c.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: operatorSA, Namespace: operatorNS}}); err != nil {
		return err
	}
	if err := c.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: operatorSA + "-auth-delegator"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "system:auth-delegator"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: operatorNS, Name: operatorSA}},
	}); err != nil {
		return err
	}
	return nil
}

// issueSAJWT requests a JWT for the given SA via the TokenRequest subresource.
// envtest's apiserver supports this in versions ≥ 1.20.
func issueSAJWT(ctx context.Context, kc kubernetes.Interface, ns, name string, audiences []string) (string, error) {
	ttl := int64(3600)
	resp, err := kc.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{Audiences: audiences, ExpirationSeconds: &ttl},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	if resp.Status.Token == "" {
		return "", fmt.Errorf("empty token in TokenRequest response")
	}
	return resp.Status.Token, nil
}

// renderKubeconfig serializes a rest.Config into a kubeconfig YAML that
// `target.ClusterManager` can parse. CertData/KeyData are inlined.
func renderKubeconfig(cfg *rest.Config) ([]byte, error) {
	type kubeconfigCluster struct {
		Server                   string `json:"server"`
		CertificateAuthorityData string `json:"certificate-authority-data,omitempty"`
		InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify,omitempty"`
	}
	type clusterEntry struct {
		Name    string            `json:"name"`
		Cluster kubeconfigCluster `json:"cluster"`
	}
	type userEntry struct {
		Name string                 `json:"name"`
		User map[string]interface{} `json:"user"`
	}
	type contextEntry struct {
		Name    string                 `json:"name"`
		Context map[string]interface{} `json:"context"`
	}
	type root struct {
		APIVersion     string         `json:"apiVersion"`
		Kind           string         `json:"kind"`
		Clusters       []clusterEntry `json:"clusters"`
		Users          []userEntry    `json:"users"`
		Contexts       []contextEntry `json:"contexts"`
		CurrentContext string         `json:"current-context"`
	}
	user := map[string]interface{}{}
	if len(cfg.CertData) > 0 {
		user["client-certificate-data"] = base64.StdEncoding.EncodeToString(cfg.CertData)
	}
	if len(cfg.KeyData) > 0 {
		user["client-key-data"] = base64.StdEncoding.EncodeToString(cfg.KeyData)
	}
	if cfg.BearerToken != "" {
		user["token"] = cfg.BearerToken
	}
	cl := kubeconfigCluster{Server: cfg.Host}
	if len(cfg.CAData) > 0 {
		cl.CertificateAuthorityData = base64.StdEncoding.EncodeToString(cfg.CAData)
	}
	if cfg.Insecure {
		cl.InsecureSkipTLSVerify = true
	}
	doc := root{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       []clusterEntry{{Name: "envtest", Cluster: cl}},
		Users:          []userEntry{{Name: "envtest", User: user}},
		Contexts:       []contextEntry{{Name: "envtest", Context: map[string]interface{}{"cluster": "envtest", "user": "envtest"}}},
		CurrentContext: "envtest",
	}
	// Use JSON (valid YAML subset) so we don't need a separate yaml dep.
	return json.MarshalIndent(doc, "", "  ")
}

// reconcileUntil drives a single reconciler in a tight loop until cond
// returns true or the deadline elapses. Used because we don't run the
// manager goroutine in tests (see [[feedback-testing]]).
func reconcileUntil(t *testing.T, ctx context.Context, label string, timeout time.Duration, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := cond()
		if err == nil && ok {
			return
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("[%s] condition not met within %s; last err: %v", label, timeout, lastErr)
}

// isConditionTrue is duplicated here so the package has no cross-package
// test-only imports. Mirrors internal/controller/conditions.go.
func isConditionTrue(conditions []metav1.Condition, t string) bool {
	for i := range conditions {
		if conditions[i].Type == t {
			return conditions[i].Status == metav1.ConditionTrue
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}

// firstEnvtestBinaryDir locates the envtest k8s binary dir under bin/k8s.
// Mirrors the helper in suite_test.go so we don't depend on that package.
func firstEnvtestBinaryDir() string {
	base := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(base, e.Name())
		}
	}
	return ""
}
