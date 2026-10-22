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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// harness is one real Vault 1.20.x dev server plus one envtest apiserver,
// bootstrapped the way production is: the operator logs in through the
// kubernetes-mgmt mount with the vault-operator-admin policy.
type harness struct {
	t           *testing.T
	ctx         context.Context
	vault       *VaultDevServer
	env         *envtest.Environment
	cfg         *rest.Config
	k8s         client.Client
	scheme      *runtime.Scheme
	operatorJWT string
	factory     *controller.DefaultVaultClientFactory
	kubeconfig  []byte
}

// newHarness starts both servers; crdDir selects the CRDs envtest installs
// (the tree's own when empty). Everything is torn down by t.Cleanup.
func newHarness(t *testing.T, crdDir string) *harness {
	t.Helper()
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stderr)))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)

	srv := StartVaultDev(ctx, t)
	if err := EnsureKVMount(ctx, srv, sharedKVMount); err != nil {
		t.Fatalf("ensure KV mount: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if crdDir == "" {
		crdDir = filepath.Join("..", "..", "config", "crd", "bases")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{crdDir}, ErrorIfCRDPathMissing: true}
	if bin := firstEnvtestBinaryDir(); bin != "" {
		env.BinaryAssetsDirectory = bin
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("envtest.Start: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("k8s client: %v", err)
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	if err := bootstrapOperatorSA(ctx, k8s); err != nil {
		t.Fatalf("bootstrap operator SA: %v", err)
	}
	jwt, err := issueSAJWT(ctx, kc, operatorNS, operatorSA, nil)
	if err != nil {
		t.Fatalf("issue operator JWT: %v", err)
	}
	if err := BootstrapVaultDev(ctx, srv, BootstrapConfig{
		ManagerAuthPath: mgmtAuthPath, ManagerRole: mgmtRole,
		KubernetesHost: cfg.Host, KubernetesCACert: string(cfg.CAData), TokenReviewerJWT: jwt,
		SABoundNames: []string{operatorSA}, SABoundNamespaces: []string{operatorNS},
	}); err != nil {
		t.Fatalf("bootstrap vault: %v", err)
	}
	if err := EnableTransitMount(ctx, srv, "transit"); err != nil {
		t.Fatalf("enable transit: %v", err)
	}
	kubeconfig, err := renderKubeconfig(cfg)
	if err != nil {
		t.Fatalf("render kubeconfig: %v", err)
	}
	h := &harness{t: t, ctx: ctx, vault: srv, env: env, cfg: cfg, k8s: k8s, scheme: scheme, operatorJWT: jwt,
		factory: &controller.DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource(jwt)}, kubeconfig: kubeconfig}
	return h
}

// vaultConfig creates a VaultConfig logging in as role on the operator mount
// and drives it to Reachable.
func (h *harness) vaultConfig(name, role string) {
	h.t.Helper()
	h.vaultConfigObject(name, role)
	r := &controller.VaultConfigReconciler{Client: h.k8s, Scheme: h.scheme, VaultFactory: h.factory}
	reconcileUntil(h.t, h.ctx, "VaultConfig "+name, 15*time.Second, func() (bool, error) {
		if _, err := r.Reconcile(h.ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			return false, err
		}
		got := &vaultv1alpha1.VaultConfig{}
		if err := h.k8s.Get(h.ctx, types.NamespacedName{Name: name}, got); err != nil {
			return false, err
		}
		return isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReachable) &&
			isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound), nil
	})
}

// vaultConfigObject only creates the object: the other operators' VaultConfigs
// matter to a claim as declarations of the mount and the role, not as clients.
func (h *harness) vaultConfigObject(name, role string) {
	h.t.Helper()
	vc := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address:     h.vault.Addr,
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: mgmtAuthPath, Role: role},
			Storage:     vaultv1alpha1.StorageSpec{KvMountPath: sharedKVMount},
		},
	}
	if err := h.k8s.Create(h.ctx, vc); err != nil {
		h.t.Fatalf("create VaultConfig %s: %v", name, err)
	}
}

func (h *harness) namespace(name string) {
	h.t.Helper()
	if err := h.k8s.Create(h.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		h.t.Fatalf("create namespace %s: %v", name, err)
	}
}

// kubeconfigSecret is the infra kubeconfig of a claim; the target cluster is
// the envtest apiserver itself.
func (h *harness) kubeconfigSecret(ns, claim string) {
	h.t.Helper()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: claim + "-infra-kubeconfig", Namespace: ns},
		Data:       map[string][]byte{"value": h.kubeconfig},
	}
	if err := h.k8s.Create(h.ctx, s); err != nil {
		h.t.Fatalf("create kubeconfig Secret: %v", err)
	}
}

func (h *harness) reconciler(ownership controller.OwnershipPolicy, guard policyguard.Mode) *controller.VaultClaimReconciler {
	return &controller.VaultClaimReconciler{
		Client: h.k8s, Scheme: h.scheme, VaultFactory: h.factory,
		TargetManager: target.NewClusterManager(h.scheme),
		Ownership:     ownership, PolicyGuard: guard,
	}
}

// cycles reconciles every claim n times in order: a fixed count, not "until
// Ready", so a claim that should stay refused is driven just as hard.
func (h *harness) cycles(r *controller.VaultClaimReconciler, n int, claims ...*vaultv1alpha1.VaultClaim) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		for _, c := range claims {
			if _, err := r.Reconcile(h.ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(c)}); err != nil {
				h.t.Fatalf("reconcile %s/%s: %v", c.Namespace, c.Name, err)
			}
		}
	}
}

func (h *harness) claim(c *vaultv1alpha1.VaultClaim) *vaultv1alpha1.VaultClaim {
	h.t.Helper()
	got := &vaultv1alpha1.VaultClaim{}
	if err := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(c), got); err != nil {
		h.t.Fatalf("get claim %s/%s: %v", c.Namespace, c.Name, err)
	}
	return got
}

// deleteClaim deletes a claim and drives the reverse pipeline until it is gone.
func (h *harness) deleteClaim(r *controller.VaultClaimReconciler, c *vaultv1alpha1.VaultClaim) {
	h.t.Helper()
	if err := h.k8s.Delete(h.ctx, h.claim(c)); err != nil {
		h.t.Fatalf("delete claim: %v", err)
	}
	reconcileUntil(h.t, h.ctx, "delete "+c.Name, 20*time.Second, func() (bool, error) {
		if _, err := r.Reconcile(h.ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(c)}); err != nil {
			return false, err
		}
		err := h.k8s.Get(h.ctx, client.ObjectKeyFromObject(c), &vaultv1alpha1.VaultClaim{})
		return err != nil, nil
	})
}

func reasonOf(c *vaultv1alpha1.VaultClaim, condType string) string {
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == condType {
			return c.Status.Conditions[i].Reason
		}
	}
	return "<absent>"
}

// root issues a dev-root request and decodes the JSON answer; a 404 yields nil.
func (h *harness) root(method, path string, body any) map[string]any {
	h.t.Helper()
	var resp map[string]any
	status, err := h.rootRaw(method, path, body, &resp)
	if err != nil {
		h.t.Fatalf("vault %s %s: %v", method, path, err)
	}
	if status == http.StatusNotFound {
		return nil
	}
	return resp
}

func (h *harness) rootRaw(method, path string, body any, out *map[string]any) (int, error) {
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(h.ctx, method, h.vault.Addr+"/v1/"+strings.TrimLeft(path, "/"), reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Vault-Token", h.vault.RootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

func dataOf(resp map[string]any) map[string]any {
	if resp == nil {
		return nil
	}
	d, _ := resp["data"].(map[string]any)
	return d
}

func keysOf(resp map[string]any) []string {
	raw, _ := dataOf(resp)["keys"].([]any)
	out := make([]string, 0, len(raw))
	for _, k := range raw {
		out = append(out, fmt.Sprint(k))
	}
	sort.Strings(out)
	return out
}

// listKeys runs a LIST; a missing path lists nothing.
func (h *harness) listKeys(path string) []string {
	return keysOf(h.root(http.MethodGet, path+"?list=true", nil))
}

// snapshot is the normalized Vault state the operator can touch: every ACL
// policy body, every auth mount (type, description, accessor), every role and
// config of every kubernetes mount, and every Transit key. encoding/json sorts
// map keys, so equal states give equal bytes.
func (h *harness) snapshot() []byte {
	h.t.Helper()
	snap := map[string]any{}
	policies := map[string]any{}
	for _, name := range h.listKeys("sys/policies/acl") {
		policies[name] = dataOf(h.root(http.MethodGet, "sys/policies/acl/"+name, nil))["policy"]
	}
	snap["policies"] = policies

	mounts := map[string]any{}
	for path, raw := range dataOf(h.root(http.MethodGet, "sys/auth", nil)) {
		m, _ := raw.(map[string]any)
		entry := map[string]any{"type": m["type"], "description": m["description"], "accessor": m["accessor"]}
		if m["type"] == "kubernetes" {
			name := strings.TrimSuffix(path, "/")
			roles := map[string]any{}
			for _, role := range h.listKeys("auth/" + name + "/role") {
				roles[role] = dataOf(h.root(http.MethodGet, "auth/"+name+"/role/"+role, nil))
			}
			entry["roles"] = roles
			entry["config"] = dataOf(h.root(http.MethodGet, "auth/"+name+"/config", nil))
		}
		mounts[path] = entry
	}
	snap["auth"] = mounts

	keys := map[string]any{}
	for _, name := range h.listKeys("transit/keys") {
		keys[name] = dataOf(h.root(http.MethodGet, "transit/keys/"+name, nil))
	}
	snap["transit"] = keys

	out, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		h.t.Fatalf("marshal snapshot: %v", err)
	}
	return out
}

// reviewerName is the token reviewer SA of claim name. Every claim of a
// harness has its target cluster in the one envtest apiserver, where
// production has a cluster per claim: a name per claim keeps each reviewer
// the claim's own.
func reviewerName(claim string) string { return "vault-token-reviewer-" + claim }

// withoutGlobBindings turns production shapes into claims the current schema
// admits on creation: it refuses a glob in a new binding, so the read-only
// role binds a named ServiceAccount. Claims that already hold the glob are
// covered by the upgrade test, which creates them under the legacy schema.
func withoutGlobBindings(claims []*vaultv1alpha1.VaultClaim) []*vaultv1alpha1.VaultClaim {
	for _, c := range claims {
		for i := range c.Spec.Roles {
			b := &c.Spec.Roles[i].BoundServiceAccounts
			if b.Name == "*" {
				b.Name = "reader"
			}
			if b.Namespace == "*" {
				b.Namespace = "apps"
			}
		}
	}
	return claims
}

// prodShapedClaims are the two claim shapes production runs (census of 112
// claims: 105 of the first, 7 of the second), with names of the same form.
func prodShapedClaims(ns string) []*vaultv1alpha1.VaultClaim {
	ttl := func(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }
	base := func(name string) *vaultv1alpha1.VaultClaim {
		id := ns + "-" + name
		return &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: name + "-infra-kubeconfig"},
				SecretsPrefix:  "clusters/" + id,
				DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath:  id,
					AutoCreate: ptr.To(true),
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "vault-reviewer", Name: reviewerName(name), AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Transit: &vaultv1alpha1.TransitSpec{MountPath: "transit", Keys: []vaultv1alpha1.TransitKeySpec{
					{Name: id, Type: "aes256-gcm96"},
				}},
			},
		}
	}
	kms := func(c *vaultv1alpha1.VaultClaim) {
		id := c.Spec.Auth.MountPath
		c.Spec.Policies = append(c.Spec.Policies, vaultv1alpha1.PolicySpec{Name: id + "-etcd-kms", Rules: `path "transit/encrypt/` + id + `" {
  capabilities = ["update"]
}

path "transit/decrypt/` + id + `" {
  capabilities = ["update"]
}

path "transit/keys/` + id + `" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
`})
		c.Spec.Roles = append(c.Spec.Roles, vaultv1alpha1.RoleSpec{
			Name:                 id + "-kms-plugin",
			Audience:             "vault-kms-plugin." + id + ".client",
			BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "client-cp-control-plane-control-plane", Namespace: "platform-system"},
			Policies:             []string{id + "-etcd-kms"},
			TokenMaxTTL:          ttl(24 * time.Hour), TokenNoDefaultPolicy: true, TokenTTL: ttl(time.Hour), TokenType: "service",
		})
	}

	a := base("ab3b6f")
	idA := a.Spec.Auth.MountPath
	a.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: idA + "-ro", Rules: `path "sys/mounts" { capabilities = ["read"] }

path "secret/data/clusters/` + idA + `/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/clusters/` + idA + `/*" {
  capabilities = ["list"]
}
`}}
	a.Spec.Roles = []vaultv1alpha1.RoleSpec{{
		Name: idA + "-ro", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "*", Namespace: "*"},
		Policies: []string{idA + "-ro"}, TokenTTL: ttl(time.Hour),
	}}
	kms(a)

	b := base("cb93d2")
	idB := b.Spec.Auth.MountPath
	b.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: idB + "-apps", Rules: `path "secret/data/clusters/` + idB + `/argocd" { capabilities = ["read"] }
path "secret/data/clusters/` + idB + `/haproxy-metrics" { capabilities = ["read"] }
path "secret/data/clusters/` + idB + `/s3" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
`}}
	b.Spec.Roles = []vaultv1alpha1.RoleSpec{{
		Name: idB + "-argocd", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "argocd-repo-server", Namespace: "argocd"},
		Policies: []string{idB + "-apps"}, TokenTTL: ttl(time.Hour),
	}}
	kms(b)
	return []*vaultv1alpha1.VaultClaim{a, b}
}
