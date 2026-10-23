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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

// legacyRef is the release production runs; E2E_LEGACY_REF overrides it.
const legacyRef = "v0.0.9"

// legacyDriverSource drives the reconcilers of the legacy tree the way its
// manager would, a fixed number of passes over every VaultConfig and
// VaultClaim. It compiles against that tree's own packages, so the legacy
// pipeline runs unchanged; only the JWT comes from a file instead of the pod
// projection.
const legacyDriverSource = `package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

func main() {
	kubeconfig := flag.String("apiserver-kubeconfig", "", "")
	jwtFile := flag.String("jwt-file", "", "")
	cycles := flag.Int("cycles", 3, "")
	flag.Parse()
	cfg, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = vaultv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	jwt, err := os.ReadFile(*jwtFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	factory := &controller.DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource(strings.TrimSpace(string(jwt)))}
	vcr := &controller.VaultConfigReconciler{Client: c, Scheme: scheme, VaultFactory: factory}
	r := &controller.VaultClaimReconciler{Client: c, Scheme: scheme, VaultFactory: factory, TargetManager: target.NewClusterManager(scheme)}
	ctx := context.Background()
	for i := 0; i < *cycles; i++ {
		var cfgs vaultv1alpha1.VaultConfigList
		if err := c.List(ctx, &cfgs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, x := range cfgs.Items {
			if _, err := vcr.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&x)}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		var claims vaultv1alpha1.VaultClaimList
		if err := c.List(ctx, &claims); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, x := range claims.Items {
			if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&x)}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
	var claims vaultv1alpha1.VaultClaimList
	_ = c.List(ctx, &claims)
	for _, x := range claims.Items {
		fmt.Printf("%s/%s %s\n", x.Namespace, x.Name, x.Status.Phase)
	}
}
`

// legacyTree extracts the legacy release from the repository and builds its
// driver. Both are hard requirements: without the legacy binary there is no
// comparison, and a test that cannot compare must fail.
func legacyTree(t *testing.T) (crdDir, driver string) {
	t.Helper()
	ref := os.Getenv("E2E_LEGACY_REF")
	if ref == "" {
		ref = legacyRef
	}
	return legacyDriverTree(t, ref, legacyDriverSource)
}

// legacyDriverTree собирает настоящий контроллер выбранного выпуска с узким драйвером.
func legacyDriverTree(t *testing.T, ref, source string) (crdDir, driver string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("git", "-C", filepath.Join("..", ".."), "archive", "--format=tar", ref)
	untar := exec.Command("tar", "-x", "-C", src)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	untar.Stdin = pipe
	var archiveErr bytes.Buffer
	archive.Stderr = &archiveErr
	if err := untar.Start(); err != nil {
		t.Fatalf("tar: %v", err)
	}
	if err := archive.Run(); err != nil {
		t.Fatalf("git archive %s (fetch the tag first): %v: %s", ref, err, archiveErr.String())
	}
	if err := untar.Wait(); err != nil {
		t.Fatalf("tar: %v", err)
	}
	mainDir := filepath.Join(src, "cmd", "compatdriver")
	if err := os.MkdirAll(mainDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainDir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	driver = filepath.Join(dir, "legacy-driver")
	build := exec.Command("go", "build", "-o", driver, "./cmd/compatdriver")
	build.Dir = src
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build legacy driver from %s: %v\n%s", ref, err, out)
	}
	return filepath.Join(src, "config", "crd", "bases"), driver
}

func (h *harness) runLegacy(driver string, cycles int) string {
	h.t.Helper()
	dir := h.t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	jwt := filepath.Join(dir, "jwt")
	if err := os.WriteFile(kc, h.kubeconfig, 0o600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(jwt, []byte(h.operatorJWT), 0o600); err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(h.ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, driver, "-apiserver-kubeconfig", kc, "-jwt-file", jwt, "-cycles", fmt.Sprint(cycles))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("legacy driver: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}

// enableAudit turns on a file audit device; auditDeletes counts delete
// operations recorded after offset lines.
func (h *harness) enableAudit() string {
	h.t.Helper()
	path := filepath.Join(h.t.TempDir(), "audit.log")
	h.root(http.MethodPut, "sys/audit/file", map[string]any{"type": "file", "options": map[string]string{"file_path": path}})
	return path
}

func auditLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func auditDeletes(t *testing.T, lines []string) []string {
	t.Helper()
	var deletes []string
	for _, l := range lines {
		var e struct {
			Type    string `json:"type"`
			Request struct {
				Operation string `json:"operation"`
				Path      string `json:"path"`
			} `json:"request"`
		}
		if json.Unmarshal([]byte(l), &e) == nil && e.Type == "request" && e.Request.Operation == "delete" {
			deletes = append(deletes, e.Request.Path)
		}
	}
	return deletes
}

// installCRDs replaces the CRDs envtest serves, like a chart upgrade does.
func (h *harness) installCRDs(dir string) {
	h.t.Helper()
	if _, err := envtest.InstallCRDs(h.cfg, envtest.CRDInstallOptions{Paths: []string{dir}, ErrorIfPathMissing: true}); err != nil {
		h.t.Fatalf("install CRDs from %s: %v", dir, err)
	}
}

// Claims the legacy release created behave byte for byte as before under the
// new release: the Vault snapshot after three legacy cycles equals the one
// after the upgrade (natural passes and forced full passes), no delete reaches
// Vault, and after a refused claim is removed per the rollback runbook the
// legacy release leaves Vault exactly as the new one did.
func TestUpgradeFromLegacyKeepsVaultByteForByte(t *testing.T) {
	crdOld, driver := legacyTree(t)
	h := newHarness(t, crdOld)
	audit := h.enableAudit()
	h.vaultConfig("default", "vault-operator")
	h.namespace("acme")
	claims := prodShapedClaims("acme")
	// A mount made by hand before its claim: the legacy release configured it
	// without looking at its description. The upgrade must keep it so.
	handMade := claims[1].DeepCopy()
	handMade.Name, handMade.Spec.ClusterRef.Name, handMade.Spec.ClusterRef.KubeconfigSecret = "hm0001", "hm0001", "hm0001-infra-kubeconfig"
	handMade.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(handMade.Name)
	handMade.Spec.Auth.MountPath, handMade.Spec.SecretsPrefix = "acme-hm0001", "clusters/acme-hm0001"
	handMade.Spec.Transit = nil
	handMade.Spec.Policies, handMade.Spec.Roles = handMade.Spec.Policies[:1], handMade.Spec.Roles[:1]
	handMade.Spec.Policies[0].Name, handMade.Spec.Roles[0].Name = "acme-hm0001-apps", "acme-hm0001-apps"
	handMade.Spec.Roles[0].Policies = []string{"acme-hm0001-apps"}
	handMade.Spec.Policies[0].Rules = `path "secret/data/clusters/acme-hm0001/s3" { capabilities = ["read"] }`
	h.root(http.MethodPost, "sys/auth/acme-hm0001", map[string]string{"type": "kubernetes", "description": "created by hand"})
	claims = append(claims, handMade)
	for _, c := range claims {
		h.kubeconfigSecret("acme", c.Name)
		// The legacy schema has no autoCreate pointer; the default is the same.
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.Name, err)
		}
	}

	out := h.runLegacy(driver, 3)
	for _, c := range claims {
		if !strings.Contains(out, c.Namespace+"/"+c.Name+" Ready") {
			t.Fatalf("legacy release did not bring %s to Ready:\n%s", c.Name, out)
		}
	}
	s0 := h.snapshot()
	// The comparison is only as wide as what the snapshot read: name it, and
	// refuse a snapshot that misses the claims' objects.
	census := snapshotCensus(t, s0)
	t.Logf("snapshot census: %v", census)
	for kind, min := range map[string]int{"policies": 5 + 1, "kubernetesMounts": 3 + 1, "roles": 5 + 1, "transitKeys": 2} {
		if census[kind] < min {
			t.Fatalf("snapshot read %d %s, want at least %d", census[kind], kind, min)
		}
	}

	// Upgrade: new CRDs, then the new reconciler.
	h.installCRDs(filepath.Join("..", "..", "config", "crd", "bases"))
	h.assertGlobBindingsRatchet(claims[0])
	upgradeStart := len(auditLines(t, audit))
	r := h.reconciler(controller.OwnershipPolicy{}, policyguard.ModeAudit)
	h.cycles(r, 3, claims...)
	if s1 := h.snapshot(); !bytes.Equal(s0, s1) {
		t.Fatalf("Vault changed after the upgrade (natural passes):\n%s", diffLines(s0, s1))
	}
	if d := dataOf(h.root(http.MethodGet, "sys/auth", nil))["acme-hm0001/"]; d == nil || d.(map[string]any)["description"] != "created by hand" {
		t.Fatalf("the hand-made mount is not in the snapshot as it was made: %v", d)
	}
	for _, c := range claims {
		if got := h.claim(c).Status.Phase; got != vaultv1alpha1.PhaseReady {
			t.Fatalf("%s phase after upgrade = %s", c.Name, got)
		}
	}

	// Force full passes: every write path of the new pipeline runs over state
	// the legacy release wrote.
	for _, c := range claims {
		fresh := h.claim(c)
		base := fresh.DeepCopy()
		fresh.Status.ObservedGeneration = 0
		if err := h.k8s.Status().Patch(h.ctx, fresh, client.MergeFrom(base)); err != nil {
			t.Fatalf("reset observedGeneration: %v", err)
		}
	}
	h.cycles(r, 3, claims...)
	if s1 := h.snapshot(); !bytes.Equal(s0, s1) {
		t.Fatalf("Vault changed after forced full passes:\n%s", diffLines(s0, s1))
	}
	if deletes := auditDeletes(t, auditLines(t, audit)[upgradeStart:]); len(deletes) != 0 {
		t.Fatalf("the upgraded operator deleted %d objects: %v", len(deletes), deletes)
	}
	for _, c := range claims {
		got := h.claim(c)
		if got.Status.Phase != vaultv1alpha1.PhaseReady || !got.Status.Vault.AuthMountOwned {
			t.Fatalf("%s: phase=%s authMountOwned=%t", c.Name, got.Status.Phase, got.Status.Vault.AuthMountOwned)
		}
	}

	// A claim the new release refuses; the legacy one would apply it.
	refused := claims[1].DeepCopy()
	refused.ResourceVersion, refused.UID = "", ""
	refused.Name, refused.Spec.ClusterRef.Name, refused.Spec.ClusterRef.KubeconfigSecret = "rr0001", "rr0001", "rr0001-infra-kubeconfig"
	refused.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(refused.Name)
	refused.Spec.Auth.MountPath, refused.Spec.SecretsPrefix = "acme-rr0001", "clusters/acme-rr0001"
	refused.Spec.Transit, refused.Spec.Roles = nil, nil
	refused.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "acme-rr0001-admin", Rules: `path "sys/policies/acl/*" { capabilities = ["create", "update"] }`}}
	refused.Status = vaultv1alpha1.VaultClaimStatus{}
	h.kubeconfigSecret("acme", refused.Name)
	if err := h.k8s.Create(h.ctx, refused); err != nil {
		t.Fatalf("create refused claim: %v", err)
	}
	enforce := h.reconciler(controller.OwnershipPolicy{}, policyguard.ModeEnforce)
	h.cycles(enforce, 3, append(claims, refused)...)
	if got := reasonOf(h.claim(refused), vaultv1alpha1.ConditionPoliciesApplied); got != controller.ReasonPolicyGuardViolation {
		t.Fatalf("refused claim reason = %s", got)
	}
	// Rollback gate (docs/user-guide/rollback.md): count refused claims; each is
	// deleted before the legacy release comes back.
	if n := countRefused(t, h); n != 1 {
		t.Fatalf("rollback gate counted %d refused claims, want 1", n)
	}
	h.deleteClaim(enforce, refused)
	if n := countRefused(t, h); n != 0 {
		t.Fatalf("rollback gate still counts %d refused claims", n)
	}
	sNew := h.snapshot()

	// Rollback: the legacy release over what the new one left.
	out = h.runLegacy(driver, 3)
	if strings.Contains(out, "rr0001") {
		t.Fatalf("the refused claim is still there for the legacy release:\n%s", out)
	}
	if sOld := h.snapshot(); !bytes.Equal(sNew, sOld) {
		t.Fatalf("Vault changed after the rollback:\n%s", diffLines(sNew, sOld))
	}
	if h.root(http.MethodGet, "sys/policies/acl/acme-rr0001-admin", nil) != nil {
		t.Fatal("the refused policy reached Vault")
	}
}

// assertGlobBindingsRatchet: the new schema refuses a glob in a new binding,
// and a claim the legacy release admitted with one is still updated while that
// binding stays as it is. Every write is a dry run, so Vault and the claims are
// as the legacy release left them.
func (h *harness) assertGlobBindingsRatchet(stored *vaultv1alpha1.VaultClaim) {
	h.t.Helper()
	fresh := func(name string) *vaultv1alpha1.VaultClaim {
		c := stored.DeepCopy()
		c.ObjectMeta = metav1.ObjectMeta{Name: name, Namespace: stored.Namespace}
		c.Status = vaultv1alpha1.VaultClaimStatus{}
		return c
	}
	if got := fresh("x").Spec.Roles[0].BoundServiceAccounts.Name; got != "*" {
		h.t.Fatalf("the ratchet fixture binds %q, want the production glob", got)
	}
	// The served schema follows the CRD update with a delay: wait until the new
	// rule answers before trusting an admission.
	var refusal string
	reconcileUntil(h.t, h.ctx, "new schema refuses a new glob binding", 20*time.Second, func() (bool, error) {
		err := h.k8s.Create(h.ctx, fresh("rt0001"), client.DryRunAll)
		if err == nil {
			return false, nil
		}
		refusal = err.Error()
		return strings.Contains(refusal, "boundServiceAccounts.name"), nil
	})
	h.t.Logf("new glob binding refused: %s", refusal)
	twin := fresh("rt0002")
	twin.Spec.Roles[0].BoundServiceAccounts = vaultv1alpha1.BoundServiceAccounts{Name: "reader", Namespace: "apps"}
	if err := h.k8s.Create(h.ctx, twin, client.DryRunAll); err != nil {
		h.t.Fatalf("a binding without a glob refused: %v", err)
	}

	old := h.claim(stored)
	old.Spec.Roles[0].TokenTTL = &metav1.Duration{Duration: 2 * time.Hour}
	if err := h.k8s.Update(h.ctx, old, client.DryRunAll); err != nil {
		h.t.Fatalf("an update next to a stored glob binding refused: %v", err)
	}
	old = h.claim(stored)
	old.Spec.Roles[0].BoundServiceAccounts.Name = "app-*"
	if err := h.k8s.Update(h.ctx, old, client.DryRunAll); err == nil {
		h.t.Fatal("a stored glob binding changed into another glob was admitted")
	}
}

// countRefused is the rollback gate: claims carrying any refusal reason in
// any condition.
func countRefused(t *testing.T, h *harness) int {
	t.Helper()
	var list vaultv1alpha1.VaultClaimList
	if err := h.k8s.List(h.ctx, &list); err != nil {
		t.Fatal(err)
	}
	n := 0
	for i := range list.Items {
		for _, c := range list.Items[i].Status.Conditions {
			if containsString(controller.RefusalReasons, c.Reason) {
				n++
				break
			}
		}
	}
	return n
}

func diffLines(a, b []byte) string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	var out []string
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			out = append(out, fmt.Sprintf("line %d:\n- %s\n+ %s", i+1, x, y))
			if len(out) > 20 {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// snapshotCensus counts what a snapshot holds.
func snapshotCensus(t *testing.T, snap []byte) map[string]int {
	t.Helper()
	var s struct {
		Policies map[string]any `json:"policies"`
		Auth     map[string]struct {
			Type  string         `json:"type"`
			Roles map[string]any `json:"roles"`
		} `json:"auth"`
		Transit map[string]any `json:"transit"`
	}
	if err := json.Unmarshal(snap, &s); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	out := map[string]int{"policies": len(s.Policies), "transitKeys": len(s.Transit)}
	for _, m := range s.Auth {
		if m.Type == "kubernetes" {
			out["kubernetesMounts"]++
			out["roles"] += len(m.Roles)
		}
	}
	return out
}
