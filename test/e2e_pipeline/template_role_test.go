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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

// login logs sa in through role on mount as Vault sees a pod do it; it returns
// the client token, or the HTTP status and errors of a refusal.
func (h *harness) login(kc kubernetes.Interface, mount, role, ns, sa string) (string, int, string) {
	h.t.Helper()
	jwt, err := issueSAJWT(h.ctx, kc, ns, sa, nil)
	if err != nil {
		h.t.Fatalf("issue JWT for %s/%s: %v", ns, sa, err)
	}
	body, _ := json.Marshal(map[string]string{"role": role, "jwt": jwt})
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.vault.Addr+"/v1/auth/"+mount+"/login", bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("login %s/%s: %v", ns, sa, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, string(raw)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Auth.ClientToken == "" {
		h.t.Fatalf("login %s/%s: no client token in %s", ns, sa, raw)
	}
	return out.Auth.ClientToken, resp.StatusCode, ""
}

// readAs reads a KV-v2 secret with token and returns the HTTP status.
func (h *harness) readAs(token, path string) int {
	h.t.Helper()
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, h.vault.Addr+"/v1/"+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("read %s: %v", path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// One template policy and one role with names[] give each ServiceAccount its
// own path: a reads its path and is refused the path of the same name in
// another namespace and the path of b, through both template forms. Login is
// refused to a listed name in another namespace and to a name not listed.
func TestTemplateRoleE2E(t *testing.T) {
	h := newHarness(t, "")
	h.vaultConfig("default", "vault-operator")
	kc, err := kubernetes.NewForConfig(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.namespace("acme")
	for _, ns := range []string{"ns1", "ns2"} {
		h.namespace(ns)
	}
	for _, sa := range []struct{ ns, name string }{{"ns1", "a"}, {"ns1", "b"}, {"ns1", "c"}, {"ns2", "a"}} {
		if err := h.k8s.Create(h.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: sa.ns, Name: sa.name}}); err != nil {
			t.Fatalf("create SA %s/%s: %v", sa.ns, sa.name, err)
		}
	}

	const id = "acme-tp0001"
	prefix := "clusters/" + id
	claim := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "tp0001", Namespace: "acme"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: "tp0001", KubeconfigSecret: "tp0001-infra-kubeconfig"},
			SecretsPrefix:  prefix,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath:  id,
				AutoCreate: ptr.To(true),
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "vault-reviewer", Name: "vault-token-reviewer", AutoCreate: true},
					TTL:            metav1.Duration{Duration: 24 * time.Hour},
				},
			},
			Policies: []vaultv1alpha1.PolicySpec{
				{Name: id + "-own", IdentityPaths: []vaultv1alpha1.IdentityPath{{
					Path: "secret/data/" + prefix + "/{serviceAccountNamespace}/{serviceAccountName}", Capabilities: []string{"read"},
				}}},
				{Name: id + "-shared", Rules: `path "secret/data/` + prefix + `/shared/{{ vaultSANamespace }}" { capabilities = ["read"] }`},
			},
			Roles: []vaultv1alpha1.RoleSpec{{
				Name:                 "apps",
				BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Names: []string{"b", "a"}, Namespace: "ns1"},
				Policies:             []string{id + "-own", id + "-shared"},
				AliasNameSource:      vaultv1alpha1.AliasNameSourceName,
				TokenTTL:             &metav1.Duration{Duration: time.Hour},
			}},
		},
	}
	h.kubeconfigSecret("acme", claim.Name)
	if err := h.k8s.Create(h.ctx, claim); err != nil {
		t.Fatalf("create claim: %v", err)
	}
	r := h.reconciler(controller.OwnershipPolicy{}, policyguard.ModeEnforce)
	h.cycles(r, 3, claim)
	got := h.claim(claim)
	if got.Status.Phase != vaultv1alpha1.PhaseReady {
		t.Fatalf("claim phase = %s, conditions %+v", got.Status.Phase, got.Status.Conditions)
	}
	mountInfo, _ := dataOf(h.root(http.MethodGet, "sys/auth", nil))[id+"/"].(map[string]any)
	accessor, _ := mountInfo["accessor"].(string)
	if accessor == "" || got.Status.Vault.AuthMountAccessor != accessor {
		t.Fatalf("status accessor %q, sys/auth accessor %q", got.Status.Vault.AuthMountAccessor, accessor)
	}

	role := dataOf(h.root(http.MethodGet, "auth/"+id+"/role/apps", nil))
	if fmt.Sprint(role["bound_service_account_names"]) != "[a b]" || role["alias_name_source"] != vaultv1alpha1.AliasNameSourceName {
		t.Fatalf("role written as %v", role)
	}
	policy, _ := dataOf(h.root(http.MethodGet, "sys/policies/acl/"+id+"-own", nil))["policy"].(string)
	if !strings.Contains(policy, "{{identity.entity.aliases."+accessor+".metadata.service_account_name}}") {
		t.Fatalf("policy body %q does not name the logged-in ServiceAccount", policy)
	}

	for _, p := range []string{"ns1/a", "ns2/a", "ns1/b", "shared/ns1", "shared/ns2"} {
		if err := SeedKV(h.ctx, h.vault, sharedKVMount, prefix+"/"+p, map[string]interface{}{"v": p}); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	token, status, refusal := h.login(kc, id, "apps", "ns1", "a")
	if token == "" {
		t.Fatalf("a/ns1 login refused: %d %s", status, refusal)
	}
	for path, want := range map[string]int{
		"ns1/a":      http.StatusOK,
		"ns2/a":      http.StatusForbidden,
		"ns1/b":      http.StatusForbidden,
		"shared/ns1": http.StatusOK,
		"shared/ns2": http.StatusForbidden,
	} {
		if got := h.readAs(token, "secret/data/"+prefix+"/"+path); got != want {
			t.Errorf("a/ns1 reading %s: status %d, want %d", path, got, want)
		}
	}
	if tokenB, status, refusal := h.login(kc, id, "apps", "ns1", "b"); tokenB == "" {
		t.Fatalf("b/ns1 login refused: %d %s", status, refusal)
	} else if got := h.readAs(tokenB, "secret/data/"+prefix+"/ns1/b"); got != http.StatusOK {
		t.Errorf("b/ns1 reading its own path: status %d", got)
	}

	for _, who := range []struct{ ns, sa, why string }{
		{"ns2", "a", "namespace not authorized"},
		{"ns1", "c", "service account name not authorized"},
	} {
		if tok, status, refusal := h.login(kc, id, "apps", who.ns, who.sa); tok != "" || status != http.StatusForbidden || !strings.Contains(refusal, who.why) {
			t.Errorf("%s/%s login: token=%t status=%d %s, want 403 %q", who.ns, who.sa, tok != "", status, refusal, who.why)
		}
	}

	// A full pass over the same Vault rewrites nothing.
	before := h.snapshot()
	fresh := h.claim(claim)
	base := fresh.DeepCopy()
	fresh.Status.ObservedGeneration = 0
	if err := h.k8s.Status().Patch(h.ctx, fresh, client.MergeFrom(base)); err != nil {
		t.Fatalf("reset observedGeneration: %v", err)
	}
	h.cycles(r, 2, claim)
	if after := h.snapshot(); !bytes.Equal(before, after) {
		t.Fatalf("Vault changed on a full pass:\n%s", diffLines(before, after))
	}

	h.deleteClaim(r, claim)
	if h.root(http.MethodGet, "sys/policies/acl/"+id+"-own", nil) != nil {
		t.Error("template policy survived the claim's deletion")
	}
}
