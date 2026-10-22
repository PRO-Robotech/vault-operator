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
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

// operatorRoles are the six roles the platform writes on the operator mount;
// three of them are what the three operators log in with.
var operatorRoles = []string{"vault-operator", "s3-bucket-operator", "vault-secret-operator", "platform-ro", "platform-avp-argocd", "metrics-reader"}

// seedOperatorMount writes what the platform's bootstrap writes next to the
// e2e manager role: the other five roles and the operators' policies.
func seedOperatorMount(h *harness) {
	h.t.Helper()
	for _, p := range []string{"s3-bucket-operator", "vault-secret-operator", "registry-guest"} {
		h.root(http.MethodPut, "sys/policies/acl/"+p, map[string]string{"policy": `path "secret/data/` + p + `/*" { capabilities = ["read"] }`})
	}
	for _, r := range operatorRoles[1:] {
		h.root(http.MethodPost, "auth/"+mgmtAuthPath+"/role/"+r, map[string]any{
			"bound_service_account_names": []string{r}, "bound_service_account_namespaces": []string{"platform-system"},
			"token_policies": []string{r}, "token_ttl": 600,
		})
	}
}

// operatorMountState is the operator mount as the guest must leave it.
func operatorMountState(h *harness) []byte {
	h.t.Helper()
	state := map[string]any{"config": dataOf(h.root(http.MethodGet, "auth/"+mgmtAuthPath+"/config", nil))}
	roles := map[string]any{}
	for _, r := range operatorRoles {
		roles[r] = dataOf(h.root(http.MethodGet, "auth/"+mgmtAuthPath+"/role/"+r, nil))
	}
	state["roles"] = roles
	out, _ := json.Marshal(state)
	return out
}

func guestClaim(ns, name, role string) *vaultv1alpha1.VaultClaim {
	prefix := "clusters/mgmt/namespaces/" + ns + "/apps/docker-registry/" + name
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			SecretsPrefix:  prefix,
			Auth: vaultv1alpha1.AuthSpec{MountPath: mgmtAuthPath, AutoCreate: ptr.To(false), ManageConfig: ptr.To(false),
				RolePruning: vaultv1alpha1.RolePruningOwned},
			Policies: []vaultv1alpha1.PolicySpec{{Name: name + "-read", Rules: `path "secret/data/` + prefix + `" { capabilities = ["read"] }`}},
			Roles: []vaultv1alpha1.RoleSpec{{Name: role, BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: name, Namespace: ns},
				Policies: []string{name + "-read", "registry-guest"}}},
		},
	}
}

// A guest on the operator mount adds its own role and leaves the six platform
// roles and the mount config byte for byte as they were, through three cycles
// and its own deletion. An owner claim on that mount, and a guest naming a
// platform role, are refused without a write.
func TestGuestOnOperatorMountE2E(t *testing.T) {
	h := newHarness(t, "")
	h.vaultConfig("default", "vault-operator")
	h.vaultConfigObject("s3-bucket", "s3-bucket-operator")
	h.vaultConfigObject("vault-secret", "vault-secret-operator")
	seedOperatorMount(h)
	h.namespace("registry")
	before := operatorMountState(h)

	ownership := controller.OwnershipPolicy{
		ReservedPolicyNames: []string{"vault-operator-admin", "s3-bucket-operator", "vault-secret-operator"},
		ExternalPolicyNames: []string{"registry-guest"},
	}
	r := h.reconciler(ownership, policyguard.ModeAudit)

	guest := guestClaim("registry", "zot-1", "zot-1")
	// No reserved role list is configured: the ledger rule alone must protect
	// a platform role the guest names.
	squatter := guestClaim("registry", "zot-2", "platform-ro")
	intruder := withoutGlobBindings(prodShapedClaims("registry"))[0]
	intruder.Name, intruder.Spec.ClusterRef.Name = "intruder", "intruder"
	intruder.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(intruder.Name)
	intruder.Spec.Auth.MountPath = mgmtAuthPath
	intruder.Spec.SecretsPrefix = "clusters/registry-intruder"
	intruder.Spec.Transit = nil
	intruder.Spec.Roles = intruder.Spec.Roles[:1]
	intruder.Spec.Policies = intruder.Spec.Policies[:1]
	h.kubeconfigSecret("registry", "intruder")
	for _, c := range []*vaultv1alpha1.VaultClaim{guest, squatter, intruder} {
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.Name, err)
		}
		time.Sleep(1100 * time.Millisecond) // distinct creation timestamps
	}
	h.cycles(r, 3, guest, squatter, intruder)

	if got := h.claim(guest); got.Status.Phase != vaultv1alpha1.PhaseReady {
		t.Fatalf("guest phase = %s, conditions %+v", got.Status.Phase, got.Status.Conditions)
	}
	if role := dataOf(h.root(http.MethodGet, "auth/"+mgmtAuthPath+"/role/zot-1", nil)); role == nil {
		t.Fatal("guest role zot-1 was not written")
	}
	if got := reasonOf(h.claim(squatter), vaultv1alpha1.ConditionRolesApplied); got != controller.ReasonOwnershipConflict {
		t.Errorf("squatter RolesApplied reason = %s, want OwnershipConflict", got)
	}
	if got := reasonOf(h.claim(intruder), vaultv1alpha1.ConditionAuthMountReady); got != controller.ReasonMountConflict {
		t.Errorf("intruder AuthMountReady reason = %s, want MountConflict", got)
	}
	if after := operatorMountState(h); !bytes.Equal(before, after) {
		t.Fatalf("operator mount changed after 3 cycles:\nbefore %s\nafter  %s", before, after)
	}

	for _, c := range []*vaultv1alpha1.VaultClaim{guest, squatter, intruder} {
		h.deleteClaim(r, c)
	}
	if role := dataOf(h.root(http.MethodGet, "auth/"+mgmtAuthPath+"/role/zot-1", nil)); role != nil {
		t.Error("guest role zot-1 survived the guest's deletion")
	}
	if p := h.root(http.MethodGet, "sys/policies/acl/zot-1-read", nil); p != nil {
		t.Error("guest policy zot-1-read survived the guest's deletion")
	}
	if p := h.root(http.MethodGet, "sys/policies/acl/registry-guest", nil); p == nil {
		t.Error("external policy registry-guest was deleted")
	}
	if after := operatorMountState(h); !bytes.Equal(before, after) {
		t.Fatalf("operator mount changed by deletions:\nbefore %s\nafter  %s", before, after)
	}
	if _, ok := dataOf(h.root(http.MethodGet, "sys/auth", nil))[mgmtAuthPath+"/"]; !ok {
		t.Fatal("operator mount was disabled")
	}
}

// Names have one owner at the level of Vault state: a pre-existing policy and
// a hand-made mount are never adopted, a second claim never reconfigures a
// key, the ledger removes what left spec, and enforce keeps an escalation out
// of Vault.
func TestOwnershipE2E(t *testing.T) {
	h := newHarness(t, "")
	h.vaultConfig("default", "vault-operator")
	h.namespace("acme")
	shapes := withoutGlobBindings(prodShapedClaims("acme"))
	r := h.reconciler(controller.OwnershipPolicy{ReservedPolicyNames: []string{"vault-operator-admin"}}, policyguard.ModeAudit)

	t.Run("a policy that exists before the claim keeps its body", func(t *testing.T) {
		h.root(http.MethodPut, "sys/policies/acl/acme-ab3b6f-ro", map[string]string{"policy": `path "secret/data/foreign/*" { capabilities = ["read"] }`})
		before := dataOf(h.root(http.MethodGet, "sys/policies/acl/acme-ab3b6f-ro", nil))["policy"]
		c := shapes[0].DeepCopy()
		h.kubeconfigSecret("acme", c.Name)
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 3, c)
		if got := reasonOf(h.claim(c), vaultv1alpha1.ConditionPoliciesApplied); got != controller.ReasonOwnershipConflict {
			t.Fatalf("PoliciesApplied reason = %s", got)
		}
		h.deleteClaim(r, c)
		if after := dataOf(h.root(http.MethodGet, "sys/policies/acl/acme-ab3b6f-ro", nil))["policy"]; after != before {
			t.Fatalf("policy body changed: %v → %v", before, after)
		}
		h.root(http.MethodDelete, "sys/policies/acl/acme-ab3b6f-ro", nil)
	})

	t.Run("a second claim with the same transit key never configures it", func(t *testing.T) {
		elder := shapes[1].DeepCopy()
		h.kubeconfigSecret("acme", elder.Name)
		if err := h.k8s.Create(h.ctx, elder); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 1, elder)
		if got := h.claim(elder).Status.Phase; got != vaultv1alpha1.PhaseReady {
			t.Fatalf("elder phase = %s", got)
		}
		before := dataOf(h.root(http.MethodGet, "transit/keys/"+elder.Spec.Transit.Keys[0].Name, nil))
		time.Sleep(1100 * time.Millisecond)
		younger := shapes[1].DeepCopy()
		younger.Name, younger.Spec.ClusterRef.Name, younger.Spec.ClusterRef.KubeconfigSecret = "dd0001", "dd0001", "dd0001-infra-kubeconfig"
		younger.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(younger.Name)
		younger.Spec.Auth.MountPath, younger.Spec.SecretsPrefix = "acme-dd0001", "clusters/acme-dd0001"
		younger.Spec.Policies, younger.Spec.Roles = nil, nil
		younger.Spec.Transit.Keys[0].Exportable = true
		younger.Spec.Transit.Keys[0].DeletionAllowed = true
		h.kubeconfigSecret("acme", younger.Name)
		if err := h.k8s.Create(h.ctx, younger); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 3, younger)
		if got := reasonOf(h.claim(younger), vaultv1alpha1.ConditionTransitKeysReady); got != controller.ReasonOwnershipConflict {
			t.Fatalf("younger TransitKeysReady reason = %s", got)
		}
		after := dataOf(h.root(http.MethodGet, "transit/keys/"+elder.Spec.Transit.Keys[0].Name, nil))
		if b, a := mustJSON(before), mustJSON(after); !bytes.Equal(b, a) {
			t.Fatalf("key changed:\nbefore %s\nafter  %s", b, a)
		}
		h.deleteClaim(r, younger)
		h.deleteClaim(r, elder)
	})

	t.Run("a hand-made mount is not adopted by a claim that waited for its kubeconfig", func(t *testing.T) {
		h.root(http.MethodPost, "sys/auth/acme-ee0001", map[string]string{"type": "kubernetes", "description": "created by hand"})
		c := shapes[1].DeepCopy()
		c.Name, c.Spec.ClusterRef.Name, c.Spec.ClusterRef.KubeconfigSecret = "ee0001", "ee0001", "ee0001-infra-kubeconfig"
		c.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(c.Name)
		c.Spec.Auth.MountPath, c.Spec.SecretsPrefix = "acme-ee0001", "clusters/acme-ee0001"
		c.Spec.Transit = nil
		c.Spec.Policies, c.Spec.Roles = c.Spec.Policies[:1], c.Spec.Roles[:1]
		c.Spec.Policies[0].Name, c.Spec.Roles[0].Policies = "acme-ee0001-apps", []string{"acme-ee0001-apps"}
		c.Spec.Policies[0].Rules = `path "secret/data/clusters/acme-ee0001/s3" { capabilities = ["read"] }`
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 1, c)
		waited := h.claim(c)
		if got := reasonOf(waited, vaultv1alpha1.ConditionKubeconfigAvailable); got != "NotFound" {
			t.Fatalf("KubeconfigAvailable reason = %s; the claim did not wait for its kubeconfig", got)
		}
		// A record of the mount is what accepts it; waiting must not earn one.
		if waited.Status.Vault != nil && waited.Status.Vault.AuthMountPath != "" {
			t.Fatalf("status.vault.authMountPath = %q after waiting", waited.Status.Vault.AuthMountPath)
		}
		h.kubeconfigSecret("acme", c.Name)
		h.cycles(r, 3, c)
		got := h.claim(c)
		if reason := reasonOf(got, vaultv1alpha1.ConditionAuthMountReady); reason != controller.ReasonMountConflict {
			t.Fatalf("AuthMountReady reason = %s", reason)
		}
		if got.Status.Vault != nil && got.Status.Vault.AuthMountPath != "" {
			t.Fatalf("status.vault.authMountPath = %q for a refused mount", got.Status.Vault.AuthMountPath)
		}
		if host := dataOf(h.root(http.MethodGet, "auth/acme-ee0001/config", nil))["kubernetes_host"]; host != nil && host != "" {
			t.Fatalf("config of a foreign mount was written: kubernetes_host=%v", host)
		}
		h.deleteClaim(r, c)
		if _, ok := dataOf(h.root(http.MethodGet, "sys/auth", nil))["acme-ee0001/"]; !ok {
			t.Fatal("a foreign mount was disabled by a claim's deletion")
		}
	})

	t.Run("names are compared the way Vault resolves them", func(t *testing.T) {
		const ext = "ext-template"
		h.root(http.MethodPut, "sys/policies/acl/"+ext, map[string]string{"policy": `path "secret/data/ext/*" { capabilities = ["read"] }`})
		before := dataOf(h.root(http.MethodGet, "sys/policies/acl/"+ext, nil))["policy"]
		names := h.reconciler(controller.OwnershipPolicy{ReservedPolicyNames: []string{"vault-operator-admin"}, ExternalPolicyNames: []string{ext}}, policyguard.ModeAudit)
		mk := func(id string) *vaultv1alpha1.VaultClaim {
			c := shapes[1].DeepCopy()
			c.Name, c.Spec.ClusterRef.Name, c.Spec.ClusterRef.KubeconfigSecret = id, id, id+"-infra-kubeconfig"
			c.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(c.Name)
			c.Spec.Auth.MountPath, c.Spec.SecretsPrefix = "acme-"+id, "clusters/acme-"+id
			c.Spec.Transit, c.Spec.Policies, c.Spec.Roles = nil, nil, nil
			h.kubeconfigSecret("acme", id)
			return c
		}
		// A ledger entry in another case names the external policy.
		ledger := mk("nk0001")
		// A role reference in another case names the reserved policy.
		ref := mk("nk0002")
		ref.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "nk-own", Rules: `path "secret/data/clusters/acme-nk0002/*" { capabilities = ["read"] }`}}
		ref.Spec.Roles = []vaultv1alpha1.RoleSpec{{Name: "nk-r", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "a", Namespace: "x"},
			Policies: []string{"nk-own", "Vault-Operator-Admin"}}}
		for _, c := range []*vaultv1alpha1.VaultClaim{ledger, ref} {
			if err := h.k8s.Create(h.ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		fresh := h.claim(ledger)
		fresh.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"EXT-TEMPLATE"}}
		if err := h.k8s.Status().Update(h.ctx, fresh); err != nil {
			t.Fatal(err)
		}
		h.cycles(names, 3, ledger, ref)
		if after := dataOf(h.root(http.MethodGet, "sys/policies/acl/"+ext, nil))["policy"]; after != before {
			t.Fatalf("external policy %s after a ledger entry in another case: %v", ext, after)
		}
		if got := reasonOf(h.claim(ref), vaultv1alpha1.ConditionRolesApplied); got != controller.ReasonPolicyReferenceForbidden {
			t.Fatalf("RolesApplied reason = %s, want PolicyReferenceForbidden", got)
		}
		if role := dataOf(h.root(http.MethodGet, "auth/acme-nk0002/role/nk-r", nil)); role != nil {
			t.Fatalf("a role referencing the reserved policy reached Vault: %v", role["token_policies"])
		}
		h.deleteClaim(names, ledger)
		h.deleteClaim(names, ref)
		if after := dataOf(h.root(http.MethodGet, "sys/policies/acl/"+ext, nil))["policy"]; after != before {
			t.Fatal("external policy removed by a claim's deletion")
		}
		h.root(http.MethodDelete, "sys/policies/acl/"+ext, nil)
	})

	t.Run("the ledger removes what left spec", func(t *testing.T) {
		c := shapes[1].DeepCopy()
		c.Name, c.Spec.ClusterRef.Name, c.Spec.ClusterRef.KubeconfigSecret = "ff0001", "ff0001", "ff0001-infra-kubeconfig"
		c.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(c.Name)
		c.Spec.Auth.MountPath, c.Spec.SecretsPrefix = "acme-ff0001", "clusters/acme-ff0001"
		c.Spec.Transit = nil
		rules := `path "secret/data/clusters/acme-ff0001/x" { capabilities = ["read"] }`
		c.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "ff-a", Rules: rules}, {Name: "ff-b", Rules: rules}}
		c.Spec.Roles = []vaultv1alpha1.RoleSpec{
			{Name: "ra", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "a", Namespace: "x"}, Policies: []string{"ff-a"}},
			{Name: "rb", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "b", Namespace: "x"}, Policies: []string{"ff-b"}},
		}
		h.kubeconfigSecret("acme", c.Name)
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 1, c)
		fresh := h.claim(c)
		fresh.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "ff-c", Rules: rules}}
		fresh.Spec.Roles = []vaultv1alpha1.RoleSpec{{Name: "rc", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "c", Namespace: "x"}, Policies: []string{"ff-c"}}}
		if err := h.k8s.Update(h.ctx, fresh); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 2, c)
		if got := h.listKeys("auth/acme-ff0001/role"); !equalStrings(got, []string{"rc"}) {
			t.Errorf("roles = %v, want [rc]", got)
		}
		for name, want := range map[string]bool{"ff-a": false, "ff-b": false, "ff-c": true} {
			if got := h.root(http.MethodGet, "sys/policies/acl/"+name, nil) != nil; got != want {
				t.Errorf("policy %s present=%t, want %t", name, got, want)
			}
		}
		fresh = h.claim(c)
		fresh.Spec.Policies, fresh.Spec.Roles = nil, nil
		if err := h.k8s.Update(h.ctx, fresh); err != nil {
			t.Fatal(err)
		}
		h.cycles(r, 2, c)
		if h.root(http.MethodGet, "sys/policies/acl/ff-c", nil) != nil || len(h.listKeys("auth/acme-ff0001/role")) != 0 {
			t.Error("spec [] left policies or roles behind")
		}
		h.deleteClaim(r, c)
	})

	t.Run("enforce keeps an escalation out of Vault; the twin is written", func(t *testing.T) {
		enforce := h.reconciler(controller.OwnershipPolicy{}, policyguard.ModeEnforce)
		bad := shapes[1].DeepCopy()
		bad.Name, bad.Spec.ClusterRef.Name, bad.Spec.ClusterRef.KubeconfigSecret = "gg0001", "gg0001", "gg0001-infra-kubeconfig"
		bad.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(bad.Name)
		bad.Spec.Auth.MountPath, bad.Spec.SecretsPrefix = "acme-gg0001", "clusters/acme-gg0001"
		bad.Spec.Transit, bad.Spec.Roles = nil, nil
		bad.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "gg-escalate", Rules: `path "sys/policies/acl/*" { capabilities = ["create", "update"] }`}}
		twin := bad.DeepCopy()
		twin.Name, twin.Spec.ClusterRef.Name, twin.Spec.ClusterRef.KubeconfigSecret = "gg0002", "gg0002", "gg0002-infra-kubeconfig"
		twin.Spec.Auth.TokenReviewer.ServiceAccount.Name = reviewerName(twin.Name)
		twin.Spec.Auth.MountPath, twin.Spec.SecretsPrefix = "acme-gg0002", "clusters/acme-gg0002"
		twin.Spec.Policies = []vaultv1alpha1.PolicySpec{{Name: "gg-own", Rules: `path "secret/data/clusters/acme-gg0002/*" { capabilities = ["read"] }`}}
		for _, c := range []*vaultv1alpha1.VaultClaim{bad, twin} {
			h.kubeconfigSecret("acme", c.Name)
			if err := h.k8s.Create(h.ctx, c); err != nil {
				t.Fatal(err)
			}
		}
		h.cycles(enforce, 3, bad, twin)
		if got := reasonOf(h.claim(bad), vaultv1alpha1.ConditionPoliciesApplied); got != controller.ReasonPolicyGuardViolation {
			t.Fatalf("PoliciesApplied reason = %s", got)
		}
		if h.root(http.MethodGet, "sys/policies/acl/gg-escalate", nil) != nil {
			t.Fatal("refused policy is in Vault")
		}
		if h.root(http.MethodGet, "sys/policies/acl/gg-own", nil) == nil {
			t.Fatal("twin policy was not written")
		}
		h.deleteClaim(enforce, bad)
		h.deleteClaim(enforce, twin)
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
