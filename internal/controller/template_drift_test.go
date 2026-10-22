/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

func templatedClaim() *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 1},
		Spec: vaultv1alpha1.VaultClaimSpec{
			SecretsPrefix: "clusters/ec8a00",
			Auth:          vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"},
			Policies: []vaultv1alpha1.PolicySpec{{
				Name: "ec8a00-apps",
				IdentityPaths: []vaultv1alpha1.IdentityPath{
					{Path: "secret/data/clusters/ec8a00/{serviceAccountNamespace}/{serviceAccountName}", Capabilities: []string{"read"}},
				},
			}},
			Roles: []vaultv1alpha1.RoleSpec{{
				Name:                 "apps",
				BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Names: []string{"b", "a"}, Namespace: "apps"},
				Policies:             []string{"ec8a00-apps"},
			}},
		},
		Status: vaultv1alpha1.VaultClaimStatus{Vault: &vaultv1alpha1.VaultStatusSummary{
			AuthMountPath:     "kubernetes-ec8a00",
			AuthMountAccessor: "auth_kubernetes_old",
			AppliedPolicies:   []string{"ec8a00-apps"},
			AppliedRoles:      []string{"apps"},
		}},
	}
}

// liveFor is the Vault state a full pass leaves for claim, rendered with
// accessor.
func liveFor(t *testing.T, claim *vaultv1alpha1.VaultClaim, accessor string) *fakeVaultClient {
	t.Helper()
	policies := map[string]string{}
	for _, p := range claim.Spec.Policies {
		body, err := renderClaimPolicy(p, accessor)
		if err != nil {
			t.Fatalf("render %s: %v", p.Name, err)
		}
		policies[p.Name] = body
	}
	roles := map[string]vault.KubernetesRole{}
	for _, r := range claim.Spec.Roles {
		roles[r.Name] = roleBody(r)
	}
	return &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{"kubernetes-ec8a00/": {Type: "kubernetes", Accessor: accessor}},
		ListPoliciesResp:   []string{"ec8a00-apps"},
		ListRolesResp:      []string{"apps"},
		AuthConfigs:        reviewerSet(),
		WrittenPolicies:    policies,
		WrittenRoles:       roles,
	}
}

// A recreated mount has a new accessor; the templated bodies in Vault name the
// old one and grant nothing. Drift must see it; the same accessor, or none
// recorded yet, is not drift.
func TestDetectDriftSeesAChangedAccessor(t *testing.T) {
	claim := templatedClaim()
	fake := liveFor(t, claim, "auth_kubernetes_old")
	fake.ListAuthMountsResp["kubernetes-ec8a00/"] = vault.AuthMountInfo{Type: "kubernetes", Accessor: "auth_kubernetes_new"}
	report, err := (&VaultClaimReconciler{}).detectDrift(context.Background(), fake, claim)
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if !report.AccessorChanged || !strings.Contains(report.Summary(), "accessor") {
		t.Fatalf("changed accessor not reported: %+v / %q", report, report.Summary())
	}

	twin := liveFor(t, claim, "auth_kubernetes_old")
	report, err = (&VaultClaimReconciler{}).detectDrift(context.Background(), twin, claim)
	if err != nil {
		t.Fatalf("detectDrift twin: %v", err)
	}
	if report.Found() {
		t.Fatalf("same accessor reported as drift: %+v", report)
	}

	unrecorded := templatedClaim()
	unrecorded.Status.Vault.AuthMountAccessor = ""
	fresh := liveFor(t, unrecorded, "auth_kubernetes_new")
	report, err = (&VaultClaimReconciler{}).detectDrift(context.Background(), fresh, unrecorded)
	if err != nil {
		t.Fatalf("detectDrift unrecorded: %v", err)
	}
	if report.Found() {
		t.Fatalf("an accessor not recorded yet reported as drift: %+v", report)
	}
}

// A hand edit of a templated policy is drift: its body is compared with the
// body rendered from the recorded accessor, not skipped.
func TestDetectDriftComparesTemplatedPolicyBodies(t *testing.T) {
	claim := templatedClaim()
	fake := liveFor(t, claim, "auth_kubernetes_old")
	fake.WrittenPolicies["ec8a00-apps"] = `path "secret/data/*" { capabilities = ["read"] }`
	report, err := (&VaultClaimReconciler{}).detectDrift(context.Background(), fake, claim)
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if len(report.ChangedPolicies) != 1 {
		t.Fatalf("hand-edited templated policy not reported: %+v", report)
	}

	legacy := templatedClaim()
	legacy.Spec.Policies[0] = vaultv1alpha1.PolicySpec{Name: "ec8a00-apps",
		Rules: "path \"secret/data/{{`{{`}}identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace{{`}}`}}\" { capabilities = [\"read\"] }"}
	edited := liveFor(t, legacy, "auth_kubernetes_old")
	edited.WrittenPolicies["ec8a00-apps"] = `path "secret/data/*" { capabilities = ["read"] }`
	report, err = (&VaultClaimReconciler{}).detectDrift(context.Background(), edited, legacy)
	if err != nil {
		t.Fatalf("detectDrift legacy: %v", err)
	}
	if len(report.ChangedPolicies) != 1 {
		t.Fatalf("hand-edited legacy templated policy not reported: %+v", report)
	}
}

// Content drift is judged for every claim, not only for claims with Transit.
func TestContentDriftRunsWithoutTransit(t *testing.T) {
	claim := templatedClaim()
	fake := liveFor(t, claim, "auth_kubernetes_old")
	tampered := fake.WrittenRoles["apps"]
	tampered.TokenPolicies = []string{"root"}
	fake.WrittenRoles["apps"] = tampered
	report, err := (&VaultClaimReconciler{}).detectDrift(context.Background(), fake, claim)
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if len(report.ChangedRoles) != 1 {
		t.Fatalf("tampered role of a claim without transit not reported: %+v", report)
	}
}

// names is a set: another order is not drift, another member is.
func TestRoleBodyDiffComparesNamesAsASet(t *testing.T) {
	want := vaultv1alpha1.RoleSpec{Name: "apps", Policies: []string{"p"},
		BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Names: []string{"b", "a"}, Namespace: "apps"}}
	live := &vault.KubernetesRole{BoundServiceAccountNames: []string{"a", "b"}, BoundServiceAccountNamespaces: []string{"apps"}, TokenPolicies: []string{"p"}}
	if d := roleBodyDiff(want, live); d != "" {
		t.Fatalf("another order reported: %s", d)
	}
	live.BoundServiceAccountNames = []string{"b", "a"}
	if d := roleBodyDiff(want, live); d != "" {
		t.Fatalf("the spec order reported: %s", d)
	}
	live.BoundServiceAccountNames = []string{"a", "c"}
	if d := roleBodyDiff(want, live); !strings.Contains(d, "bound SA names") {
		t.Fatalf("another member not reported: %q", d)
	}
}

func TestRoleBodyDiffComparesAliasNameSourceWhenSet(t *testing.T) {
	want := vaultv1alpha1.RoleSpec{Name: "apps", Policies: []string{"p"}, AliasNameSource: vaultv1alpha1.AliasNameSourceName,
		BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "a", Namespace: "apps"}}
	live := &vault.KubernetesRole{BoundServiceAccountNames: []string{"a"}, BoundServiceAccountNamespaces: []string{"apps"},
		TokenPolicies: []string{"p"}, AliasNameSource: vaultv1alpha1.AliasNameSourceUID}
	if d := roleBodyDiff(want, live); !strings.Contains(d, "alias_name_source") {
		t.Fatalf("alias_name_source change not reported: %q", d)
	}
	want.AliasNameSource = ""
	if d := roleBodyDiff(want, live); d != "" {
		t.Fatalf("unset alias_name_source reported: %s", d)
	}
}

// The role body of a claim without the new fields is what the legacy release
// sent, on the wire; names are sent sorted and alias_name_source when set.
func TestRoleBodyOnTheWire(t *testing.T) {
	legacy := vaultv1alpha1.RoleSpec{Name: "r", Policies: []string{"p"},
		BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "vmauth", Namespace: "monitoring"}}
	raw, err := json.Marshal(roleBody(legacy))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"bound_service_account_names":["vmauth"],"bound_service_account_namespaces":["monitoring"],"token_policies":["p"],"token_ttl":0,"token_max_ttl":0}`
	if string(raw) != want {
		t.Fatalf("legacy role body changed:\ngot  %s\nwant %s", raw, want)
	}

	multi := legacy
	multi.BoundServiceAccounts = vaultv1alpha1.BoundServiceAccounts{Names: []string{"zot-2", "zot-1"}, Namespace: "registry"}
	multi.AliasNameSource = vaultv1alpha1.AliasNameSourceName
	body := roleBody(multi)
	if got := strings.Join(body.BoundServiceAccountNames, ","); got != "zot-1,zot-2" {
		t.Fatalf("names sent as %s, want sorted", got)
	}
	if body.AliasNameSource != vaultv1alpha1.AliasNameSourceName {
		t.Fatalf("alias_name_source = %q", body.AliasNameSource)
	}
	if multi.BoundServiceAccounts.Names[0] != "zot-2" {
		t.Fatal("sorting changed the spec")
	}
}

// A full pass that reads a new accessor says so and renders the policies with
// it; the same accessor says nothing.
func TestApplyPoliciesRendersAgainOnAChangedAccessor(t *testing.T) {
	claim := templatedClaim()
	fake := &fakeVaultClient{AccessorResp: "auth_kubernetes_new"}
	rec := record.NewFakeRecorder(10)
	r := &VaultClaimReconciler{Recorder: rec}
	state := &pipelineState{Vault: fake}
	if res, err := r.stepApplyPolicies(context.Background(), claim, state); err != nil || res != Proceed {
		t.Fatalf("stepApplyPolicies = %v, %v", res, err)
	}
	if !strings.Contains(fake.WrittenPolicies["ec8a00-apps"], "aliases.auth_kubernetes_new.metadata") {
		t.Fatalf("policy not rendered with the new accessor: %q", fake.WrittenPolicies["ec8a00-apps"])
	}
	if claim.Status.Vault.AuthMountAccessor != "auth_kubernetes_new" {
		t.Fatalf("status accessor = %q", claim.Status.Vault.AuthMountAccessor)
	}
	if got := strings.Join(drainEvents(rec), "\n"); !strings.Contains(got, "AuthMountAccessorChanged") {
		t.Fatalf("no AuthMountAccessorChanged event: %q", got)
	}

	if _, err := r.stepApplyPolicies(context.Background(), claim, state); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if got := strings.Join(drainEvents(rec), "\n"); strings.Contains(got, "AuthMountAccessorChanged") {
		t.Fatalf("unchanged accessor reported: %q", got)
	}
}
