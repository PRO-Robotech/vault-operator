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
	"fmt"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const driftMount = "kubernetes-c1"

// driftClaim is a Ready claim with three policies and three roles, recorded
// in its ledger, on its own mount.
func driftClaim(pruning string) *vaultv1alpha1.VaultClaim {
	c := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			Auth:           vaultv1alpha1.AuthSpec{MountPath: driftMount, RolePruning: pruning},
		},
		Status: vaultv1alpha1.VaultClaimStatus{Vault: &vaultv1alpha1.VaultStatusSummary{AuthMountPath: driftMount}},
	}
	for _, n := range []string{"p1", "p2", "p3"} {
		c.Spec.Policies = append(c.Spec.Policies, vaultv1alpha1.PolicySpec{Name: n, Rules: `path "secret/data/` + n + `" { capabilities = ["read"] }`})
		c.Status.Vault.AppliedPolicies = append(c.Status.Vault.AppliedPolicies, n)
	}
	for _, n := range []string{"r1", "r2", "r3"} {
		c.Spec.Roles = append(c.Spec.Roles, vaultv1alpha1.RoleSpec{Name: n, Policies: []string{"p1"},
			BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: n, Namespace: "apps"}})
		c.Status.Vault.AppliedRoles = append(c.Status.Vault.AppliedRoles, n)
	}
	return c
}

// driftVault holds what driftClaim declares, on an operator-size Vault: many
// other mounts, policies and roles the claim does not own.
func driftVault(t *testing.T, claim *vaultv1alpha1.VaultClaim) *httpVault {
	t.Helper()
	v := newHTTPVault()
	v.authMounts[driftMount+"/"] = map[string]any{"type": "kubernetes", "accessor": "auth_kubernetes_c1",
		"description": mountDescription(claim)}
	for i := range 200 {
		v.authMounts[fmt.Sprintf("kubernetes-other-%d/", i)] = map[string]any{"type": "kubernetes"}
	}
	for i := range claim.Spec.Policies {
		v.policies[claim.Spec.Policies[i].Name] = claim.Spec.Policies[i].Rules
	}
	for i := range claim.Spec.Roles {
		v.roles[claim.Spec.Roles[i].Name] = map[string]any{
			"bound_service_account_names":      []string{claim.Spec.Roles[i].BoundServiceAccounts.Name},
			"bound_service_account_namespaces": []string{"apps"},
			"token_policies":                   []string{"p1"},
		}
	}
	t.Cleanup(v.start().Close)
	return v
}

func driftClient(t *testing.T, addr string) *vault.Client {
	t.Helper()
	c, err := vault.New(vault.Config{Address: addr, AuthPath: "kubernetes-mgmt", Role: "vault-operator",
		JWTSource: vault.StaticJWTSource("jwt")})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

func sortedCalls(calls []string) []string {
	out := slices.Clone(calls)
	slices.Sort(out)
	return out
}

// A drift check reads the claim's own objects one by one: what it costs does
// not depend on how many mounts, policies and roles Vault holds for others.
func TestDriftReadsOnlyTheClaimsOwnObjects(t *testing.T) {
	cases := []struct {
		name    string
		pruning string
		want    []string
	}{
		{"Owned", vaultv1alpha1.RolePruningOwned, []string{
			"GET auth/" + driftMount + "/config",
			"GET auth/" + driftMount + "/role/r1", "GET auth/" + driftMount + "/role/r2", "GET auth/" + driftMount + "/role/r3",
			"GET sys/auth/" + driftMount,
			"GET sys/policies/acl/p1", "GET sys/policies/acl/p2", "GET sys/policies/acl/p3",
		}},
		// Exclusive judges every role on the mount: one LIST, which also
		// answers presence.
		{"Exclusive", vaultv1alpha1.RolePruningExclusive, []string{
			"GET auth/" + driftMount + "/config",
			"GET sys/auth/" + driftMount,
			"GET sys/policies/acl/p1", "GET sys/policies/acl/p2", "GET sys/policies/acl/p3",
			"LIST auth/" + driftMount + "/role",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim := driftClaim(tc.pruning)
			v := driftVault(t, claim)
			vc := driftClient(t, v.URL)
			if err := vc.Login(context.Background()); err != nil {
				t.Fatalf("Login: %v", err)
			}
			v.reset()

			report, err := (&VaultClaimReconciler{}).detectDrift(context.Background(), vc, claim)
			if err != nil {
				t.Fatalf("detectDrift: %v", err)
			}
			if report.Found() {
				t.Fatalf("drift on a claim Vault matches: %s", report.Summary())
			}
			if got := sortedCalls(v.calls()); !slices.Equal(got, tc.want) {
				t.Fatalf("calls =\n  %v\nwant\n  %v", got, tc.want)
			}
		})
	}
}

// Twin: reading object by object still finds what is missing.
func TestDriftByObjectFindsWhatIsMissing(t *testing.T) {
	claim := driftClaim(vaultv1alpha1.RolePruningOwned)
	v := driftVault(t, claim)
	v.mu.Lock()
	delete(v.policies, "p2")
	delete(v.roles, "r3")
	v.mu.Unlock()
	vc := driftClient(t, v.URL)

	report, err := (&VaultClaimReconciler{}).detectDrift(context.Background(), vc, claim)
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if !slices.Equal(report.MissingPolicies, []string{"p2"}) || !slices.Equal(report.MissingRoles, []string{"r3"}) {
		t.Fatalf("missing policies %v, roles %v; want [p2] and [r3]", report.MissingPolicies, report.MissingRoles)
	}
	if report.MountMissing {
		t.Fatal("the mount is reported missing")
	}
}

// Without read on sys/auth/<mount> (the operator policy before it is widened)
// the check falls back to the sys/auth listing, and keeps using it.
func TestDriftFallsBackToTheMountListingOn403(t *testing.T) {
	claim := driftClaim(vaultv1alpha1.RolePruningOwned)
	v := driftVault(t, claim)
	v.mu.Lock()
	v.authReadDenied = true
	v.mu.Unlock()
	vc := driftClient(t, v.URL)
	if err := vc.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	r := &VaultClaimReconciler{}

	for pass := range 2 {
		v.reset()
		report, err := r.detectDrift(context.Background(), vc, claim)
		if err != nil {
			t.Fatalf("pass %d: detectDrift: %v", pass, err)
		}
		if report.Found() {
			t.Fatalf("pass %d: drift on a claim Vault matches: %s", pass, report.Summary())
		}
		calls := v.calls()
		if !slices.Contains(calls, "GET sys/auth") {
			t.Fatalf("pass %d: calls %v, want the sys/auth listing", pass, calls)
		}
		direct := slices.Contains(calls, "GET sys/auth/"+driftMount)
		if pass == 0 && !direct {
			t.Fatalf("pass 0: calls %v, want one GET sys/auth/%s first", calls, driftMount)
		}
		if pass == 1 && direct {
			t.Fatalf("pass 1: calls %v: a denied read is asked again", calls)
		}
	}
}
