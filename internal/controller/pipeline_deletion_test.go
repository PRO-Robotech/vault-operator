/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"reflect"
	"testing"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func TestRoleNamesForDeletion_StatusFirst(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{
		Spec: vaultv1alpha1.VaultClaimSpec{
			Roles: []vaultv1alpha1.RoleSpec{{Name: "spec-only"}, {Name: "in-both"}},
		},
		Status: vaultv1alpha1.VaultClaimStatus{
			Vault: &vaultv1alpha1.VaultStatusSummary{
				AppliedRoles: []string{"in-both", "status-only"},
			},
		},
	}
	got := roleNamesForDeletion(claim)
	want := []string{"in-both", "status-only", "spec-only"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roleNamesForDeletion = %v, want %v", got, want)
	}
}

func TestRoleNamesForDeletion_StatusNilUsesSpec(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{
		Spec: vaultv1alpha1.VaultClaimSpec{
			Roles: []vaultv1alpha1.RoleSpec{{Name: "r1"}, {Name: "r2"}},
		},
	}
	got := roleNamesForDeletion(claim)
	want := []string{"r1", "r2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestPolicyNamesForDeletion_Dedup(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{
		Spec: vaultv1alpha1.VaultClaimSpec{
			Policies: []vaultv1alpha1.PolicySpec{{Name: "p-shared"}, {Name: "p-spec"}},
		},
		Status: vaultv1alpha1.VaultClaimStatus{
			Vault: &vaultv1alpha1.VaultStatusSummary{
				AppliedPolicies: []string{"p-status", "p-shared"},
			},
		},
	}
	got := policyNamesForDeletion(claim)
	want := []string{"p-status", "p-shared", "p-spec"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestPolicyNamesForDeletion_Empty(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{}
	got := policyNamesForDeletion(claim)
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}
