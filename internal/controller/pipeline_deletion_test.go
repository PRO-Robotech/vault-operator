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
	"reflect"
	"sort"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// runDeletion drives the real deleteVaultObjects with the given claims in the
// cluster; the first claim is the one being deleted.
func runDeletion(t *testing.T, ownership OwnershipPolicy, claims ...*vaultv1alpha1.VaultClaim) *fakeVaultClient {
	t.Helper()
	sch := runtime.NewScheme()
	if err := vaultv1alpha1.AddToScheme(sch); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	cfg := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address:     "https://vault.invalid:8200",
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{MountPath: "kubernetes-mgmt", Role: "vault-operator"},
		},
	}
	b := ctrlfake.NewClientBuilder().WithScheme(sch).WithObjects(cfg)
	for i, c := range claims {
		c.UID = types.UID("uid-" + c.Name)
		c.CreationTimestamp = metav1.Unix(int64(1000+i), 0)
		b = b.WithObjects(c.DeepCopy())
	}
	fakeVC := &fakeVaultClient{}
	r := &VaultClaimReconciler{Client: b.Build(), VaultFactory: &fakeVaultFactory{Client: fakeVC}, Ownership: ownership}
	if err := r.deleteVaultObjects(context.Background(), claims[0]); err != nil {
		t.Fatalf("deleteVaultObjects: %v", err)
	}
	return fakeVC
}

func ledgerClaim(name string, specRoles, specPolicies, ledgerRoles, ledgerPolicies []string) *vaultv1alpha1.VaultClaim {
	c := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
			Auth:           vaultv1alpha1.AuthSpec{MountPath: "kubernetes-" + name, AutoCreate: ptr.To(true)},
		},
	}
	for _, r := range specRoles {
		c.Spec.Roles = append(c.Spec.Roles, vaultv1alpha1.RoleSpec{Name: r})
	}
	for _, p := range specPolicies {
		c.Spec.Policies = append(c.Spec.Policies, vaultv1alpha1.PolicySpec{Name: p})
	}
	if ledgerRoles != nil || ledgerPolicies != nil {
		c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedRoles: ledgerRoles, AppliedPolicies: ledgerPolicies}
	}
	return c
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// Deletion trusts the ledger, not spec: a spec name the claim never wrote may
// belong to someone else.
func TestDeletionUsesTheLedgerNotSpec(t *testing.T) {
	got := runDeletion(t, OwnershipPolicy{}, ledgerClaim("a",
		[]string{"spec-only", "in-both"}, []string{"p-spec", "p-shared"},
		[]string{"in-both", "status-only"}, []string{"p-status", "p-shared"}))
	if want := []string{"in-both", "status-only"}; !reflect.DeepEqual(sorted(got.DeletedRoles), want) {
		t.Errorf("deleted roles = %v, want %v", got.DeletedRoles, want)
	}
	if want := []string{"p-shared", "p-status"}; !reflect.DeepEqual(sorted(got.DeletedPolicies), want) {
		t.Errorf("deleted policies = %v, want %v", got.DeletedPolicies, want)
	}
}

func TestDeletionWithoutLedgerDeletesNothing(t *testing.T) {
	got := runDeletion(t, OwnershipPolicy{}, ledgerClaim("a", []string{"r1", "r2"}, []string{"p1"}, nil, nil))
	if len(got.DeletedRoles)+len(got.DeletedPolicies) != 0 {
		t.Errorf("deleted roles %v and policies %v without a ledger", got.DeletedRoles, got.DeletedPolicies)
	}
}

// A ledger can be stale or hand-edited; reserved names and names another claim
// still holds are never deleted. The twin name in the same ledger is.
func TestDeletionSkipsReservedAndOtherClaimsNames(t *testing.T) {
	victim := ledgerClaim("a", nil, nil, nil, []string{"vault-operator-admin", "shared", "own"})
	other := ledgerClaim("b", nil, []string{"shared"}, nil, nil)
	got := runDeletion(t, OwnershipPolicy{ReservedPolicyNames: []string{"vault-operator-admin"}}, victim, other)
	if want := []string{"own"}; !reflect.DeepEqual(got.DeletedPolicies, want) {
		t.Errorf("deleted policies = %v, want %v", got.DeletedPolicies, want)
	}
}

// A guest's ledger on the operator mount never reaches the roles the operators
// log in with.
func TestDeletionNeverRemovesOperatorRoles(t *testing.T) {
	guest := ledgerClaim("g", nil, nil, []string{"vault-operator", "zot-1"}, nil)
	guest.Spec.Auth = vaultv1alpha1.AuthSpec{MountPath: "kubernetes-mgmt", AutoCreate: ptr.To(false), ManageConfig: ptr.To(false), RolePruning: vaultv1alpha1.RolePruningOwned}
	got := runDeletion(t, OwnershipPolicy{}, guest)
	if want := []string{"zot-1"}; !reflect.DeepEqual(got.DeletedRoles, want) {
		t.Errorf("deleted roles = %v, want %v", got.DeletedRoles, want)
	}
	if got.DisableAuthCalls != 0 {
		t.Errorf("a guest disabled its host mount")
	}
}
