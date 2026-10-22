/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func inventoryClaims(n int) []client.Object {
	out := make([]client.Object, 0, n)
	for i := range n {
		c := &vaultv1alpha1.VaultClaim{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("c%d", i), Namespace: "ns"}}
		c.Status.Phase = vaultv1alpha1.PhaseReady
		if i%3 == 0 {
			c.Status.Phase = vaultv1alpha1.PhaseFailed
		}
		c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"p"}, AppliedRoles: []string{"r1", "r2"}}
		out = append(out, c)
	}
	return out
}

func inventoryRegistry(t *testing.T, objs []client.Object) *prometheus.Registry {
	t.Helper()
	cli := fakeclient.NewClientBuilder().WithScheme(newMapfuncTestScheme(t)).WithObjects(objs...).Build()
	reg := prometheus.NewRegistry()
	if err := RegisterInventory(reg, cli, KindVaultClaim); err != nil {
		t.Fatalf("RegisterInventory: %v", err)
	}
	return reg
}

// The inventory counts claims by phase and ledger entries by type.
func TestInventoryCountsClaimsAndLedgers(t *testing.T) {
	reg := inventoryRegistry(t, inventoryClaims(6))
	want := `
# HELP vault_operator_claims Claims by kind and phase, read from the informer cache at scrape time.
# TYPE vault_operator_claims gauge
vault_operator_claims{kind="VaultClaim",phase="Configuring"} 0
vault_operator_claims{kind="VaultClaim",phase="Deleting"} 0
vault_operator_claims{kind="VaultClaim",phase="Failed"} 2
vault_operator_claims{kind="VaultClaim",phase="Pending"} 0
vault_operator_claims{kind="VaultClaim",phase="Ready"} 4
vault_operator_claims{kind="VaultClaim",phase="Unknown"} 0
# HELP vault_operator_managed_objects Objects the claims' ledgers record, by claim kind and object type.
# TYPE vault_operator_managed_objects gauge
vault_operator_managed_objects{kind="VaultClaim",type="policy"} 6
vault_operator_managed_objects{kind="VaultClaim",type="role"} 12
vault_operator_managed_objects{kind="VaultClaim",type="transit_key"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"vault_operator_claims", "vault_operator_managed_objects"); err != nil {
		t.Fatal(err)
	}
}

// The number of series does not depend on the number of claims.
func TestInventorySeriesDoNotGrowWithClaims(t *testing.T) {
	few, err := testutil.GatherAndCount(inventoryRegistry(t, inventoryClaims(1)))
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	many, err := testutil.GatherAndCount(inventoryRegistry(t, inventoryClaims(300)))
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if few != many {
		t.Fatalf("series: %d for 1 claim, %d for 300", few, many)
	}
}

// An unknown kind is refused at registration.
func TestInventoryRefusesAnUnknownKind(t *testing.T) {
	if err := RegisterInventory(prometheus.NewRegistry(), nil, "Unknown"); err == nil {
		t.Fatal("an unknown kind was registered")
	}
}
