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
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

// One operator process holds one Vault token per VaultConfig: probes and
// claim passes after the first login add no token to Vault.
func TestOneVaultTokenPerProcessE2E(t *testing.T) {
	h := newHarness(t, "")
	h.vaultConfig("default", mgmtRole)
	h.namespace("tokens")
	claim := guestClaim("tokens", "tok-1", "tok-1")
	claim.Spec.Roles[0].Policies = []string{"tok-1-read"}
	if err := h.k8s.Create(h.ctx, claim); err != nil {
		t.Fatalf("create claim: %v", err)
	}
	r := h.reconciler(controller.OwnershipPolicy{}, policyguard.ModeAudit)
	probe := &controller.VaultConfigReconciler{Client: h.k8s, Scheme: h.scheme, VaultFactory: h.factory}
	h.cycles(r, 1, claim)
	if got := h.claim(claim); got.Status.Phase != vaultv1alpha1.PhaseReady {
		t.Fatalf("claim phase = %s, conditions %+v", got.Status.Phase, got.Status.Conditions)
	}

	before := len(h.listKeys("auth/token/accessors"))
	for range 10 {
		if _, err := probe.Reconcile(h.ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}}); err != nil {
			t.Fatalf("probe: %v", err)
		}
		h.cycles(r, 1, claim)
	}
	after := len(h.listKeys("auth/token/accessors"))
	if after != before {
		t.Fatalf("Vault tokens: %d before, %d after 10 probes and 10 claim passes; want no new token", before, after)
	}
	if got := h.claim(claim); got.Status.Phase != vaultv1alpha1.PhaseReady {
		t.Fatalf("claim phase after the passes = %s", got.Status.Phase)
	}
	h.deleteClaim(r, claim)
}
