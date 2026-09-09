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
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

func transitClaim(keys ...vaultv1alpha1.TransitKeySpec) *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "a8f60d", Namespace: "dlputi1u"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			Auth: vaultv1alpha1.AuthSpec{MountPath: "dlputi1u-a8f60d"},
			Transit: &vaultv1alpha1.TransitSpec{
				MountPath: "transit",
				Keys:      keys,
			},
		},
	}
}

func hardenedKey(name string) vaultv1alpha1.TransitKeySpec {
	return vaultv1alpha1.TransitKeySpec{Name: name, Type: "aes256-gcm96"}
}

func transitReconciler() *VaultClaimReconciler {
	return &VaultClaimReconciler{}
}

// transitCondition returns the TransitKeysReady condition, or nil when the
// step deliberately left it unset.
func transitCondition(claim *vaultv1alpha1.VaultClaim) *metav1.Condition {
	for i := range claim.Status.Conditions {
		if claim.Status.Conditions[i].Type == vaultv1alpha1.ConditionTransitKeysReady {
			return &claim.Status.Conditions[i]
		}
	}
	return nil
}

func TestTransitStepSkippedWhenNotDeclared(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "a8f60d", Namespace: "dlputi1u"},
		Spec:       vaultv1alpha1.VaultClaimSpec{Auth: vaultv1alpha1.AuthSpec{MountPath: "m"}},
	}
	fake := &fakeVaultClient{}
	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil || res != Proceed {
		t.Fatalf("res=%v err=%v, want Proceed/nil", res, err)
	}
	if fake.MountExistsCalls != 0 {
		t.Errorf("MountExistsCalls = %d, want 0: a claim without spec.transit must not touch Vault", fake.MountExistsCalls)
	}
	if c := transitCondition(claim); c != nil {
		t.Errorf("condition %s = %v, want absent", c.Type, c.Status)
	}
}

func TestTransitStepWaitsWhenMountMissing(t *testing.T) {
	claim := transitClaim(hardenedKey("dlputi1u-a8f60d-l2"))
	fake := &fakeVaultClient{MountExistsResp: map[string]bool{"transit": false}}

	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != Wait {
		t.Errorf("res = %v, want Wait", res)
	}
	if fake.CreateTransitKeyCalls != 0 {
		t.Errorf("CreateTransitKeyCalls = %d, want 0", fake.CreateTransitKeyCalls)
	}
	c := transitCondition(claim)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "MountMissing" {
		t.Fatalf("condition = %+v, want False/MountMissing", c)
	}
}

func TestTransitStepCreatesHardenedKeyAndRecordsLedger(t *testing.T) {
	rotate := metav1.Duration{Duration: 0}
	claim := transitClaim(vaultv1alpha1.TransitKeySpec{
		Name:             "dlputi1u-a8f60d-l2",
		Type:             "aes256-gcm96",
		AutoRotatePeriod: &rotate,
	})
	fake := &fakeVaultClient{MountExistsResp: map[string]bool{"transit": true}}

	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil || res != Proceed {
		t.Fatalf("res=%v err=%v, want Proceed/nil", res, err)
	}

	created, ok := fake.CreatedTransitKeys["transit/dlputi1u-a8f60d-l2"]
	if !ok {
		t.Fatal("key was not created")
	}
	if created.Type != "aes256-gcm96" {
		t.Errorf("Type = %q, want aes256-gcm96", created.Type)
	}
	if created.Exportable || created.AllowPlaintextBackup || created.Derived {
		t.Errorf("key created without hardening: %+v", created)
	}
	cfg, ok := fake.UpdatedTransitCfgs["transit/dlputi1u-a8f60d-l2"]
	if !ok {
		t.Fatal("config was not written after creation")
	}
	if cfg.DeletionAllowed {
		t.Error("DeletionAllowed = true, want false")
	}

	if len(claim.Status.Vault.TransitKeys) != 1 {
		t.Fatalf("ledger has %d entries, want 1", len(claim.Status.Vault.TransitKeys))
	}
	entry := claim.Status.Vault.TransitKeys[0]
	if !entry.CreatedByClaim {
		t.Error("CreatedByClaim = false; the interlock depends on this flag")
	}
	if entry.LatestVersion != 1 {
		t.Errorf("LatestVersion = %d, want 1 (read back, not assumed)", entry.LatestVersion)
	}
	if c := transitCondition(claim); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v, want True", c)
	}
}

// A key this claim created and that vanished must stop reconciliation, not be recreated.
func TestTransitStepRefusesToRecreateVanishedKey(t *testing.T) {
	claim := transitClaim(hardenedKey("dlputi1u-a8f60d-l2"))
	claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{
		TransitKeys: []vaultv1alpha1.TransitKeyStatus{
			{Name: "dlputi1u-a8f60d-l2", LatestVersion: 3, CreatedByClaim: true},
		},
	}
	fake := &fakeVaultClient{MountExistsResp: map[string]bool{"transit": true}}

	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != Wait {
		t.Errorf("res = %v, want Wait", res)
	}
	if fake.CreateTransitKeyCalls != 0 {
		t.Fatalf("CreateTransitKeyCalls = %d, want 0 — the key must NOT be recreated", fake.CreateTransitKeyCalls)
	}
	c := transitCondition(claim)
	if c == nil || c.Reason != "KeyMissing" {
		t.Fatalf("condition = %+v, want reason KeyMissing", c)
	}
	if len(claim.Status.Vault.TransitKeys) != 1 || !claim.Status.Vault.TransitKeys[0].CreatedByClaim {
		t.Errorf("ledger = %+v, want the CreatedByClaim entry preserved", claim.Status.Vault.TransitKeys)
	}
}

// A key this claim never created is adopted, not rejected.
func TestTransitStepAdoptsPreexistingKey(t *testing.T) {
	claim := transitClaim(hardenedKey("dlputi1u-a8f60d-l2"))
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys: map[string]*vault.TransitKey{
			"transit/dlputi1u-a8f60d-l2": {Name: "dlputi1u-a8f60d-l2", Type: "aes256-gcm96", LatestVersion: 7},
		},
	}

	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil || res != Proceed {
		t.Fatalf("res=%v err=%v, want Proceed/nil", res, err)
	}
	if fake.CreateTransitKeyCalls != 0 {
		t.Errorf("CreateTransitKeyCalls = %d, want 0", fake.CreateTransitKeyCalls)
	}
	entry := claim.Status.Vault.TransitKeys[0]
	if entry.CreatedByClaim {
		t.Error("CreatedByClaim = true for an adopted key, want false")
	}
	if entry.LatestVersion != 7 {
		t.Errorf("LatestVersion = %d, want 7", entry.LatestVersion)
	}
}

func TestTransitStepStopsOnUnrepairableMismatch(t *testing.T) {
	cases := []struct {
		name string
		live *vault.TransitKey
	}{
		{
			name: "type is fixed at creation",
			live: &vault.TransitKey{Name: "k", Type: "aes128-gcm96", LatestVersion: 1},
		},
		{
			name: "exportable cannot be revoked",
			live: &vault.TransitKey{Name: "k", Type: "aes256-gcm96", Exportable: true, LatestVersion: 1},
		},
		{
			name: "plaintext backup cannot be revoked",
			live: &vault.TransitKey{Name: "k", Type: "aes256-gcm96", AllowPlaintextBackup: true, LatestVersion: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim := transitClaim(hardenedKey("k"))
			fake := &fakeVaultClient{
				MountExistsResp: map[string]bool{"transit": true},
				TransitKeys:     map[string]*vault.TransitKey{"transit/k": tc.live},
			}
			res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res != Wait {
				t.Errorf("res = %v, want Wait", res)
			}
			c := transitCondition(claim)
			if c == nil || c.Reason != "KeyMismatch" {
				t.Fatalf("condition = %+v, want reason KeyMismatch", c)
			}
			if fake.UpdateTransitCfgCalls != 0 {
				t.Errorf("UpdateTransitCfgCalls = %d, want 0: the step must not pretend it can fix this", fake.UpdateTransitCfgCalls)
			}
		})
	}
}

func TestTransitStepRepairsMutableConfigDrift(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys: map[string]*vault.TransitKey{
			// Someone allowed deletion and set rotation by hand.
			"transit/k": {Name: "k", Type: "aes256-gcm96", DeletionAllowed: true, AutoRotatePeriod: 3600, LatestVersion: 2},
		},
	}

	res, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err != nil || res != Proceed {
		t.Fatalf("res=%v err=%v, want Proceed/nil", res, err)
	}
	cfg, ok := fake.UpdatedTransitCfgs["transit/k"]
	if !ok {
		t.Fatal("config drift was not repaired")
	}
	if cfg.DeletionAllowed {
		t.Error("DeletionAllowed still true after repair")
	}
	if cfg.AutoRotatePeriodSecs != 0 {
		t.Errorf("AutoRotatePeriodSecs = %d, want 0", cfg.AutoRotatePeriodSecs)
	}
}

// A 403 means the operator's ACL lacks the Transit paths, not a flaky Vault.
func TestTransitStepNamesForbiddenDistinctly(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	forbidden := &vault.APIError{Method: http.MethodGet, Path: "sys/mounts", StatusCode: http.StatusForbidden}
	fake := &fakeVaultClient{MountExistsErr: forbidden}

	_, err := transitReconciler().stepEnsureTransitKeys(context.Background(), claim, &pipelineState{Vault: fake})
	if err == nil {
		t.Fatal("expected an error")
	}
	c := transitCondition(claim)
	if c == nil || c.Reason != "MountCheckForbidden" {
		t.Fatalf("condition = %+v, want reason MountCheckForbidden", c)
	}
}

func TestTransitMountPathDefaults(t *testing.T) {
	cases := []struct {
		name  string
		claim *vaultv1alpha1.VaultClaim
		want  string
	}{
		{"explicit", transitClaim(), "transit"},
		{
			name:  "empty falls back",
			claim: &vaultv1alpha1.VaultClaim{Spec: vaultv1alpha1.VaultClaimSpec{Transit: &vaultv1alpha1.TransitSpec{}}},
			want:  "transit",
		},
		{
			name:  "custom respected",
			claim: &vaultv1alpha1.VaultClaim{Spec: vaultv1alpha1.VaultClaimSpec{Transit: &vaultv1alpha1.TransitSpec{MountPath: "kms-transit"}}},
			want:  "kms-transit",
		},
		{"absent", &vaultv1alpha1.VaultClaim{}, "transit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := transitMountPath(tc.claim); got != tc.want {
				t.Errorf("transitMountPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAutoRotateSeconds(t *testing.T) {
	if got := autoRotateSeconds(vaultv1alpha1.TransitKeySpec{}); got != 0 {
		t.Errorf("nil period = %d, want 0", got)
	}
	d := metav1.Duration{Duration: 2 * time.Hour}
	if got := autoRotateSeconds(vaultv1alpha1.TransitKeySpec{AutoRotatePeriod: &d}); got != 7200 {
		t.Errorf("2h = %d, want 7200", got)
	}
}
