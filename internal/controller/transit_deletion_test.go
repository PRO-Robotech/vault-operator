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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// deletionDecision drives the real deleteVaultObjects and reports what it did.
func deletionDecision(t *testing.T, policy string, autoCreate bool) *fakeVaultClient {
	t.Helper()

	sch := runtime.NewScheme()
	if err := vaultv1alpha1.AddToScheme(sch); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	cfg := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address: "https://vault.invalid:8200",
		},
	}
	claim := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "a8f60d", Namespace: "dlputi1u"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			DeletionPolicy: policy,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath:  "dlputi1u-a8f60d",
				AutoCreate: autoCreate,
			},
			Transit: &vaultv1alpha1.TransitSpec{
				MountPath: "transit",
				Keys:      []vaultv1alpha1.TransitKeySpec{hardenedKey("dlputi1u-a8f60d-l2")},
			},
		},
	}
	fakeVC := &fakeVaultClient{}
	r := &VaultClaimReconciler{
		Client:       ctrlfake.NewClientBuilder().WithScheme(sch).WithObjects(cfg).Build(),
		VaultFactory: &fakeVaultFactory{Client: fakeVC},
	}
	if err := r.deleteVaultObjects(context.Background(), claim); err != nil {
		t.Fatalf("deleteVaultObjects: %v", err)
	}
	return fakeVC
}

func TestDeletionAuthMountDecision(t *testing.T) {
	cases := []struct {
		name       string
		policy     string
		autoCreate bool
		wantDisabl bool
		why        string
	}{
		{
			name:   "Purge with autoCreate disables — the historical behaviour",
			policy: vaultv1alpha1.DeletionPolicyPurge, autoCreate: true, wantDisabl: true,
			why: "default teardown must keep working exactly as before",
		},
		{
			name:   "Retain keeps the mount for other consumers",
			policy: vaultv1alpha1.DeletionPolicyRetain, autoCreate: true, wantDisabl: false,
			why: "Retain revokes access via roles/policies, not by breaking the mount",
		},
		{
			name:   "adopted mount is never disabled",
			policy: vaultv1alpha1.DeletionPolicyPurge, autoCreate: false, wantDisabl: false,
			why: "creating was gated on autoCreate while deleting was not; disabling a mount we never made breaks its owner",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deletionDecision(t, tc.policy, tc.autoCreate)
			if tc.wantDisabl && len(got.DisabledAuthPaths) == 0 {
				t.Errorf("auth mount was not disabled; %s", tc.why)
			}
			if !tc.wantDisabl && len(got.DisabledAuthPaths) > 0 {
				t.Errorf("auth mount %v was disabled; %s", got.DisabledAuthPaths, tc.why)
			}
		})
	}
}

// No deletion policy may remove a Transit key.
func TestDeletionNeverTouchesTransitKeys(t *testing.T) {
	for _, policy := range []string{vaultv1alpha1.DeletionPolicyPurge, vaultv1alpha1.DeletionPolicyRetain} {
		t.Run(policy, func(t *testing.T) {
			got := deletionDecision(t, policy, true)
			if got.CreateTransitKeyCalls != 0 || got.UpdateTransitCfgCalls != 0 {
				t.Errorf("deletion wrote to Transit (create=%d, config=%d)", got.CreateTransitKeyCalls, got.UpdateTransitCfgCalls)
			}
			if got.ReadTransitKeyCalls != 0 {
				t.Errorf("ReadTransitKeyCalls = %d; deletion has no business reading keys", got.ReadTransitKeyCalls)
			}
		})
	}
}

// Drift must notice a key that disappeared from a Ready claim.
func TestDetectTransitDriftFindsMissingKey(t *testing.T) {
	claim := transitClaim(hardenedKey("dlputi1u-a8f60d-l2"))
	fake := &fakeVaultClient{MountExistsResp: map[string]bool{"transit": true}}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Found() {
		t.Fatal("Found() = false, want true for a missing key")
	}
	if len(report.MissingKeys) != 1 {
		t.Errorf("MissingKeys = %v, want one entry", report.MissingKeys)
	}
}

// Rotation outside the operator counts as drift.
func TestDetectTransitDriftFindsMovedVersion(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{
		TransitKeys: []vaultv1alpha1.TransitKeyStatus{{Name: "k", LatestVersion: 1, CreatedByClaim: true}},
	}
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys:     map[string]*vault.TransitKey{"transit/k": {Name: "k", Type: "aes256-gcm96", LatestVersion: 2}},
	}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.KeyVersionMoved) != 1 {
		t.Fatalf("KeyVersionMoved = %v, want one entry", report.KeyVersionMoved)
	}
	if report.Summary() == "" {
		t.Error("Summary() is empty; the drift event would say nothing")
	}
}

func TestDetectTransitDriftSilentWithoutTransit(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{Spec: vaultv1alpha1.VaultClaimSpec{}}
	fake := &fakeVaultClient{}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Found() {
		t.Error("Found() = true for a claim with no spec.transit")
	}
	if fake.MountExistsCalls != 0 {
		t.Errorf("MountExistsCalls = %d, want 0", fake.MountExistsCalls)
	}
}

// A role keeping its name but losing its audience is invisible to a name check.
func TestContentDriftFindsTamperedRole(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	claim.Spec.Roles = []vaultv1alpha1.RoleSpec{{
		Name:                 "kms-l2",
		BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "cp", Namespace: "beget-system"},
		Policies:             []string{"p"},
		Audience:             "vault-kms-plugin.dlputi1u-a8f60d.l2",
		TokenType:            "service",
		TokenNoDefaultPolicy: true,
	}}
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys:     map[string]*vault.TransitKey{"transit/k": {Name: "k", Type: "aes256-gcm96", LatestVersion: 1}},
		WrittenRoles: map[string]vault.KubernetesRole{
			"kms-l2": {
				BoundServiceAccountNames:      []string{"cp"},
				BoundServiceAccountNamespaces: []string{"beget-system"},
				TokenPolicies:                 []string{"p"},
				TokenType:                     "service",
				TokenNoDefaultPolicy:          true,
				Audience:                      "", // stripped by hand in Vault
			},
		},
	}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.ChangedRoles) != 1 {
		t.Fatalf("ChangedRoles = %v, want the tampered role", report.ChangedRoles)
	}
	if !strings.Contains(report.Summary(), "audience") {
		t.Errorf("Summary() = %q, want it to name the audience", report.Summary())
	}
}

// A policy can keep its name while its rules are rewritten.
func TestContentDriftFindsRewrittenPolicy(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	claim.Spec.Policies = []vaultv1alpha1.PolicySpec{{
		Name:  "p",
		Rules: `path "transit/encrypt/mine" { capabilities = ["update"] }`,
	}}
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys:     map[string]*vault.TransitKey{"transit/k": {Name: "k", Type: "aes256-gcm96", LatestVersion: 1}},
		WrittenPolicies: map[string]string{
			"p": `path "transit/decrypt/someone-elses" { capabilities = ["update"] }`,
		},
	}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.ChangedPolicies) != 1 {
		t.Fatalf("ChangedPolicies = %v, want the rewritten policy", report.ChangedPolicies)
	}
}

// Reindenting is not tampering.
func TestContentDriftIgnoresFormatting(t *testing.T) {
	claim := transitClaim(hardenedKey("k"))
	claim.Spec.Policies = []vaultv1alpha1.PolicySpec{{
		Name:  "p",
		Rules: "path \"transit/encrypt/mine\" {\n  capabilities = [\"update\"]\n}",
	}}
	fake := &fakeVaultClient{
		MountExistsResp: map[string]bool{"transit": true},
		TransitKeys:     map[string]*vault.TransitKey{"transit/k": {Name: "k", Type: "aes256-gcm96", LatestVersion: 1}},
		WrittenPolicies: map[string]string{
			"p": "path \"transit/encrypt/mine\" { capabilities = [\"update\"] }",
		},
	}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.ChangedPolicies) != 0 {
		t.Errorf("ChangedPolicies = %v, want none for a pure reformat", report.ChangedPolicies)
	}
}

// Claims without Transit keep the name-only check.
func TestContentDriftSkippedWithoutTransit(t *testing.T) {
	claim := &vaultv1alpha1.VaultClaim{
		Spec: vaultv1alpha1.VaultClaimSpec{
			Auth:  vaultv1alpha1.AuthSpec{MountPath: "m"},
			Roles: []vaultv1alpha1.RoleSpec{{Name: "r"}},
		},
	}
	fake := &fakeVaultClient{}

	var report DriftReport
	if err := transitReconciler().detectTransitDrift(context.Background(), fake, claim, &report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.ReadRoleCalls != 0 || fake.ReadPolicyCalls != 0 {
		t.Errorf("content drift ran for a claim without transit (roles=%d policies=%d)", fake.ReadRoleCalls, fake.ReadPolicyCalls)
	}
}
