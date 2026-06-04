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
	"errors"
	"net/http"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

func driftFixtureClaim() *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			Auth: vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"},
			Policies: []vaultv1alpha1.PolicySpec{
				{Name: "ec8a00-vmauth-reader", Rules: "path \"*\" { capabilities = [\"read\"] }"},
				{Name: "ec8a00-argocd-reader", Rules: "path \"*\" { capabilities = [\"read\"] }"},
			},
			Roles: []vaultv1alpha1.RoleSpec{
				{Name: "vmauth-reader"},
				{Name: "argocd-reader"},
			},
		},
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	fake := &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{
			"kubernetes-ec8a00/": {Type: "kubernetes", Accessor: "acc1"},
			// some unrelated mounts to prove we ignore them
			"kubernetes-other/": {Type: "kubernetes"},
		},
		ListPoliciesResp: []string{
			"ec8a00-vmauth-reader",
			"ec8a00-argocd-reader",
			"unrelated-policy", // a user-managed policy we don't own
		},
		ListRolesResp: []string{"vmauth-reader", "argocd-reader"},
	}
	r := &VaultClaimReconciler{}
	report, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if report.Found() {
		t.Errorf("expected no drift, got %+v", report)
	}
}

func TestDetectDrift_AuthMountMissing(t *testing.T) {
	fake := &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{
			"kubernetes-other/": {Type: "kubernetes"},
		},
		ListPoliciesResp: []string{"ec8a00-vmauth-reader", "ec8a00-argocd-reader"},
		ListRolesResp:    []string{"vmauth-reader", "argocd-reader"},
	}
	r := &VaultClaimReconciler{}
	report, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if !report.Found() || !report.MountMissing {
		t.Errorf("expected MountMissing drift, got %+v", report)
	}
}

func TestDetectDrift_PolicyMissing(t *testing.T) {
	fake := &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{"kubernetes-ec8a00/": {Type: "kubernetes"}},
		ListPoliciesResp: []string{
			"ec8a00-vmauth-reader",
			// "ec8a00-argocd-reader" missing
		},
		ListRolesResp: []string{"vmauth-reader", "argocd-reader"},
	}
	r := &VaultClaimReconciler{}
	report, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if len(report.MissingPolicies) != 1 || report.MissingPolicies[0] != "ec8a00-argocd-reader" {
		t.Errorf("expected one MissingPolicies entry, got %+v", report.MissingPolicies)
	}
}

func TestDetectDrift_RoleExtra(t *testing.T) {
	fake := &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{"kubernetes-ec8a00/": {Type: "kubernetes"}},
		ListPoliciesResp:   []string{"ec8a00-vmauth-reader", "ec8a00-argocd-reader"},
		ListRolesResp:      []string{"vmauth-reader", "argocd-reader", "rogue-role"},
	}
	r := &VaultClaimReconciler{}
	report, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if len(report.ExtraRoles) != 1 || report.ExtraRoles[0] != "rogue-role" {
		t.Errorf("expected one ExtraRoles entry, got %+v", report.ExtraRoles)
	}
}

func TestDetectDrift_RoleMissing(t *testing.T) {
	fake := &fakeVaultClient{
		ListAuthMountsResp: map[string]vault.AuthMountInfo{"kubernetes-ec8a00/": {Type: "kubernetes"}},
		ListPoliciesResp:   []string{"ec8a00-vmauth-reader", "ec8a00-argocd-reader"},
		ListRolesResp:      []string{"vmauth-reader"}, // argocd-reader missing
	}
	r := &VaultClaimReconciler{}
	report, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err != nil {
		t.Fatalf("detectDrift: %v", err)
	}
	if len(report.MissingRoles) != 1 || report.MissingRoles[0] != "argocd-reader" {
		t.Errorf("expected one MissingRoles entry, got %+v", report.MissingRoles)
	}
}

func TestDetectDrift_PropagatesListError(t *testing.T) {
	fake := &fakeVaultClient{ListAuthMountsErr: errors.New("network down")}
	r := &VaultClaimReconciler{}
	_, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err == nil {
		t.Fatal("expected propagated list error")
	}
}

func TestDetectDrift_ForbiddenIsAnError(t *testing.T) {
	// A 403 on sys/auth bubbles up to the caller as an error — the caller
	// (executePipeline) then falls through to the full pipeline rather than
	// claiming "no drift".
	fake := &fakeVaultClient{ListAuthMountsErr: &vault.APIError{Method: http.MethodGet, Path: "/v1/sys/auth", StatusCode: http.StatusForbidden}}
	r := &VaultClaimReconciler{}
	_, err := r.detectDrift(context.Background(), fake, driftFixtureClaim())
	if err == nil {
		t.Fatal("expected error from forbidden list")
	}
}

func TestDriftReport_Summary(t *testing.T) {
	r := DriftReport{
		MountMissing:    true,
		MissingPolicies: []string{"p1"},
		MissingRoles:    []string{"r1", "r2"},
		ExtraRoles:      []string{"r3"},
	}
	got := r.Summary()
	want := "auth mount missing; 1 policies missing; 2 roles missing; 1 extra roles"
	if got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}

	if (DriftReport{}).Summary() != "" {
		t.Error("empty report should have empty summary")
	}
}
