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
	"strings"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// DriftReport summarises divergences between claim.Spec and live Vault state.
type DriftReport struct {
	MountMissing    bool
	MissingPolicies []string
	MissingRoles    []string
	ExtraRoles      []string
	TransitMissing  bool
	MissingKeys     []string
	KeyVersionMoved []string
	ChangedRoles    []string
	ChangedPolicies []string
}

func (d DriftReport) Found() bool {
	return d.MountMissing || len(d.MissingPolicies) > 0 || len(d.MissingRoles) > 0 || len(d.ExtraRoles) > 0 ||
		d.TransitMissing || len(d.MissingKeys) > 0 || len(d.KeyVersionMoved) > 0 ||
		len(d.ChangedRoles) > 0 || len(d.ChangedPolicies) > 0
}

func (d DriftReport) Summary() string {
	if !d.Found() {
		return ""
	}
	parts := make([]string, 0, 4)
	if d.MountMissing {
		parts = append(parts, "auth mount missing")
	}
	if n := len(d.MissingPolicies); n > 0 {
		parts = append(parts, fmt.Sprintf("%d policies missing", n))
	}
	if n := len(d.MissingRoles); n > 0 {
		parts = append(parts, fmt.Sprintf("%d roles missing", n))
	}
	if n := len(d.ExtraRoles); n > 0 {
		parts = append(parts, fmt.Sprintf("%d extra roles", n))
	}
	if d.TransitMissing {
		parts = append(parts, "transit mount missing")
	}
	if n := len(d.MissingKeys); n > 0 {
		parts = append(parts, fmt.Sprintf("%d transit keys missing", n))
	}
	if n := len(d.KeyVersionMoved); n > 0 {
		parts = append(parts, fmt.Sprintf("%d transit keys changed version", n))
	}
	if n := len(d.ChangedRoles); n > 0 {
		parts = append(parts, fmt.Sprintf("%d roles altered: %s", n, strings.Join(d.ChangedRoles, "; ")))
	}
	if n := len(d.ChangedPolicies); n > 0 {
		parts = append(parts, fmt.Sprintf("%d policy bodies altered: %s", n, strings.Join(d.ChangedPolicies, ", ")))
	}
	return strings.Join(parts, "; ")
}

// detectDrift is read-only: errors propagate so the caller can fall through
// to the full pipeline (safer than silently leaving drift). The drift metric
// is incremented once per category, not once per object, to keep cardinality
// bounded.
func (r *VaultClaimReconciler) detectDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim) (DriftReport, error) {
	var report DriftReport
	mount := claim.Spec.Auth.MountPath

	// Mount missing → listing policies/roles under it is meaningless.
	mounts, err := vc.ListAuthMounts(ctx)
	if err != nil {
		return report, fmt.Errorf("list auth mounts: %w", err)
	}
	key := strings.TrimSuffix(strings.Trim(mount, "/"), "/") + "/"
	if _, ok := mounts[key]; !ok {
		report.MountMissing = true
		driftDetectedCounter.WithLabelValues(DriftTypeMount).Inc()
	}

	// Only check policies we own — user-managed policies are not our drift.
	if len(claim.Spec.Policies) > 0 {
		existing, err := vc.ListPolicies(ctx)
		if err != nil {
			return report, fmt.Errorf("list policies: %w", err)
		}
		present := make(map[string]struct{}, len(existing))
		for _, name := range existing {
			present[name] = struct{}{}
		}
		for i := range claim.Spec.Policies {
			name := claim.Spec.Policies[i].Name
			if _, ok := present[name]; !ok {
				report.MissingPolicies = append(report.MissingPolicies, name)
			}
		}
		if len(report.MissingPolicies) > 0 {
			driftDetectedCounter.WithLabelValues(DriftTypePolicy).Inc()
		}
	}

	existingRoles, err := vc.ListKubernetesRoles(ctx, mount)
	if err != nil {
		return report, fmt.Errorf("list roles: %w", err)
	}
	desired := make(map[string]struct{}, len(claim.Spec.Roles))
	for i := range claim.Spec.Roles {
		desired[claim.Spec.Roles[i].Name] = struct{}{}
	}
	present := make(map[string]struct{}, len(existingRoles))
	for _, name := range existingRoles {
		present[name] = struct{}{}
		if _, ok := desired[name]; !ok {
			report.ExtraRoles = append(report.ExtraRoles, name)
		}
	}
	for name := range desired {
		if _, ok := present[name]; !ok {
			report.MissingRoles = append(report.MissingRoles, name)
		}
	}
	if len(report.MissingRoles) > 0 || len(report.ExtraRoles) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypeRole).Inc()
	}

	if err := r.detectTransitDrift(ctx, vc, claim, &report); err != nil {
		return report, err
	}

	return report, nil
}

// detectTransitDrift reports keys that vanished or changed version.
func (r *VaultClaimReconciler) detectTransitDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim, report *DriftReport) error {
	if claim.Spec.Transit == nil || len(claim.Spec.Transit.Keys) == 0 {
		return nil
	}
	mount := transitMountPath(claim)

	exists, err := vc.MountExists(ctx, mount, "transit")
	if err != nil {
		return fmt.Errorf("check transit mount: %w", err)
	}
	if !exists {
		report.TransitMissing = true
		driftDetectedCounter.WithLabelValues(DriftTypeTransitKey).Inc()
		return nil
	}

	for i := range claim.Spec.Transit.Keys {
		name := claim.Spec.Transit.Keys[i].Name
		live, err := vc.ReadTransitKey(ctx, mount, name)
		if err != nil {
			if vault.IsNotFound(err) {
				report.MissingKeys = append(report.MissingKeys, name)
				continue
			}
			return fmt.Errorf("read transit key %q: %w", name, err)
		}
		if prior := transitKeyStatus(claim, name); prior != nil && prior.LatestVersion != 0 &&
			prior.LatestVersion != live.LatestVersion {
			report.KeyVersionMoved = append(report.KeyVersionMoved, name)
		}
	}
	if len(report.MissingKeys) > 0 || len(report.KeyVersionMoved) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypeTransitKey).Inc()
	}
	return r.detectContentDrift(ctx, vc, claim, report)
}

// detectContentDrift compares live role and policy bodies against spec.
// Scoped to claims declaring Transit keys; elsewhere the name check stands.
func (r *VaultClaimReconciler) detectContentDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim, report *DriftReport) error {
	mount := claim.Spec.Auth.MountPath

	for i := range claim.Spec.Roles {
		want := claim.Spec.Roles[i]
		live, err := vc.ReadKubernetesRole(ctx, mount, want.Name)
		if err != nil {
			if vault.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("read role %q: %w", want.Name, err)
		}
		if diff := roleBodyDiff(want, live); diff != "" {
			report.ChangedRoles = append(report.ChangedRoles, fmt.Sprintf("%s (%s)", want.Name, diff))
		}
	}

	for i := range claim.Spec.Policies {
		want := claim.Spec.Policies[i]
		live, err := vc.ReadPolicy(ctx, want.Name)
		if err != nil {
			if vault.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("read policy %q: %w", want.Name, err)
		}
		// Templated bodies are resolved at apply time and cannot be compared here.
		if strings.Contains(want.Rules, templateAccessorVar) {
			continue
		}
		if normalizeHCL(live) != normalizeHCL(want.Rules) {
			report.ChangedPolicies = append(report.ChangedPolicies, want.Name)
		}
	}

	if len(report.ChangedRoles) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypeRoleBody).Inc()
	}
	if len(report.ChangedPolicies) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypePolicyBody).Inc()
	}
	return nil
}

// roleBodyDiff names the fields that stopped matching.
func roleBodyDiff(want vaultv1alpha1.RoleSpec, live *vault.KubernetesRole) string {
	var parts []string
	if live.Audience != want.Audience {
		parts = append(parts, fmt.Sprintf("audience %q != %q", live.Audience, want.Audience))
	}
	if live.TokenNoDefaultPolicy != want.TokenNoDefaultPolicy {
		parts = append(parts, fmt.Sprintf("token_no_default_policy %t != %t", live.TokenNoDefaultPolicy, want.TokenNoDefaultPolicy))
	}
	if want.TokenType != "" && live.TokenType != want.TokenType {
		parts = append(parts, fmt.Sprintf("token_type %q != %q", live.TokenType, want.TokenType))
	}
	if !equalStrings(live.TokenPolicies, want.Policies) {
		parts = append(parts, fmt.Sprintf("token_policies %v != %v", live.TokenPolicies, want.Policies))
	}
	if !equalStrings(live.BoundServiceAccountNames, []string{want.BoundServiceAccounts.Name}) {
		parts = append(parts, fmt.Sprintf("bound SA names %v != [%s]", live.BoundServiceAccountNames, want.BoundServiceAccounts.Name))
	}
	if !equalStrings(live.BoundServiceAccountNamespaces, []string{want.BoundServiceAccounts.Namespace}) {
		parts = append(parts, fmt.Sprintf("bound SA namespaces %v != [%s]", live.BoundServiceAccountNamespaces, want.BoundServiceAccounts.Namespace))
	}
	if want.TokenExplicitMaxTTL != nil && live.TokenExplicitMaxTTLSecs != int(want.TokenExplicitMaxTTL.Seconds()) {
		parts = append(parts, fmt.Sprintf("token_explicit_max_ttl %ds != %ds", live.TokenExplicitMaxTTLSecs, int(want.TokenExplicitMaxTTL.Seconds())))
	}
	return strings.Join(parts, ", ")
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

// normalizeHCL collapses formatting so a reindent is not reported as drift.
func normalizeHCL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
