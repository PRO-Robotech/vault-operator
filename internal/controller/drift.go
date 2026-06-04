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
)

// DriftReport summarises divergences between claim.Spec and live Vault state.
type DriftReport struct {
	MountMissing    bool
	MissingPolicies []string
	MissingRoles    []string
	ExtraRoles      []string
}

func (d DriftReport) Found() bool {
	return d.MountMissing || len(d.MissingPolicies) > 0 || len(d.MissingRoles) > 0 || len(d.ExtraRoles) > 0
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

	return report, nil
}
