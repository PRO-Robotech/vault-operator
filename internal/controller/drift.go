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
	// ReviewerJWTUnset: auth/{mount}/config has no token_reviewer_jwt.
	ReviewerJWTUnset bool
}

func (d DriftReport) Found() bool {
	return d.MountMissing || len(d.MissingPolicies) > 0 || len(d.MissingRoles) > 0 || len(d.ExtraRoles) > 0 ||
		d.TransitMissing || len(d.MissingKeys) > 0 || len(d.KeyVersionMoved) > 0 ||
		len(d.ChangedRoles) > 0 || len(d.ChangedPolicies) > 0 || d.ReviewerJWTUnset
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
	if d.ReviewerJWTUnset {
		parts = append(parts, "token_reviewer_jwt not set")
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

// liveObjects holds the bodies the drift check already read, so the content
// comparison does not read them a second time.
type liveObjects struct {
	policies map[string]string
	roles    map[string]*vault.KubernetesRole
}

// detectDrift is read-only: errors propagate so the caller can fall through
// to the full pipeline (safer than silently leaving drift). It reads the
// claim's own objects one by one — its mount, its policies, its roles — so
// its cost follows the claim, not the size of Vault. The drift metric is
// incremented once per category, not once per object, to keep cardinality
// bounded.
func (r *VaultClaimReconciler) detectDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim) (DriftReport, error) {
	var report DriftReport
	mount := claim.Spec.Auth.MountPath
	live := liveObjects{policies: map[string]string{}, roles: map[string]*vault.KubernetesRole{}}

	// Mount missing → reading its config is meaningless.
	info, mountExists, err := vc.ReadAuthMount(ctx, mount)
	if err != nil {
		return report, fmt.Errorf("read auth mount: %w", err)
	}
	if !mountExists {
		report.MountMissing = true
		driftDetectedCounter.WithLabelValues(DriftTypeMount).Inc()
	} else if claim.Spec.Auth.ManagesConfig() {
		// Running clients only renew, so a wiped reviewer shows up on the next
		// login. A guest does not own the mount config and does not judge it.
		cfg, err := vc.ReadKubernetesAuthConfig(ctx, mount)
		if err != nil {
			return report, fmt.Errorf("read auth config: %w", err)
		}
		if !cfg.TokenReviewerJWTSet {
			report.ReviewerJWTUnset = true
			driftDetectedCounter.WithLabelValues(DriftTypeAuthConfig).Inc()
		}
	}

	// Only policies we own are read — user-managed policies are not our drift.
	for i := range claim.Spec.Policies {
		name := claim.Spec.Policies[i].Name
		body, err := vc.ReadPolicy(ctx, name)
		switch {
		case err == nil:
			live.policies[name] = body
		case vault.IsNotFound(err):
			report.MissingPolicies = append(report.MissingPolicies, name)
		default:
			return report, fmt.Errorf("read policy %q: %w", name, err)
		}
	}
	if len(report.MissingPolicies) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypePolicy).Inc()
	}

	var recorded string
	if claim.Status.Vault != nil {
		recorded = claim.Status.Vault.AuthMountPath
	}
	owned := mountExists && mountAccepted(info, claim, recorded)
	if err := r.detectRoleDrift(ctx, vc, claim, owned, &report, live); err != nil {
		return report, err
	}

	if err := r.detectTransitDrift(ctx, vc, claim, &report, live); err != nil {
		return report, err
	}

	return report, nil
}

// detectRoleDrift reports missing roles and extra ones. Exclusive judges
// every role on a mount the claim owns, so it lists the mount; otherwise
// only the claim's roles are read, and only a role the ledger says the claim
// wrote can be extra.
func (r *VaultClaimReconciler) detectRoleDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim,
	owned bool, report *DriftReport, live liveObjects) error {
	mount := claim.Spec.Auth.MountPath
	desired := make(map[string]string, len(claim.Spec.Roles))
	names := make([]string, 0, len(claim.Spec.Roles))
	for i := range claim.Spec.Roles {
		desired[nameKey(claim.Spec.Roles[i].Name)] = claim.Spec.Roles[i].Name
		names = append(names, claim.Spec.Roles[i].Name)
	}
	exclusive := owned && claim.Spec.Auth.ManagesConfig() && claim.Spec.Auth.RolePruningMode() == vaultv1alpha1.RolePruningExclusive
	var ledger []string
	if claim.Status.Vault != nil {
		ledger = claim.Status.Vault.AppliedRoles
	}
	keep, err := r.pruneFilter(ctx, claim)
	if err != nil {
		return err
	}

	if exclusive {
		existingRoles, err := vc.ListKubernetesRoles(ctx, mount)
		if err != nil {
			return fmt.Errorf("list roles: %w", err)
		}
		present := make(map[string]struct{}, len(existingRoles))
		for _, name := range existingRoles {
			present[nameKey(name)] = struct{}{}
			if _, ok := desired[nameKey(name)]; !ok && !keep(name) {
				report.ExtraRoles = append(report.ExtraRoles, name)
			}
		}
		for _, name := range names {
			if _, ok := present[nameKey(name)]; !ok {
				report.MissingRoles = append(report.MissingRoles, name)
			}
		}
	} else {
		for _, name := range names {
			role, err := vc.ReadKubernetesRole(ctx, mount, name)
			switch {
			case err == nil:
				live.roles[name] = role
			case vault.IsNotFound(err):
				report.MissingRoles = append(report.MissingRoles, name)
			default:
				return fmt.Errorf("read role %q: %w", name, err)
			}
		}
		for _, name := range minus(ledger, names) {
			if keep(name) {
				continue
			}
			_, err := vc.ReadKubernetesRole(ctx, mount, name)
			switch {
			case err == nil:
				report.ExtraRoles = append(report.ExtraRoles, name)
			case vault.IsNotFound(err):
			default:
				return fmt.Errorf("read role %q: %w", name, err)
			}
		}
	}
	if len(report.MissingRoles) > 0 || len(report.ExtraRoles) > 0 {
		driftDetectedCounter.WithLabelValues(DriftTypeRole).Inc()
	}

	return nil
}

// pruneFilter reports roles pruning would leave alone (reserved, or held by
// another claim), so drift does not report what the full pass will not fix.
// Without a client (drift unit tests) nothing is kept.
func (r *VaultClaimReconciler) pruneFilter(ctx context.Context, claim *vaultv1alpha1.VaultClaim) (func(string) bool, error) {
	if r.Client == nil {
		return func(string) bool { return false }, nil
	}
	view, err := r.buildOwnershipView(ctx, claim)
	if err != nil {
		return nil, err
	}
	others, err := r.everyOtherClaim(ctx, claim)
	if err != nil {
		return nil, err
	}
	held := collectHeld(others)
	mount := normMount(claim.Spec.Auth.MountPath)
	return func(name string) bool {
		return len(deletableRoles(view, mount, []string{name}, held)) == 0
	}, nil
}

// detectTransitDrift reports keys that vanished or changed version.
func (r *VaultClaimReconciler) detectTransitDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim,
	report *DriftReport, live liveObjects) error {
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
	return r.detectContentDrift(ctx, vc, claim, report, live)
}

// detectContentDrift compares live role and policy bodies against spec.
// Scoped to claims declaring Transit keys; elsewhere the name check stands.
// Bodies the presence check already read are not read again.
func (r *VaultClaimReconciler) detectContentDrift(ctx context.Context, vc VaultClient, claim *vaultv1alpha1.VaultClaim,
	report *DriftReport, live liveObjects) error {
	mount := claim.Spec.Auth.MountPath

	for i := range claim.Spec.Roles {
		want := claim.Spec.Roles[i]
		role, ok := live.roles[want.Name]
		if !ok {
			got, err := vc.ReadKubernetesRole(ctx, mount, want.Name)
			if err != nil {
				if vault.IsNotFound(err) {
					continue
				}
				return fmt.Errorf("read role %q: %w", want.Name, err)
			}
			role = got
		}
		if diff := roleBodyDiff(want, role); diff != "" {
			report.ChangedRoles = append(report.ChangedRoles, fmt.Sprintf("%s (%s)", want.Name, diff))
		}
	}

	for i := range claim.Spec.Policies {
		want := claim.Spec.Policies[i]
		body, ok := live.policies[want.Name]
		if !ok {
			got, err := vc.ReadPolicy(ctx, want.Name)
			if err != nil {
				if vault.IsNotFound(err) {
					continue
				}
				return fmt.Errorf("read policy %q: %w", want.Name, err)
			}
			body = got
		}
		// Templated bodies are resolved at apply time and cannot be compared here.
		if strings.Contains(want.Rules, templateAccessorVar) {
			continue
		}
		if normalizeHCL(body) != normalizeHCL(want.Rules) {
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
