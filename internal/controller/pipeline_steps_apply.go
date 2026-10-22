/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// templateAccessorVar must match the variable name Vault expects when policies
// interpolate the auth-mount accessor.
const templateAccessorVar = ".AuthMountAccessor"

// stepEnableAuthMount (owner claims) makes sure the claim's own mount exists
// and writes its config. Ownership is judged by what sys/auth reports, never by
// status: a mount that exists without this claim's description is refused, and
// neither its config nor its roles are touched.
func (r *VaultClaimReconciler) stepEnableAuthMount(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	mount := normMount(claim.Spec.Auth.MountPath)
	if mount == "" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"MountPathMissing", "spec.auth.mountPath is empty")
		return Wait, nil
	}
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}

	mounts, err := state.Vault.ListAuthMounts(ctx)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"MountLookupFailed", "reading sys/auth failed: "+failureText(err))
		return Proceed, fmt.Errorf("list auth mounts: %w", err)
	}
	info, exists := mounts[mountKey(mount)]
	switch {
	case exists:
		if !mountIsOurs(info, claim) {
			claim.Status.Vault.AuthMountOwned = false
			return r.refuse(claim, state, vaultv1alpha1.ConditionAuthMountReady, ReasonMountConflict,
				fmt.Sprintf("auth mount %q exists and was not created for this claim", mount))
		}
	case claim.Spec.Auth.AutoCreateEnabled():
		if err := state.intent(ctx, claim); err != nil {
			return Proceed, err
		}
		err := state.Vault.EnableAuthMethod(ctx, mount, vault.EnableAuthRequest{
			Type:        "kubernetes",
			Description: mountDescription(claim),
		})
		switch {
		case err == nil:
		case vault.IsBadRequest(err):
			// Created between our read and our POST: judge it by what Vault holds.
			again, lerr := state.Vault.ListAuthMounts(ctx)
			if lerr != nil {
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
					"MountLookupFailed", "reading sys/auth failed: "+failureText(lerr))
				return Proceed, fmt.Errorf("list auth mounts: %w", lerr)
			}
			if info, ok := again[mountKey(mount)]; !ok || !mountIsOurs(info, claim) {
				claim.Status.Vault.AuthMountOwned = false
				return r.refuse(claim, state, vaultv1alpha1.ConditionAuthMountReady, ReasonMountConflict,
					fmt.Sprintf("auth mount %q exists and was not created for this claim", mount))
			}
		default:
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
				"EnableAuthFailed", fmt.Sprintf("enabling auth method %q failed: %s", mount, failureText(err)))
			return Proceed, fmt.Errorf("enable auth method %q: %w", mount, err)
		}
	default:
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"MountMissing", fmt.Sprintf("auth mount %q does not exist and spec.auth.autoCreate is false", mount))
		return Wait, nil
	}
	state.MountOwned = true
	claim.Status.Vault.AuthMountOwned = true

	// Vault replaces the config: writing without the JWT would wipe the reviewer.
	if state.ReviewerJWT == nil || state.ReviewerJWT.Token == "" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"ReviewerJWTMissing", "no reviewer JWT issued in this pass; auth config not written")
		return Proceed, fmt.Errorf("write auth config for %q: no reviewer JWT issued in this pass", mount)
	}

	issuer, disableISS := r.resolveIssuer(ctx, claim, state)

	cfg := vault.KubernetesAuthConfig{
		KubernetesHost:       state.Target.Host,
		KubernetesCACert:     string(state.Target.CABundle),
		TokenReviewerJWT:     state.ReviewerJWT.Token,
		Issuer:               issuer,
		DisableISSValidation: disableISS,
		DisableLocalCAJWT:    true,
	}

	if err := state.Vault.WriteKubernetesAuthConfig(ctx, mount, cfg); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"WriteConfigFailed", fmt.Sprintf("writing auth/%s/config failed: %s", mount, failureText(err)))
		return Proceed, fmt.Errorf("write auth config for %q: %w", mount, err)
	}

	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionTrue, claim.Generation,
		"Configured", fmt.Sprintf("auth method %q enabled and configured", mount))
	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "AuthMountReady",
			"auth/%s configured (token_reviewer_jwt rotated=true)", mount)
	}
	return Proceed, nil
}

// stepVerifyGuestMount (guest claims) waits for the host mount its owner
// configures. It never writes the mount.
func (r *VaultClaimReconciler) stepVerifyGuestMount(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	mount := normMount(claim.Spec.Auth.MountPath)
	mounts, err := state.Vault.ListAuthMounts(ctx)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"MountLookupFailed", "reading sys/auth failed: "+failureText(err))
		return Proceed, fmt.Errorf("list auth mounts: %w", err)
	}
	if info, ok := mounts[mountKey(mount)]; !ok || info.Type != "kubernetes" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			ReasonMountNotConfigured, fmt.Sprintf("auth mount %q does not exist or is not a kubernetes mount", mount))
		return Wait, nil
	}
	cfg, err := state.Vault.ReadKubernetesAuthConfig(ctx, mount)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"ReadConfigFailed", fmt.Sprintf("reading auth/%s/config failed: %s", mount, failureText(err)))
		return Proceed, fmt.Errorf("read auth config for %q: %w", mount, err)
	}
	if cfg.KubernetesHost == "" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			ReasonMountNotConfigured, fmt.Sprintf("auth mount %q has no kubernetes_host configured", mount))
		return Wait, nil
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionTrue, claim.Generation,
		"GuestMount", fmt.Sprintf("auth mount %q is configured by its owner", mount))
	return Proceed, nil
}

// resolveIssuer: explicit spec, then OIDC discovery, then disable ISS validation.
func (r *VaultClaimReconciler) resolveIssuer(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (string, bool) {
	if claim.Spec.Auth.Issuer != "" {
		return claim.Spec.Auth.Issuer, false
	}
	if state.Target != nil {
		if issuer, err := target.DiscoverIssuer(ctx, state.Target); err == nil && issuer != "" {
			return issuer, false
		}
	}
	return "", true
}

func (r *VaultClaimReconciler) guardScope(claim *vaultv1alpha1.VaultClaim, state *pipelineState) policyguard.Scope {
	scope := policyguard.Scope{KVMount: "secret", SecretsPrefix: claim.Spec.SecretsPrefix, TransitMount: transitMountPath(claim)}
	if state.Config != nil && state.Config.Spec.Storage.KvMountPath != "" {
		scope.KVMount = state.Config.Spec.Storage.KvMountPath
	}
	if claim.Spec.Transit != nil {
		for i := range claim.Spec.Transit.Keys {
			scope.TransitKeys = append(scope.TransitKeys, claim.Spec.Transit.Keys[i].Name)
		}
	}
	return scope
}

// stepApplyPolicies renders, judges and writes spec.policies. A name the
// ledger does not hold is written only when Vault has no policy of that name:
// the ledger, not the name, is what makes a policy this claim's.
func (r *VaultClaimReconciler) stepApplyPolicies(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	if len(claim.Spec.Policies) == 0 {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionTrue, claim.Generation,
			"NoPolicies", "spec.policies is empty — nothing to apply")
		return Proceed, nil
	}

	needsAccessor := false
	for i := range claim.Spec.Policies {
		if strings.Contains(claim.Spec.Policies[i].Rules, templateAccessorVar) {
			needsAccessor = true
			break
		}
	}

	var accessor string
	if needsAccessor {
		acc, err := state.Vault.GetAuthMountAccessor(ctx, claim.Spec.Auth.MountPath)
		if err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"AccessorLookupFailed", "reading the auth mount accessor failed: "+failureText(err))
			return Proceed, fmt.Errorf("get auth mount accessor: %w", err)
		}
		accessor = acc
		claim.Status.Vault.AuthMountAccessor = accessor
	}

	ctxData := map[string]string{"AuthMountAccessor": accessor}
	mode := r.guardMode(claim)
	scope := r.guardScope(claim, state)
	rendered := make(map[string]string, len(claim.Spec.Policies))
	names := make([]string, 0, len(claim.Spec.Policies))
	for i := range claim.Spec.Policies {
		p := claim.Spec.Policies[i]
		body, err := renderPolicy(p.Rules, ctxData)
		if err != nil {
			log.FromContext(ctx).V(1).Info("policy does not render", "policy", p.Name, "error", err.Error())
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"RenderFailed", fmt.Sprintf("policy %q: the rules do not render as a template", p.Name))
			return Proceed, fmt.Errorf("render policy %q: %w", p.Name, err)
		}
		if v := policyguard.Check(body, scope); len(v) > 0 {
			for _, x := range v {
				policyGuardViolations.WithLabelValues(string(mode), x.Rule).Inc()
			}
			msg := fmt.Sprintf("policy %q is outside the claim's scope: %s", p.Name, policyguard.Summary(v))
			if mode == policyguard.ModeEnforce {
				return r.refuse(claim, state, vaultv1alpha1.ConditionPoliciesApplied, ReasonPolicyGuardViolation, msg)
			}
			if r.Recorder != nil {
				r.Recorder.Event(claim, corev1.EventTypeWarning, ReasonPolicyGuardViolation, msg+" (audit mode: applied)")
			}
		}
		rendered[p.Name] = body
		names = append(names, p.Name)
	}

	ledger := claim.Status.Vault.AppliedPolicies
	for _, name := range minus(names, ledger) {
		_, err := state.Vault.ReadPolicy(ctx, name)
		switch {
		case err == nil:
			return r.refuse(claim, state, vaultv1alpha1.ConditionPoliciesApplied, ReasonOwnershipConflict,
				fmt.Sprintf("policy %q already exists in Vault and is not in this claim's ledger", name))
		case vault.IsNotFound(err):
		default:
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"ReadPolicyFailed", fmt.Sprintf("policy %q: reading it failed: %s", name, failureText(err)))
			return Proceed, fmt.Errorf("read policy %q: %w", name, err)
		}
	}

	claim.Status.Vault.AppliedPolicies = union(ledger, names)
	if err := state.intent(ctx, claim); err != nil {
		return Proceed, err
	}
	for _, name := range names {
		if err := state.Vault.PutPolicy(ctx, name, rendered[name]); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"PutPolicyFailed", fmt.Sprintf("policy %q: writing it failed: %s", name, failureText(err)))
			return Proceed, fmt.Errorf("put policy %q: %w", name, err)
		}
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionTrue, claim.Generation,
		"Applied", fmt.Sprintf("%d policies applied", len(names)))
	return Proceed, nil
}

func renderPolicy(hcl string, data map[string]string) (string, error) {
	tmpl, err := template.New("policy").Option("missingkey=error").Parse(hcl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func roleBody(role vaultv1alpha1.RoleSpec) vault.KubernetesRole {
	body := vault.KubernetesRole{
		// CRD allows one SA per role; Vault accepts arrays.
		BoundServiceAccountNames:      []string{role.BoundServiceAccounts.Name},
		BoundServiceAccountNamespaces: []string{role.BoundServiceAccounts.Namespace},
		TokenPolicies:                 role.Policies,
	}
	if role.TokenTTL != nil {
		body.TokenTTLSeconds = int(role.TokenTTL.Seconds())
	}
	if role.TokenMaxTTL != nil {
		body.TokenMaxTTLSeconds = int(role.TokenMaxTTL.Seconds())
	}
	body.Audience = role.Audience
	body.TokenType = role.TokenType
	body.TokenNoDefaultPolicy = role.TokenNoDefaultPolicy
	if role.TokenExplicitMaxTTL != nil {
		body.TokenExplicitMaxTTLSecs = int(role.TokenExplicitMaxTTL.Seconds())
	}
	return body
}

// stepApplyRoles writes spec.roles. On a mount this pass proved the claim's
// own, every role there is the claim's to write; on any other mount a role
// the ledger does not hold is written only when it does not exist yet.
func (r *VaultClaimReconciler) stepApplyRoles(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	mount := normMount(claim.Spec.Auth.MountPath)
	names := make([]string, 0, len(claim.Spec.Roles))
	for i := range claim.Spec.Roles {
		names = append(names, claim.Spec.Roles[i].Name)
	}

	ledger := claim.Status.Vault.AppliedRoles
	if !state.MountOwned {
		for _, name := range minus(names, ledger) {
			_, err := state.Vault.ReadKubernetesRole(ctx, mount, name)
			switch {
			case err == nil:
				return r.refuse(claim, state, vaultv1alpha1.ConditionRolesApplied, ReasonOwnershipConflict,
					fmt.Sprintf("role %q already exists on auth mount %q and is not in this claim's ledger", name, mount))
			case vault.IsNotFound(err):
			default:
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
					"ReadRoleFailed", fmt.Sprintf("role %q: reading it failed: %s", name, failureText(err)))
				return Proceed, fmt.Errorf("read role %q: %w", name, err)
			}
		}
	}

	claim.Status.Vault.AppliedRoles = union(ledger, names)
	if err := state.intent(ctx, claim); err != nil {
		return Proceed, err
	}
	for i := range claim.Spec.Roles {
		role := claim.Spec.Roles[i]
		if err := state.Vault.PutKubernetesRole(ctx, mount, role.Name, roleBody(role)); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
				"PutRoleFailed", fmt.Sprintf("role %q: writing it failed: %s", role.Name, failureText(err)))
			return Proceed, fmt.Errorf("put role %q: %w", role.Name, err)
		}
	}
	return Proceed, nil
}

// stepPruneRemoved deletes what left spec, roles before the policies they may
// reference. Candidates are ledger names — and, under Exclusive on a mount
// this pass proved the claim's own, every role on it. Names the deployment
// reserves and names another claim holds are dropped from the ledger without
// a Vault call.
func (r *VaultClaimReconciler) stepPruneRemoved(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	mount := normMount(claim.Spec.Auth.MountPath)
	others, err := r.everyOtherClaim(ctx, claim)
	if err != nil {
		return Proceed, err
	}
	held := collectHeld(others)
	view := state.View
	if view == nil {
		if view, err = r.buildOwnershipView(ctx, claim); err != nil {
			return Proceed, err
		}
	}

	specRoles := make([]string, 0, len(claim.Spec.Roles))
	for i := range claim.Spec.Roles {
		specRoles = append(specRoles, claim.Spec.Roles[i].Name)
	}
	specPolicies := make([]string, 0, len(claim.Spec.Policies))
	for i := range claim.Spec.Policies {
		specPolicies = append(specPolicies, claim.Spec.Policies[i].Name)
	}

	roleCandidates := minus(claim.Status.Vault.AppliedRoles, specRoles)
	if state.MountOwned && claim.Spec.Auth.RolePruningMode() == vaultv1alpha1.RolePruningExclusive {
		existing, err := state.Vault.ListKubernetesRoles(ctx, mount)
		if err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
				"ListRolesFailed", fmt.Sprintf("listing roles on auth mount %q failed: %s", mount, failureText(err)))
			return Proceed, fmt.Errorf("list roles: %w", err)
		}
		roleCandidates = union(minus(existing, specRoles), roleCandidates)
	}
	purgedRoles := 0
	for _, name := range deletableRoles(view, mount, roleCandidates, held) {
		if err := state.Vault.DeleteKubernetesRole(ctx, mount, name); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
				"PurgeFailed", fmt.Sprintf("role %q: deleting it failed: %s", name, failureText(err)))
			return Proceed, fmt.Errorf("delete removed role %q: %w", name, err)
		}
		purgedRoles++
	}
	claim.Status.Vault.AppliedRoles = union(specRoles, nil)

	purgedPolicies := 0
	for _, name := range r.deletablePolicies(minus(claim.Status.Vault.AppliedPolicies, specPolicies), held) {
		if err := state.Vault.DeletePolicy(ctx, name); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"PurgeFailed", fmt.Sprintf("policy %q: deleting it failed: %s", name, failureText(err)))
			return Proceed, fmt.Errorf("delete removed policy %q: %w", name, err)
		}
		purgedPolicies++
	}
	if len(specPolicies) == 0 {
		claim.Status.Vault.AppliedPolicies = nil
	} else {
		claim.Status.Vault.AppliedPolicies = union(specPolicies, nil)
	}

	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionTrue, claim.Generation,
		"Applied", fmt.Sprintf("%d roles applied, %d purged", len(specRoles), purgedRoles))
	if r.Recorder != nil && purgedRoles > 0 {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "RolesPurged",
			"removed %d roles in auth/%s no longer present in spec.roles[]", purgedRoles, mount)
	}
	if r.Recorder != nil && purgedPolicies > 0 {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "PoliciesPurged",
			"removed %d policies no longer present in spec.policies[]", purgedPolicies)
	}
	return Proceed, nil
}
