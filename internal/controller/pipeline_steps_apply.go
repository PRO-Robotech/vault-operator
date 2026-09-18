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
	"sort"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// templateAccessorVar must match the variable name Vault expects when policies
// interpolate the auth-mount accessor.
const templateAccessorVar = ".AuthMountAccessor"

func (r *VaultClaimReconciler) stepEnableAuthMount(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	mount := claim.Spec.Auth.MountPath
	if mount == "" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"MountPathMissing", "spec.auth.mountPath is empty")
		return Wait, nil
	}

	if claim.Spec.Auth.AutoCreate {
		if err := state.Vault.EnableAuthMethod(ctx, mount, vault.EnableAuthRequest{
			Type:        "kubernetes",
			Description: fmt.Sprintf("vault-operator: per-cluster auth for %s/%s", claim.Namespace, claim.Name),
		}); err != nil {
			// 400 means the mount already exists — treat as success.
			if !vault.IsBadRequest(err) {
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
					"EnableAuthFailed", err.Error())
				return Proceed, fmt.Errorf("enable auth method %q: %w", mount, err)
			}
		}
	}

	issuer, disableISS := r.resolveIssuer(ctx, claim, state)

	cfg := vault.KubernetesAuthConfig{
		KubernetesHost:       state.Target.Host,
		KubernetesCACert:     string(state.Target.CABundle),
		Issuer:               issuer,
		DisableISSValidation: disableISS,
		DisableLocalCAJWT:    true,
	}
	// Only overwrite token_reviewer_jwt when a fresh one was minted this
	// cycle — otherwise the previous JWT (still within TTL) is preserved.
	if state.ReviewerJWT != nil {
		cfg.TokenReviewerJWT = state.ReviewerJWT.Token
	}

	if err := state.Vault.WriteKubernetesAuthConfig(ctx, mount, cfg); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionFalse, claim.Generation,
			"WriteConfigFailed", err.Error())
		return Proceed, fmt.Errorf("write auth config for %q: %w", mount, err)
	}

	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady, metav1.ConditionTrue, claim.Generation,
		"Configured", fmt.Sprintf("auth method %q enabled and configured", mount))
	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "AuthMountReady",
			"auth/%s configured (token_reviewer_jwt rotated=%t)", mount, state.ReviewerJWT != nil)
	}
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

func (r *VaultClaimReconciler) stepApplyPolicies(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if len(claim.Spec.Policies) == 0 {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionTrue, claim.Generation,
			"NoPolicies", "spec.policies is empty — nothing to apply")
		if claim.Status.Vault != nil {
			claim.Status.Vault.AppliedPolicies = nil
		}
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
				"AccessorLookupFailed", err.Error())
			return Proceed, fmt.Errorf("get auth mount accessor: %w", err)
		}
		accessor = acc
		if claim.Status.Vault == nil {
			claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
		}
		claim.Status.Vault.AuthMountAccessor = accessor
	}

	ctxData := map[string]string{"AuthMountAccessor": accessor}
	applied := make([]string, 0, len(claim.Spec.Policies))
	for i := range claim.Spec.Policies {
		p := claim.Spec.Policies[i]
		rendered, err := renderPolicy(p.Rules, ctxData)
		if err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"RenderFailed", fmt.Sprintf("policy %q: %v", p.Name, err))
			return Proceed, fmt.Errorf("render policy %q: %w", p.Name, err)
		}
		if err := state.Vault.PutPolicy(ctx, p.Name, rendered); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionFalse, claim.Generation,
				"PutPolicyFailed", fmt.Sprintf("policy %q: %v", p.Name, err))
			return Proceed, fmt.Errorf("put policy %q: %w", p.Name, err)
		}
		applied = append(applied, p.Name)
	}

	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	sort.Strings(applied)
	claim.Status.Vault.AppliedPolicies = applied
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied, metav1.ConditionTrue, claim.Generation,
		"Applied", fmt.Sprintf("%d policies applied", len(applied)))
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

func (r *VaultClaimReconciler) stepApplyRoles(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	mount := claim.Spec.Auth.MountPath
	desired := make(map[string]struct{}, len(claim.Spec.Roles))
	applied := make([]string, 0, len(claim.Spec.Roles))

	for i := range claim.Spec.Roles {
		role := claim.Spec.Roles[i]
		desired[role.Name] = struct{}{}
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
		if err := state.Vault.PutKubernetesRole(ctx, mount, role.Name, body); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
				"PutRoleFailed", fmt.Sprintf("role %q: %v", role.Name, err))
			return Proceed, fmt.Errorf("put role %q: %w", role.Name, err)
		}
		applied = append(applied, role.Name)
	}

	existing, err := state.Vault.ListKubernetesRoles(ctx, mount)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
			"ListRolesFailed", err.Error())
		return Proceed, fmt.Errorf("list roles: %w", err)
	}
	purged := 0
	for _, name := range existing {
		if _, ok := desired[name]; ok {
			continue
		}
		if err := state.Vault.DeleteKubernetesRole(ctx, mount, name); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionFalse, claim.Generation,
				"PurgeFailed", fmt.Sprintf("delete role %q: %v", name, err))
			return Proceed, fmt.Errorf("delete extra role %q: %w", name, err)
		}
		purged++
	}

	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	sort.Strings(applied)
	claim.Status.Vault.AppliedRoles = applied
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionRolesApplied, metav1.ConditionTrue, claim.Generation,
		"Applied", fmt.Sprintf("%d roles applied, %d purged", len(applied), purged))
	if r.Recorder != nil && purged > 0 {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "RolesPurged",
			"removed %d roles in auth/%s no longer present in spec.roles[]", purged, mount)
	}
	return Proceed, nil
}
