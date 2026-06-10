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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// stepResolveConfigAndLogin (Step 1, OPERATOR-SPEC §4.1): resolves VaultConfig,
// verifies it is Reachable + SharedMountFound, and refreshes the cached token.
func (r *VaultClaimReconciler) stepResolveConfigAndLogin(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	configName := claim.Spec.VaultConfigRef.Name
	if configName == "" {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"ConfigRefMissing", "spec.vaultConfigRef.name is empty")
		return Wait, nil
	}

	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: configName}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
				"NotFound", fmt.Sprintf("VaultConfig %q not found", configName))
			return Wait, nil
		}
		return Proceed, fmt.Errorf("get VaultConfig %q: %w", configName, err)
	}
	state.Config = cfg

	if !isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionReachable) {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"VaultUnreachable", fmt.Sprintf("VaultConfig %q is not Reachable", configName))
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"VaultUnreachable", "skipped: VaultConfig reports Reachable=False")
		return Wait, nil
	}
	if !isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound) {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"SharedMountMissing", fmt.Sprintf("VaultConfig %q reports SharedMountFound=False", configName))
		return Wait, nil
	}

	if r.VaultFactory == nil {
		return Proceed, fmt.Errorf("VaultFactory is not configured")
	}
	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"FactoryError", err.Error())
		return Proceed, fmt.Errorf("build vault client: %w", err)
	}
	state.Vault = vc

	if err := vc.Login(ctx); err != nil {
		reason := "LoginFailed"
		if vault.IsCircuitOpen(err) {
			reason = ReasonCircuitOpen
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			reason, err.Error())
		return Proceed, fmt.Errorf("vault login: %w", err)
	}

	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionTrue, claim.Generation,
		"Resolved", fmt.Sprintf("VaultConfig %q is Reachable and SharedMountFound", configName))
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionTrue, claim.Generation,
		"LoggedIn", "Vault login succeeded")

	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	claim.Status.Vault.ConfigName = cfg.Name
	claim.Status.Vault.AuthMountPath = claim.Spec.Auth.MountPath
	claim.Status.Vault.SecretsPrefix = claim.Spec.SecretsPrefix
	return Proceed, nil
}

func (r *VaultClaimReconciler) stepWaitKubeconfig(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	name := kubeconfigSecretName(claim)
	secret := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: claim.Namespace, Name: name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable, metav1.ConditionFalse, claim.Generation,
				"NotFound", fmt.Sprintf("Secret %s/%s not found", claim.Namespace, name))
			return Wait, nil
		}
		return Proceed, fmt.Errorf("get kubeconfig Secret %s/%s: %w", claim.Namespace, name, err)
	}
	if len(secret.Data[target.KubeconfigKey]) == 0 {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable, metav1.ConditionFalse, claim.Generation,
			"InvalidSecret", fmt.Sprintf("Secret %s/%s missing %q entry", claim.Namespace, name, target.KubeconfigKey))
		return Wait, nil
	}
	state.Kubeconfig = secret
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable, metav1.ConditionTrue, claim.Generation,
		"Available", fmt.Sprintf("Secret %s/%s is present", claim.Namespace, name))
	return Proceed, nil
}

func (r *VaultClaimReconciler) stepEnsureTargetSA(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if r.TargetManager == nil {
		return Proceed, fmt.Errorf("TargetManager is not configured")
	}
	cs, err := r.TargetManager.Get(ctx, state.Kubeconfig)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh, metav1.ConditionFalse, claim.Generation,
			"TargetClientError", err.Error())
		return Proceed, fmt.Errorf("build target client: %w", err)
	}
	state.Target = cs

	if claim.Spec.Auth.TokenReviewer.ServiceAccount.AutoCreate {
		if err := target.EnsureTokenReviewerSA(ctx, cs, claim); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh, metav1.ConditionFalse, claim.Generation,
				"TargetSAFailed", err.Error())
			return Proceed, fmt.Errorf("ensure target SA: %w", err)
		}
	}
	return Proceed, nil
}

// stepIssueReviewerJWT (Step 4): rotates the reviewer JWT only when past the
// 30%-of-TTL threshold (D9). JWT bytes are never persisted to status — only
// timestamps (OPERATOR-SPEC §9.3).
func (r *VaultClaimReconciler) stepIssueReviewerJWT(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	now := r.now()

	claim.Status.Vault.TokenReviewerJWT = ensureJWTStatus(claim.Status.Vault.TokenReviewerJWT)
	claim.Status.Vault.TokenReviewerJWT.LastRotationAttempt = ptrTime(now)

	if !target.ShouldRotateReviewerJWT(claim.Status.Vault.TokenReviewerJWT, now) {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh, metav1.ConditionTrue, claim.Generation,
			"NoRotationNeeded",
			fmt.Sprintf("Reviewer JWT expires at %s (> 30%% TTL remaining)", claim.Status.Vault.TokenReviewerJWT.ExpiresAt.Format(time.RFC3339)))
		reviewerJWTRenewalCounter.WithLabelValues(ReviewerJWTResultSkipped).Inc()
		return Proceed, nil
	}

	issued, err := target.IssueReviewerJWT(ctx, state.Target, claim)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh, metav1.ConditionFalse, claim.Generation,
			"TokenRequestFailed", err.Error())
		reviewerJWTRenewalCounter.WithLabelValues(ReviewerJWTResultFailed).Inc()
		return Proceed, fmt.Errorf("issue reviewer JWT: %w", err)
	}
	state.ReviewerJWT = issued
	claim.Status.Vault.TokenReviewerJWT.IssuedAt = ptrTime(issued.IssuedAt)
	claim.Status.Vault.TokenReviewerJWT.ExpiresAt = ptrTime(issued.ExpiresAt)
	claim.Status.Vault.TokenReviewerJWT.LastRotated = ptrTime(issued.IssuedAt)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh, metav1.ConditionTrue, claim.Generation,
		"Rotated", fmt.Sprintf("Reviewer JWT issued, expires at %s", issued.ExpiresAt.Format(time.RFC3339)))
	reviewerJWTRenewalCounter.WithLabelValues(ReviewerJWTResultRotated).Inc()

	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "ReviewerJWTRotated",
			"Reviewer JWT for SA %s/%s rotated; expires %s",
			claim.Spec.Auth.TokenReviewer.ServiceAccount.Namespace,
			claim.Spec.Auth.TokenReviewer.ServiceAccount.Name,
			issued.ExpiresAt.Format(time.RFC3339))
	}
	return Proceed, nil
}

func ensureJWTStatus(s *vaultv1alpha1.TokenReviewerJWTStatus) *vaultv1alpha1.TokenReviewerJWTStatus {
	if s == nil {
		return &vaultv1alpha1.TokenReviewerJWTStatus{}
	}
	return s
}
