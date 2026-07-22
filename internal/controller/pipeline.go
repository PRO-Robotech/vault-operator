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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	RequeueClaimDriftReady     = 10 * time.Minute
	RequeueClaimVaultError     = 30 * time.Second
	RequeueClaimKubeconfigWait = 5 * time.Minute
	RequeueClaimTransient      = 1 * time.Minute
)

type StepResult int

const (
	Proceed StepResult = iota
	Wait
)

// pipelineState carries derived values across steps. Never persisted —
// ReviewerJWT.Token is sensitive.
type pipelineState struct {
	Config      *vaultv1alpha1.VaultConfig
	Vault       VaultClient
	Kubeconfig  *corev1.Secret
	Target      *target.ClientSet
	ReviewerJWT *target.IssuedJWT
}

type pipelineStep struct {
	name         string
	fn           func(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error)
	waitInterval time.Duration
}

// executePipeline runs the VaultClaim pipeline. When the claim was already
// Ready and spec is unchanged, a drift check after Step 1 may short-circuit
// Steps 2-7.
func (r *VaultClaimReconciler) executePipeline(ctx context.Context, claim *vaultv1alpha1.VaultClaim) ctrl.Result {
	logger := log.FromContext(ctx)
	state := &pipelineState{}

	// specChanged disables short-circuit: new policies/roles in spec would
	// be missed by drift detection.
	wasReady := claim.Status.Phase == vaultv1alpha1.PhaseReady
	specChanged := claim.Generation != claim.Status.ObservedGeneration

	setPhase(claim, vaultv1alpha1.PhaseConfiguring)

	steps := []pipelineStep{
		{name: "ResolveConfigAndLogin", fn: r.stepResolveConfigAndLogin, waitInterval: RequeueClaimVaultError},
		{name: "WaitKubeconfig", fn: r.stepWaitKubeconfig, waitInterval: RequeueClaimKubeconfigWait},
		{name: "EnsureTargetSA", fn: r.stepEnsureTargetSA, waitInterval: RequeueClaimTransient},
		{name: "IssueReviewerJWT", fn: r.stepIssueReviewerJWT, waitInterval: RequeueClaimTransient},
		{name: "EnableAuthMount", fn: r.stepEnableAuthMount, waitInterval: RequeueClaimVaultError},
		{name: "ApplyPolicies", fn: r.stepApplyPolicies, waitInterval: RequeueClaimTransient},
		{name: "ApplyRoles", fn: r.stepApplyRoles, waitInterval: RequeueClaimTransient},
	}

	for i, s := range steps {
		res, err := s.fn(ctx, claim, state)
		if err != nil {
			// Short-circuit: requeue at the next probe, not the fixed step interval.
			requeue := s.waitInterval
			var co *vault.CircuitOpenError
			if errors.As(err, &co) {
				requeue = requeueForCircuit(co.RetryAfter)
			}
			logger.Info("pipeline step failed (will retry)", "step", s.name, "error", err.Error(), "requeueAfter", requeue.String())
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeWarning, "StepRetrying",
					"Step %s failed (transient): %v", s.name, err)
			}
			return ctrl.Result{RequeueAfter: requeue}
		}
		if res == Wait {
			logger.V(1).Info("pipeline step waiting", "step", s.name)
			return ctrl.Result{RequeueAfter: s.waitInterval}
		}

		if i == 0 && wasReady && !specChanged && state.Vault != nil {
			if early, res := r.driftCheckAndMaybeShortCircuit(ctx, claim, state); early {
				return res
			}
		}
	}

	setReady(claim)
	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "VaultClaimReady",
			"All pipeline steps completed; auth/%s configured", claim.Spec.Auth.MountPath)
	}
	return ctrl.Result{RequeueAfter: RequeueClaimDriftReady}
}

func (r *VaultClaimReconciler) driftCheckAndMaybeShortCircuit(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (bool, ctrl.Result) {
	logger := log.FromContext(ctx)
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	claim.Status.Vault.LastDriftCheckAt = ptrTime(r.now())

	report, err := r.detectDrift(ctx, state.Vault, claim)
	if err != nil {
		logger.Info("drift check failed, falling through to full pipeline", "error", err.Error())
		return false, ctrl.Result{}
	}
	if report.Found() {
		logger.Info("drift detected, falling through to full pipeline", "summary", report.Summary())
		if r.Recorder != nil {
			r.Recorder.Eventf(claim, corev1.EventTypeWarning, "DriftDetected",
				"VaultClaim diverged from Vault state: %s", report.Summary())
		}
		return false, ctrl.Result{}
	}
	// detectDrift ignores JWT expiry — gate here or Step 4 never rotates.
	if target.ShouldRotateReviewerJWT(claim.Status.Vault.TokenReviewerJWT, r.now()) {
		logger.Info("reviewer JWT past rotation threshold, falling through to full pipeline")
		return false, ctrl.Result{}
	}
	setReady(claim)
	return true, ctrl.Result{RequeueAfter: RequeueClaimDriftReady}
}

func setPhase(claim *vaultv1alpha1.VaultClaim, phase string) {
	claim.Status.Phase = phase
}

func setReady(claim *vaultv1alpha1.VaultClaim) {
	setPhase(claim, vaultv1alpha1.PhaseReady)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionTrue, claim.Generation,
		"Ready", "All pipeline steps completed")
}

func kubeconfigSecretName(claim *vaultv1alpha1.VaultClaim) string {
	if claim.Spec.ClusterRef.KubeconfigSecret != "" {
		return claim.Spec.ClusterRef.KubeconfigSecret
	}
	return fmt.Sprintf("%s-infra-kubeconfig", claim.Spec.ClusterRef.Name)
}
