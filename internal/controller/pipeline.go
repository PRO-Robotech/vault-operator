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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	RequeueClaimBackoffCap     = 10 * time.Minute
	// RequeueClaimRefused re-checks a refused claim: the conflicting claim may
	// be gone, the reserved list may have changed.
	RequeueClaimRefused = 5 * time.Minute
	// RequeueClaimSpecChanged restarts a pass the claim's edit cut short. The
	// edit enqueues the claim by itself; this is the fallback.
	RequeueClaimSpecChanged = 1 * time.Second
)

// errSpecChanged stops a pass whose claim was edited while the pass persisted
// an intent. The pass admitted the previous spec; it neither writes the new
// one, which CheckOwnership has not judged, nor reports it as observed.
var errSpecChanged = errors.New("spec changed during the pass")

type StepResult int

const (
	Proceed StepResult = iota
	Wait
	// Refuse stops the pass: the claim asks for something it may not have.
	// The step has set its condition; the pass marks the claim Failed.
	Refuse
)

// Step names referenced outside the step table.
const stepAdmission = "CheckOwnership"

// pipelineState carries derived values across steps. Never persisted —
// ReviewerJWT.Token is sensitive.
type pipelineState struct {
	Config      *vaultv1alpha1.VaultConfig
	Vault       VaultClient
	Kubeconfig  *corev1.Secret
	Target      *target.ClientSet
	ReviewerJWT *target.IssuedJWT

	// View is what CheckOwnership learned about operator mounts and other claims.
	View *ownershipView
	// RecordedMount is status.vault.authMountPath as persisted when the pass
	// began: the mount an earlier pass, or an earlier release, accepted.
	RecordedMount string
	// MountOwned is proven in this pass: 2xx from this claim's POST sys/auth,
	// or sys/auth showing this claim's description. Never read from status.
	MountOwned bool
	// RefusedReason is the reason of the step that returned Refuse.
	RefusedReason string

	// persist writes the in-memory status before a Vault write. It is nil
	// only when a test drives one step directly.
	persist func(ctx context.Context, claim *vaultv1alpha1.VaultClaim) error
}

// intent persists the status as it stands, so that every name the claim is
// about to write is in its ledger before Vault sees the write. A failed
// persist aborts the step: nothing is written that the ledger does not list.
func (s *pipelineState) intent(ctx context.Context, claim *vaultv1alpha1.VaultClaim) error {
	if s.persist == nil {
		return nil
	}
	return s.persist(ctx, claim)
}

type pipelineStep struct {
	name         string
	fn           func(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error)
	waitInterval time.Duration
}

func (r *VaultClaimReconciler) pipelineSteps(claim *vaultv1alpha1.VaultClaim) []pipelineStep {
	head := []pipelineStep{
		{name: "ResolveConfigAndLogin", fn: r.stepResolveConfigAndLogin, waitInterval: RequeueClaimVaultError},
		{name: stepAdmission, fn: r.stepCheckOwnership, waitInterval: RequeueClaimVaultError},
	}
	var mount []pipelineStep
	if claim.Spec.Auth.ManagesConfig() {
		mount = []pipelineStep{
			{name: "WaitKubeconfig", fn: r.stepWaitKubeconfig, waitInterval: RequeueClaimKubeconfigWait},
			{name: "EnsureTargetSA", fn: r.stepEnsureTargetSA, waitInterval: RequeueClaimTransient},
			{name: "IssueReviewerJWT", fn: r.stepIssueReviewerJWT, waitInterval: RequeueClaimTransient},
			{name: "EnableAuthMount", fn: r.stepEnableAuthMount, waitInterval: RequeueClaimVaultError},
		}
	} else {
		mount = []pipelineStep{
			{name: "VerifyGuestMount", fn: r.stepVerifyGuestMount, waitInterval: RequeueClaimTransient},
		}
	}
	tail := []pipelineStep{
		{name: "EnsureTransitKeys", fn: r.stepEnsureTransitKeys, waitInterval: RequeueClaimVaultError},
		{name: "ApplyPolicies", fn: r.stepApplyPolicies, waitInterval: RequeueClaimTransient},
		{name: "ApplyRoles", fn: r.stepApplyRoles, waitInterval: RequeueClaimTransient},
		{name: "PruneRemoved", fn: r.stepPruneRemoved, waitInterval: RequeueClaimTransient},
	}
	return append(append(head, mount...), tail...)
}

// executePipeline runs the VaultClaim pipeline. When the claim was already
// Ready and spec is unchanged, a drift check after CheckOwnership may
// short-circuit the remaining steps. base is the status as last persisted; the
// pipeline advances it each time it writes an intent. Every step works on the
// spec claim held when the pass began: an intent never refreshes it.
// completed reports a pass that ended Ready.
func (r *VaultClaimReconciler) executePipeline(ctx context.Context, claim *vaultv1alpha1.VaultClaim,
	base *vaultv1alpha1.VaultClaimStatus) (result ctrl.Result, completed bool) {
	logger := log.FromContext(ctx)
	state := &pipelineState{persist: func(ctx context.Context, c *vaultv1alpha1.VaultClaim) error {
		return r.persistIntent(ctx, c, base)
	}}
	if claim.Status.Vault != nil {
		state.RecordedMount = claim.Status.Vault.AuthMountPath
	}
	key := client.ObjectKeyFromObject(claim)

	// specChanged disables short-circuit: new policies/roles in spec would
	// be missed by drift detection.
	startPhase := claim.Status.Phase
	wasReady := startPhase == vaultv1alpha1.PhaseReady
	specChanged := claim.Generation != claim.Status.ObservedGeneration

	setPhase(claim, vaultv1alpha1.PhaseConfiguring)

	for _, s := range r.pipelineSteps(claim) {
		res, err := s.fn(ctx, claim, state)
		if errors.Is(err, errSpecChanged) {
			// Not a failure: the next pass admits the new spec from the start.
			logger.V(1).Info("spec changed during the pass; starting over", "step", s.name)
			r.backoff.Reset(key)
			setPhase(claim, startPhase)
			return ctrl.Result{RequeueAfter: RequeueClaimSpecChanged}, false
		}
		countStep(s.name, res, err)
		if err != nil {
			// Degraded names the cause from the closed set; Ready is the
			// outcome of the last completed pass and stays as it was.
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionDegraded, metav1.ConditionTrue, claim.Generation,
				string(classifyFailure(err)), failureText(err))
			var requeue time.Duration
			var co *vault.CircuitOpenError
			if errors.As(err, &co) {
				requeue = requeueForCircuit(co.RetryAfter)
			} else {
				requeue = r.backoff.Next(key, s.name, s.waitInterval, RequeueClaimBackoffCap)
			}
			// The raw error carries Vault and target addresses; it stays in the
			// debug log. Everything a claim reader can see uses the table text.
			logger.V(1).Info("pipeline step error", "step", s.name, "error", err.Error())
			logger.Info("pipeline step failed (will retry)", "step", s.name, "cause", failureText(err), "requeueAfter", requeue.String())
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeWarning, "StepRetrying",
					"Step %s failed (transient): %s", s.name, failureText(err))
			}
			return ctrl.Result{RequeueAfter: requeue}, false
		}
		switch res {
		case Wait:
			logger.V(1).Info("pipeline step waiting", "step", s.name)
			r.backoff.Reset(key)
			return ctrl.Result{RequeueAfter: s.waitInterval}, false
		case Refuse:
			r.backoff.Reset(key)
			setPhase(claim, vaultv1alpha1.PhaseFailed)
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
				state.RefusedReason, fmt.Sprintf("step %s refused the claim; see its condition", s.name))
			return ctrl.Result{RequeueAfter: RequeueClaimRefused}, false
		}

		if s.name == stepAdmission && wasReady && !specChanged && state.Vault != nil {
			if early, res := r.driftCheckAndMaybeShortCircuit(ctx, claim, state); early {
				r.backoff.Reset(key)
				return res, true
			}
		}
	}

	r.backoff.Reset(key)
	setReady(claim)
	if r.Recorder != nil && !wasReady {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "VaultClaimReady",
			"All pipeline steps completed; auth/%s configured", claim.Spec.Auth.MountPath)
	}
	return ctrl.Result{RequeueAfter: RequeueClaimDriftReady}, true
}

// refuse records why the claim may not proceed. The message is built from
// spec values only.
func (r *VaultClaimReconciler) refuse(claim *vaultv1alpha1.VaultClaim, state *pipelineState, condType, reason, message string) (StepResult, error) {
	setCondition(&claim.Status.Conditions, condType, metav1.ConditionFalse, claim.Generation, reason, message)
	state.RefusedReason = reason
	if r.Recorder != nil {
		r.Recorder.Event(claim, corev1.EventTypeWarning, reason, message)
	}
	return Refuse, nil
}

// persistIntent persists the ledger fields of claim's status over base, then
// advances base. It patches a copy: the server answers with the whole object,
// and a spec edited since the pass began must not replace the spec the pass
// admitted. Only the resource version comes back into claim. An edit is seen
// as a new generation in the answer and ends the pass with errSpecChanged.
func (r *VaultClaimReconciler) persistIntent(ctx context.Context, claim *vaultv1alpha1.VaultClaim, base *vaultv1alpha1.VaultClaimStatus) error {
	want := intentStatus(base, &claim.Status)
	if apiequality.Semantic.DeepEqual(stripHeartbeats(base), stripHeartbeats(want)) {
		return nil
	}
	orig := claim.DeepCopy()
	orig.Status = *base
	sent := claim.DeepCopy()
	sent.Status = *want
	if err := r.Status().Patch(ctx, sent, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("persist intent: %w", err)
	}
	*base = *sent.Status.DeepCopy()
	claim.ResourceVersion = sent.ResourceVersion
	if sent.Generation != claim.Generation {
		return errSpecChanged
	}
	return nil
}

// intentStatus is base with the ledger fields of cur: the Vault config the
// claim writes through, the mount it accepted and the names it is about to
// write. Phase, conditions and the rest stay as last persisted, so an intent
// never shows a claim in a phase it was not in; the pass's outcome goes in the
// final patch. ConfigName is set before the first Vault write of a pass, so a
// persisted intent always tells deletion that Vault may hold something.
func intentStatus(base, cur *vaultv1alpha1.VaultClaimStatus) *vaultv1alpha1.VaultClaimStatus {
	out := base.DeepCopy()
	v := cur.Vault
	if v == nil || (out.Vault == nil && v.ConfigName == "" && v.AuthMountPath == "" &&
		len(v.AppliedPolicies) == 0 && len(v.AppliedRoles) == 0 && len(v.TransitKeys) == 0) {
		return out
	}
	if out.Vault == nil {
		out.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	v = v.DeepCopy()
	out.Vault.ConfigName = v.ConfigName
	out.Vault.AuthMountPath = v.AuthMountPath
	out.Vault.AppliedPolicies = v.AppliedPolicies
	out.Vault.AppliedRoles = v.AppliedRoles
	out.Vault.TransitKeys = v.TransitKeys
	return out
}

func (r *VaultClaimReconciler) driftCheckAndMaybeShortCircuit(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (bool, ctrl.Result) {
	logger := log.FromContext(ctx)
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	claim.Status.Vault.LastDriftCheckAt = ptrTime(r.now())

	report, err := r.detectDrift(ctx, state.Vault, claim)
	if err != nil {
		logger.V(1).Info("drift check error", "error", err.Error())
		logger.Info("drift check failed, falling through to full pipeline", "cause", failureText(err))
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
	// detectDrift ignores JWT expiry — gate here or the JWT never rotates on
	// schedule. A guest has no reviewer JWT of its own.
	if claim.Spec.Auth.ManagesConfig() && target.ShouldRotateReviewerJWT(claim.Status.Vault.TokenReviewerJWT, r.now()) {
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
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionDegraded, metav1.ConditionFalse, claim.Generation,
		ReasonReconciled, "the last pass completed")
}

func kubeconfigSecretName(claim *vaultv1alpha1.VaultClaim) string {
	if claim.Spec.ClusterRef.KubeconfigSecret != "" {
		return claim.Spec.ClusterRef.KubeconfigSecret
	}
	return fmt.Sprintf("%s-infra-kubeconfig", claim.Spec.ClusterRef.Name)
}
