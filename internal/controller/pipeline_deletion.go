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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

const RequeueDeletionStuck = 1 * time.Minute

// handleDeletion drives the reverse pipeline: Roles → Policies → AuthMethod →
// Target SA → finalizer. Only names in the claim's ledger are deleted, never
// spec names: spec says what the claim wants, the ledger what it may have
// written. Vault-side failures keep the finalizer + requeue (premature removal
// would orphan Vault objects). Target cleanup is best-effort.
func (r *VaultClaimReconciler) handleDeletion(ctx context.Context, claim *vaultv1alpha1.VaultClaim) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("vaultclaim", client.ObjectKeyFromObject(claim))

	if !controllerutil.ContainsFinalizer(claim, vaultv1alpha1.VaultClaimFinalizer) {
		return ctrl.Result{}, nil
	}

	setPhase(claim, vaultv1alpha1.PhaseDeleting)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
		"Deleting", "reverse pipeline in progress")

	// A claim that never got past Step 1 wrote nothing to Vault: Step 1 records
	// the VaultConfig before any Vault write, every write is preceded by its
	// ledger entry, and the intent before creating a mount persists that
	// record. An earlier release recorded the mount path instead.
	if v := claim.Status.Vault; v != nil && (v.ConfigName != "" || v.AuthMountPath != "" || len(v.AppliedRoles) > 0 || len(v.AppliedPolicies) > 0) {
		if err := r.deleteVaultObjects(ctx, claim); err != nil {
			logger.V(1).Info("Vault cleanup error", "error", err.Error())
			logger.Info("Vault cleanup failed, keeping finalizer for retry", "cause", failureText(err))
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeWarning, "DeletionStuck",
					"Vault cleanup failed (will retry): %s", failureText(err))
			}
			return ctrl.Result{RequeueAfter: RequeueDeletionStuck}, nil
		}
	}

	if claim.Spec.Auth.ManagesConfig() {
		r.deleteTargetObjects(ctx, claim)
	}

	controllerutil.RemoveFinalizer(claim, vaultv1alpha1.VaultClaimFinalizer)
	if err := r.Update(ctx, claim); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeNormal, "VaultClaimDeleted",
			"reverse pipeline completed for auth/%s", claim.Spec.Auth.MountPath)
	}
	return ctrl.Result{}, nil
}

func (r *VaultClaimReconciler) deleteVaultObjects(ctx context.Context, claim *vaultv1alpha1.VaultClaim) error {
	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: claim.Spec.VaultConfigRef.Name}, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("VaultConfig %q not found", claim.Spec.VaultConfigRef.Name)
		}
		return fmt.Errorf("get VaultConfig: %w", err)
	}

	if r.VaultFactory == nil {
		return errors.New("VaultFactory not configured")
	}
	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		return fmt.Errorf("build vault client: %w", err)
	}
	if err := vc.EnsureLoggedIn(ctx); err != nil {
		return fmt.Errorf("vault login: %w", err)
	}

	mount := normMount(claim.Spec.Auth.MountPath)
	if mount == "" {
		return errors.New("spec.auth.mountPath is empty")
	}

	view, err := r.buildOwnershipView(ctx, claim)
	if err != nil {
		return err
	}
	others, err := r.everyOtherClaim(ctx, claim)
	if err != nil {
		return err
	}
	held := collectHeld(others)

	var journalRoles, journalPolicies []string
	if claim.Status.Vault != nil {
		journalRoles = claim.Status.Vault.AppliedRoles
		journalPolicies = claim.Status.Vault.AppliedPolicies
	}
	for _, name := range deletableRoles(view, mount, journalRoles, held) {
		if err := vc.DeleteKubernetesRole(ctx, mount, name); err != nil {
			return fmt.Errorf("delete role %q: %w", name, err)
		}
	}
	for _, name := range r.deletablePolicies(journalPolicies, held) {
		if err := vc.DeletePolicy(ctx, name); err != nil {
			return fmt.Errorf("delete policy %q: %w", name, err)
		}
	}
	// Transit keys are never deleted, under any policy.
	if claim.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyRetain ||
		!claim.Spec.Auth.ManagesConfig() || !claim.Spec.Auth.AutoCreateEnabled() {
		return nil
	}

	// The mount goes only when Vault itself shows it as this claim's: status
	// cannot tell a created mount from an adopted or foreign one.
	mounts, err := vc.ListAuthMounts(ctx)
	if err != nil {
		return fmt.Errorf("list auth mounts: %w", err)
	}
	info, exists := mounts[mountKey(mount)]
	if !exists {
		return nil
	}
	if view.isOperatorMount(mount) || !mountIsOurs(info, claim) {
		if r.Recorder != nil {
			r.Recorder.Eventf(claim, corev1.EventTypeWarning, ReasonMountNotOwned,
				"auth mount %q was left in place: sys/auth does not show it as this claim's", mount)
		}
		return nil
	}
	if err := vc.DisableAuthMethod(ctx, mount); err != nil {
		return fmt.Errorf("disable auth method %q: %w", mount, err)
	}
	return nil
}

// deleteTargetObjects best-effort cleans up the token-reviewer SA + CRB.
// Failures never block the finalizer — a missing kubeconfig Secret
// or unreachable infra apiserver is preferable to leaving the VaultClaim
// stuck in Deleting.
func (r *VaultClaimReconciler) deleteTargetObjects(ctx context.Context, claim *vaultv1alpha1.VaultClaim) {
	logger := log.FromContext(ctx)
	if !claim.Spec.Auth.TokenReviewer.ServiceAccount.AutoCreate {
		return
	}

	secret := &corev1.Secret{}
	name := kubeconfigSecretName(claim)
	if err := r.Get(ctx, client.ObjectKey{Namespace: claim.Namespace, Name: name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("kubeconfig Secret already gone; skipping target SA cleanup", "secret", name)
			return
		}
		r.warnTargetCleanup(ctx, claim, err, "get kubeconfig Secret %s/%s", claim.Namespace, name)
		return
	}

	if r.TargetManager == nil {
		r.warnTargetCleanup(ctx, claim, nil, "TargetManager not configured; skipping target SA cleanup")
		return
	}
	cs, err := r.TargetManager.Get(ctx, secret)
	if err != nil {
		r.warnTargetCleanup(ctx, claim, err, "build target client")
		return
	}
	if err := target.DeleteTokenReviewerSA(ctx, cs, claim); err != nil {
		r.warnTargetCleanup(ctx, claim, err, "delete target SA")
		return
	}
}

// warnTargetCleanup reports a skipped target cleanup. The event carries the
// table text for err; the raw error, which names the target cluster, goes to
// the debug log.
func (r *VaultClaimReconciler) warnTargetCleanup(ctx context.Context, claim *vaultv1alpha1.VaultClaim, err error, format string, args ...interface{}) {
	what := fmt.Sprintf(format, args...)
	msg := what
	if err != nil {
		msg = what + ": " + failureText(err)
		log.FromContext(ctx).V(1).Info("target cleanup error", "what", what, "error", err.Error())
	}
	if r.Recorder != nil {
		r.Recorder.Event(claim, corev1.EventTypeWarning, "TargetCleanupBestEffort", msg)
	}
	log.FromContext(ctx).V(1).Info("target cleanup skipped", "reason", msg)
}
