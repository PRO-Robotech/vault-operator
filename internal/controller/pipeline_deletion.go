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

// handleDeletion drives the reverse pipeline: Roles →
// Policies → AuthMethod → Target SA → finalizer. Vault-side failures keep
// the finalizer + requeue (premature removal would orphan Vault objects).
// Target cleanup is best-effort.
func (r *VaultClaimReconciler) handleDeletion(ctx context.Context, claim *vaultv1alpha1.VaultClaim) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("vaultclaim", client.ObjectKeyFromObject(claim))

	if !controllerutil.ContainsFinalizer(claim, vaultv1alpha1.VaultClaimFinalizer) {
		return ctrl.Result{}, nil
	}

	setPhase(claim, vaultv1alpha1.PhaseDeleting)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
		"Deleting", "reverse pipeline in progress")

	// Skip Vault cleanup if the auth mount was never created — target SA
	// cleanup may still apply.
	everCreatedAuth := claim.Status.Vault != nil && claim.Status.Vault.AuthMountPath != ""
	if everCreatedAuth {
		if err := r.deleteVaultObjects(ctx, claim); err != nil {
			logger.Info("Vault cleanup failed, keeping finalizer for retry", "error", err.Error())
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeWarning, "DeletionStuck",
					"Vault cleanup failed (will retry): %v", err)
			}
			return ctrl.Result{RequeueAfter: RequeueDeletionStuck}, nil
		}
	}

	r.deleteTargetObjects(ctx, claim)

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
	if err := vc.Login(ctx); err != nil {
		return fmt.Errorf("vault login: %w", err)
	}

	mount := claim.Spec.Auth.MountPath
	if mount == "" {
		return errors.New("spec.auth.mountPath is empty")
	}

	for _, name := range roleNamesForDeletion(claim) {
		if err := vc.DeleteKubernetesRole(ctx, mount, name); err != nil {
			return fmt.Errorf("delete role %q: %w", name, err)
		}
	}
	for _, name := range policyNamesForDeletion(claim) {
		if err := vc.DeletePolicy(ctx, name); err != nil {
			return fmt.Errorf("delete policy %q: %w", name, err)
		}
	}
	if err := vc.DisableAuthMethod(ctx, mount); err != nil {
		return fmt.Errorf("disable auth method %q: %w", mount, err)
	}
	return nil
}

// roleNamesForDeletion returns the union of names recorded on status and
// declared in spec, deduplicated, so we clean up whatever we either created
// or had in spec at deletion time.
func roleNamesForDeletion(claim *vaultv1alpha1.VaultClaim) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	if claim.Status.Vault != nil {
		for _, name := range claim.Status.Vault.AppliedRoles {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	for i := range claim.Spec.Roles {
		name := claim.Spec.Roles[i].Name
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func policyNamesForDeletion(claim *vaultv1alpha1.VaultClaim) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	if claim.Status.Vault != nil {
		for _, name := range claim.Status.Vault.AppliedPolicies {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	for i := range claim.Spec.Policies {
		name := claim.Spec.Policies[i].Name
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
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
		r.warnTargetCleanup(claim, "get kubeconfig Secret %s/%s: %v", claim.Namespace, name, err)
		return
	}

	if r.TargetManager == nil {
		r.warnTargetCleanup(claim, "TargetManager not configured; skipping target SA cleanup")
		return
	}
	cs, err := r.TargetManager.Get(ctx, secret)
	if err != nil {
		r.warnTargetCleanup(claim, "build target client: %v", err)
		return
	}
	if err := target.DeleteTokenReviewerSA(ctx, cs, claim); err != nil {
		r.warnTargetCleanup(claim, "delete target SA: %v", err)
		return
	}
}

func (r *VaultClaimReconciler) warnTargetCleanup(claim *vaultv1alpha1.VaultClaim, format string, args ...interface{}) {
	if r.Recorder != nil {
		r.Recorder.Eventf(claim, corev1.EventTypeWarning, "TargetCleanupBestEffort", format, args...)
	}
	log.FromContext(context.Background()).V(1).Info("target cleanup skipped", "reason", fmt.Sprintf(format, args...))
}
