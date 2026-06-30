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
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	secretRequeueConfigNotReady = time.Minute
	secretRequeueLoginTransient = 30 * time.Second
	secretRequeueApplyFailed    = time.Minute
)

// VaultSecretClaimReconciler fills Vault with secret values via an event-driven
// pipeline. VaultFactory is injected for tests.
type VaultSecretClaimReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	VaultFactory SecretVaultClientFactory

	// Now is an injectable clock for tests; nil → time.Now.
	Now func() time.Time
}

func (r *VaultSecretClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("vaultsecretclaim", req.NamespacedName)

	claim := &vaultv1alpha1.VaultSecretClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get VaultSecretClaim: %w", err)
	}

	if !claim.DeletionTimestamp.IsZero() {
		oldStatus := claim.Status.DeepCopy()
		res, err := r.handleDeletion(ctx, claim)
		if statusErr := r.updateStatusIfChanged(ctx, claim, oldStatus); statusErr != nil {
			logger.V(1).Info("status update during deletion (will retry)", "err", statusErr.Error())
		}
		return res, err
	}

	if controllerutil.AddFinalizer(claim, vaultv1alpha1.VaultSecretClaimFinalizer) {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	oldStatus := claim.Status.DeepCopy()
	result := r.reconcile(ctx, claim)
	claim.Status.ObservedGeneration = claim.Generation

	if err := r.updateStatusIfChanged(ctx, claim, oldStatus); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}
	return result, nil
}

// reconcile runs the 4-step pipeline, mutating claim.Status. There is no
// periodic requeue on success — reconcile is event-driven.
func (r *VaultSecretClaimReconciler) reconcile(ctx context.Context, claim *vaultv1alpha1.VaultSecretClaim) ctrl.Result {
	vc, cfg, res, ok := r.resolveAndLogin(ctx, claim)
	if !ok {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
			"Pending", "waiting for VaultConfig to become reachable")
		return res
	}
	defMount := cfg.Spec.Storage.KvMountPath

	if err := validateUniqueDestinations(claim.Spec.SecretList); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionItemsApplied, metav1.ConditionFalse, claim.Generation,
			"DuplicateDestination", err.Error())
		r.markFailed(claim, "DuplicateDestination", err.Error())
		r.event(claim, "DuplicateDestination", err.Error())
		return ctrl.Result{}
	}

	if err := validateCopySources(ctx, vc, defMount, claim.Spec.SecretList); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionSourcesResolved, metav1.ConditionFalse, claim.Generation,
			"MissingSource", err.Error())
		r.markFailed(claim, "MissingSource", err.Error())
		r.event(claim, "MissingSource", err.Error())
		return ctrl.Result{RequeueAfter: secretRequeueApplyFailed}
	}

	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionSourcesResolved, metav1.ConditionTrue, claim.Generation,
		"AllSourcesPresent", "all copy sources exist in Vault")

	if allOK := r.applyItems(ctx, vc, defMount, claim); !allOK {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionItemsApplied, metav1.ConditionFalse, claim.Generation,
			"ApplyFailed", "one or more items failed to apply")
		r.markFailed(claim, "ApplyFailed", "one or more items failed to apply")
		return ctrl.Result{RequeueAfter: secretRequeueApplyFailed}
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionItemsApplied, metav1.ConditionTrue, claim.Generation,
		"AllItemsApplied", "all secrets written to Vault")

	r.markReady(claim)
	return ctrl.Result{}
}

// resolveAndLogin mirrors the main operator's Step 1: resolve the VaultConfig,
// verify it is Reachable + SharedMountFound, build the client and login.
func (r *VaultSecretClaimReconciler) resolveAndLogin(ctx context.Context, claim *vaultv1alpha1.VaultSecretClaim) (SecretVaultClient, *vaultv1alpha1.VaultConfig, ctrl.Result, bool) {
	configName := claim.Spec.VaultConfigRef.Name
	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: configName}, cfg); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"NotFound", fmt.Sprintf("VaultConfig %q not found", configName))
		return nil, nil, ctrl.Result{RequeueAfter: secretRequeueConfigNotReady}, false
	}

	if !isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionReachable) ||
		!isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound) {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"VaultUnavailable", fmt.Sprintf("VaultConfig %q not Reachable/SharedMountFound", configName))
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"VaultUnavailable", "skipped: VaultConfig not ready")
		return nil, nil, ctrl.Result{RequeueAfter: secretRequeueConfigNotReady}, false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionTrue, claim.Generation,
		"Resolved", fmt.Sprintf("VaultConfig %q is Reachable and SharedMountFound", configName))

	if r.VaultFactory == nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"FactoryError", "VaultFactory is not configured")
		return nil, nil, ctrl.Result{RequeueAfter: secretRequeueLoginTransient}, false
	}
	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"FactoryError", err.Error())
		return nil, nil, ctrl.Result{RequeueAfter: secretRequeueLoginTransient}, false
	}

	if err := vc.Login(ctx); err != nil {
		reason := ReasonLoginFailed
		if vault.IsCircuitOpen(err) {
			reason = ReasonCircuitOpen
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			reason, err.Error())
		return nil, nil, ctrl.Result{RequeueAfter: secretRequeueLoginTransient}, false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionTrue, claim.Generation,
		"LoggedIn", "Vault login succeeded")
	return vc, cfg, ctrl.Result{}, true
}

// applyItems applies every secretList item, preserving prior per-item status for
// unchanged entries. Returns false if any item failed.
func (r *VaultSecretClaimReconciler) applyItems(ctx context.Context, vc SecretVaultClient, defMount string, claim *vaultv1alpha1.VaultSecretClaim) bool {
	prev := make(map[string]vaultv1alpha1.SecretItemStatus, len(claim.Status.Items))
	for _, it := range claim.Status.Items {
		prev[it.Name] = it
	}

	now := r.now()
	out := make([]vaultv1alpha1.SecretItemStatus, 0, len(claim.Spec.SecretList))
	allOK := true

	for i := range claim.Spec.SecretList {
		item := &claim.Spec.SecretList[i]
		prevHash := prev[item.Name].SourceHash

		var newHash string
		var changed bool
		var err error
		switch item.Type {
		case vaultv1alpha1.SecretTypeCopy:
			newHash, changed, err = applyCopyItem(ctx, vc, defMount, claim.Spec.SecretsPrefix, item, prevHash)
		case vaultv1alpha1.SecretTypeGenerate:
			newHash, changed, err = applyGenerateItem(ctx, vc, defMount, claim.Spec.SecretsPrefix, item, prevHash)
		default:
			err = fmt.Errorf("item %q: unknown type %q", item.Name, item.Type)
		}

		st := vaultv1alpha1.SecretItemStatus{Name: item.Name}
		switch {
		case err != nil:
			st.State = vaultv1alpha1.ItemStateFailed
			st.Message = err.Error()
			st.SourceHash = prevHash
			st.LastAppliedAt = prev[item.Name].LastAppliedAt
			allOK = false
			r.event(claim, "ItemApplyFailed", fmt.Sprintf("item %q: %v", item.Name, err))
		case changed:
			st.State = vaultv1alpha1.ItemStateApplied
			st.SourceHash = newHash
			st.LastAppliedAt = ptrTime(now)
		default:
			st.State = vaultv1alpha1.ItemStateApplied
			st.SourceHash = newHash
			st.LastAppliedAt = prev[item.Name].LastAppliedAt
		}
		out = append(out, st)
	}

	claim.Status.Items = out
	return allOK
}

func (r *VaultSecretClaimReconciler) handleDeletion(ctx context.Context, claim *vaultv1alpha1.VaultSecretClaim) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(claim, vaultv1alpha1.VaultSecretClaimFinalizer) {
		return ctrl.Result{}, nil
	}
	claim.Status.Phase = vaultv1alpha1.PhaseDeleting

	if claim.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyPurge {
		vc, cfg, ok := r.clientForDeletion(ctx, claim)
		if !ok {
			r.event(claim, "DeletionStuck", "Purge requested but Vault is unavailable; retrying")
			return ctrl.Result{RequeueAfter: secretRequeueApplyFailed}, nil
		}
		if err := r.purge(ctx, vc, cfg.Spec.Storage.KvMountPath, claim); err != nil {
			r.event(claim, "DeletionStuck", fmt.Sprintf("purge failed: %v", err))
			return ctrl.Result{RequeueAfter: secretRequeueApplyFailed}, nil
		}
	}

	controllerutil.RemoveFinalizer(claim, vaultv1alpha1.VaultSecretClaimFinalizer)
	if err := r.Update(ctx, claim); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// clientForDeletion best-effort resolves a logged-in client for Purge.
func (r *VaultSecretClaimReconciler) clientForDeletion(ctx context.Context, claim *vaultv1alpha1.VaultSecretClaim) (SecretVaultClient, *vaultv1alpha1.VaultConfig, bool) {
	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: claim.Spec.VaultConfigRef.Name}, cfg); err != nil {
		return nil, nil, false
	}
	if r.VaultFactory == nil {
		return nil, nil, false
	}
	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		return nil, nil, false
	}
	if err := vc.Login(ctx); err != nil {
		return nil, nil, false
	}
	return vc, cfg, true
}

// purge removes the keys this claim wrote, grouped by destination path. A path
// left with no keys is deleted entirely; sibling keys not owned here survive.
func (r *VaultSecretClaimReconciler) purge(ctx context.Context, vc SecretVaultClient, defMount string, claim *vaultv1alpha1.VaultSecretClaim) error {
	type group struct {
		mount string
		path  string
		keys  map[string]struct{}
	}
	groups := map[string]*group{}
	for i := range claim.Spec.SecretList {
		item := &claim.Spec.SecretList[i]
		mount := resolveMount(item.Destination.Mount, defMount)
		path := joinPath(claim.Spec.SecretsPrefix, item.Destination.Path)
		gk := mount + "|" + path
		g, ok := groups[gk]
		if !ok {
			g = &group{mount: mount, path: path, keys: map[string]struct{}{}}
			groups[gk] = g
		}
		g.keys[item.Destination.Key] = struct{}{}
		if item.Type == vaultv1alpha1.SecretTypeGenerate && item.Destination.HashedKey != "" {
			g.keys[item.Destination.HashedKey] = struct{}{}
		}
	}

	for _, g := range groups {
		data, ok, err := vc.ReadKV(ctx, g.mount, g.path)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		for k := range g.keys {
			delete(data, k)
		}
		if len(data) == 0 {
			if err := vc.DeleteKVMetadata(ctx, g.mount, g.path); err != nil {
				return err
			}
			continue
		}
		if err := vc.WriteKV(ctx, g.mount, g.path, data); err != nil {
			return err
		}
	}
	return nil
}

func validateUniqueDestinations(items []vaultv1alpha1.SecretListItem) error {
	seen := make(map[string]string, len(items))
	for i := range items {
		it := &items[i]
		key := it.Destination.Mount + "|" + it.Destination.Path + "|" + it.Destination.Key
		if other, ok := seen[key]; ok {
			return fmt.Errorf("items %q and %q write the same destination %s#%s", other, it.Name, it.Destination.Path, it.Destination.Key)
		}
		seen[key] = it.Name
	}
	return nil
}

func (r *VaultSecretClaimReconciler) markReady(claim *vaultv1alpha1.VaultSecretClaim) {
	claim.Status.Phase = vaultv1alpha1.PhaseReady
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionTrue, claim.Generation,
		"Ready", "all secrets applied")
}

func (r *VaultSecretClaimReconciler) markFailed(claim *vaultv1alpha1.VaultSecretClaim, reason, msg string) {
	claim.Status.Phase = vaultv1alpha1.PhaseFailed
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
		reason, msg)
}

func (r *VaultSecretClaimReconciler) event(claim *vaultv1alpha1.VaultSecretClaim, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(claim, corev1.EventTypeWarning, reason, msg)
	}
}

func (r *VaultSecretClaimReconciler) updateStatusIfChanged(ctx context.Context, claim *vaultv1alpha1.VaultSecretClaim, old *vaultv1alpha1.VaultSecretClaimStatus) error {
	if apiequality.Semantic.DeepEqual(old, &claim.Status) {
		return nil
	}
	return r.Status().Update(ctx, claim)
}

func (r *VaultSecretClaimReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *VaultSecretClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultSecretClaim{}).
		Watches(
			&vaultv1alpha1.VaultConfig{},
			handler.EnqueueRequestsFromMapFunc(r.findSecretClaimsForVaultConfig),
		).
		Named("vaultsecretclaim").
		Complete(r)
}
