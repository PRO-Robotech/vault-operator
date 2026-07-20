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
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	RequeueHealthy         = 5 * time.Minute
	RequeueSealed          = 1 * time.Minute
	RequeueUnreachable     = 30 * time.Second
	RequeueDeletionBlocked = 1 * time.Minute
)

// VaultConfigReconciler probes Vault health (seal-status → login → shared
// mount), maintains health conditions, tracks
// referencedBy, and cascade-reconciles dependent VaultClaims.
type VaultConfigReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Recorder            record.EventRecorder
	VaultFactory        VaultClientFactory
	ClaimReconcilerName string

	// VaultConfigOwner scopes which VaultConfigs this reconciler owns by the
	// vault.in-cloud.io/owner label. Empty (or "vault-operator") owns label-less
	// + vault-operator configs; "vault-secret" owns the secret operator's config.
	VaultConfigOwner string
}

// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch

func (r *VaultConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("vaultconfig", req.Name)

	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, req.NamespacedName, cfg); err != nil {
		if apierrors.IsNotFound(err) {
			if r.VaultFactory != nil {
				r.VaultFactory.Invalidate(req.Name)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get VaultConfig: %w", err)
	}

	// Ignore configs owned by the other operator process — a request can still
	// arrive via a claim-cascade watch, so the gate lives in Reconcile.
	if !ownerMatches(cfg.Labels[vaultv1alpha1.LabelVaultConfigOwner], r.VaultConfigOwner) {
		return ctrl.Result{}, nil
	}

	if !cfg.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, cfg)
	}

	// AddFinalizer mutates cfg in-memory; persist it before touching status.
	if controllerutil.AddFinalizer(cfg, vaultv1alpha1.VaultConfigFinalizer) {
		if err := r.Update(ctx, cfg); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	oldStatus := cfg.Status.DeepCopy()

	refs, err := r.countReferences(ctx, cfg.Name)
	if err != nil {
		logger.Error(err, "failed to count referencing VaultClaims")
	} else {
		cfg.Status.ReferencedBy = refs
	}

	result := r.probeHealth(ctx, cfg)
	cfg.Status.ObservedGeneration = cfg.Generation
	cfg.Status.LastHealthCheckAt = ptrTime(time.Now())

	if err := r.updateStatusIfChanged(ctx, cfg, oldStatus); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}

	return result, nil
}

func (r *VaultConfigReconciler) handleDeletion(ctx context.Context, cfg *vaultv1alpha1.VaultConfig) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	if !controllerutil.ContainsFinalizer(cfg, vaultv1alpha1.VaultConfigFinalizer) {
		return ctrl.Result{}, nil
	}

	refs, err := r.countReferences(ctx, cfg.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("count references during deletion: %w", err)
	}
	if refs > 0 {
		logger.Info("deletion blocked by referencing VaultClaims", "count", refs)
		if r.Recorder != nil {
			r.Recorder.Eventf(cfg, corev1.EventTypeWarning, "DeletionBlocked",
				"%d VaultClaim(s) still reference this VaultConfig; remove them first", refs)
		}
		oldStatus := cfg.Status.DeepCopy()
		cfg.Status.ReferencedBy = refs
		_ = r.updateStatusIfChanged(ctx, cfg, oldStatus)
		return ctrl.Result{RequeueAfter: RequeueDeletionBlocked}, nil
	}

	controllerutil.RemoveFinalizer(cfg, vaultv1alpha1.VaultConfigFinalizer)
	if err := r.Update(ctx, cfg); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	if r.VaultFactory != nil {
		r.VaultFactory.Invalidate(cfg.Name)
	}
	return ctrl.Result{}, nil
}

// probeHealth runs seal-status → login → shared mount, mapping each outcome
// to a condition on cfg. Returns Result with RequeueAfter; errors stay on
// status, not in the return value.
func (r *VaultConfigReconciler) probeHealth(ctx context.Context, cfg *vaultv1alpha1.VaultConfig) ctrl.Result {
	logger := log.FromContext(ctx)

	if r.VaultFactory == nil {
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionReachable, metav1.ConditionFalse, cfg.Generation,
			"NoFactory", "vault client factory is not configured")
		return ctrl.Result{RequeueAfter: RequeueUnreachable}
	}

	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		logger.Error(err, "build vault client")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionReachable, metav1.ConditionFalse, cfg.Generation,
			"FactoryError", err.Error())
		return ctrl.Result{RequeueAfter: RequeueUnreachable}
	}

	ss, err := vc.SealStatus(ctx)
	if err != nil {
		logger.Error(err, "vault seal-status failed")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionReachable, metav1.ConditionFalse, cfg.Generation,
			"SealStatusFailed", err.Error())
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultInitialized, metav1.ConditionUnknown, cfg.Generation,
			"SealStatusFailed", "unable to probe seal status")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed, metav1.ConditionUnknown, cfg.Generation,
			"SealStatusFailed", "unable to probe seal status")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn, metav1.ConditionFalse, cfg.Generation,
			"SealStatusFailed", "skipped: Vault unreachable")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionUnknown, cfg.Generation,
			"SealStatusFailed", "skipped: Vault unreachable")
		return ctrl.Result{RequeueAfter: RequeueUnreachable}
	}
	cfg.Status.SealStatus = &vaultv1alpha1.SealStatus{
		Sealed:      ss.Sealed,
		Initialized: ss.Initialized,
		T:           int32(ss.T),
		N:           int32(ss.N),
		Progress:    int32(ss.Progress),
	}
	cfg.Status.VaultVersion = ss.Version

	setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionReachable, metav1.ConditionTrue, cfg.Generation,
		"Reachable", "GET sys/seal-status succeeded")

	if !ss.Initialized {
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultInitialized, metav1.ConditionFalse, cfg.Generation,
			"Uninitialized", "Vault reports initialized=false")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed, metav1.ConditionFalse, cfg.Generation,
			"Uninitialized", "Vault must be initialized before unseal")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn, metav1.ConditionFalse, cfg.Generation,
			"Uninitialized", "skipped: Vault uninitialized")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionFalse, cfg.Generation,
			"Uninitialized", "skipped: Vault uninitialized")
		return ctrl.Result{RequeueAfter: RequeueSealed}
	}
	setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultInitialized, metav1.ConditionTrue, cfg.Generation,
		"Initialized", "Vault reports initialized=true")

	if ss.Sealed {
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed, metav1.ConditionFalse, cfg.Generation,
			"Sealed", fmt.Sprintf("Vault is sealed (progress=%d/%d)", ss.Progress, ss.T))
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn, metav1.ConditionFalse, cfg.Generation,
			"Sealed", "skipped: Vault sealed")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionFalse, cfg.Generation,
			"Sealed", "skipped: Vault sealed")
		// Sealed Vault may have rotated tokens — drop the cached one.
		vc.ClearToken()
		return ctrl.Result{RequeueAfter: RequeueSealed}
	}
	setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed, metav1.ConditionTrue, cfg.Generation,
		"Unsealed", "Vault is unsealed")

	if err := vc.Login(ctx); err != nil {
		logger.Error(err, "vault login failed")
		reason, requeue := classifyVaultErr(err, ReasonLoginFailed)
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn, metav1.ConditionFalse, cfg.Generation,
			reason, err.Error())
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionUnknown, cfg.Generation,
			reason, "skipped: login required")
		return ctrl.Result{RequeueAfter: requeue}
	}
	setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn, metav1.ConditionTrue, cfg.Generation,
		"LoggedIn", "manager-auth login succeeded")

	exists, err := vc.SharedMountExists(ctx, cfg.Spec.Storage.KvMountPath)
	if err != nil {
		if vault.IsForbidden(err) {
			// sys/mounts requires vault-operator-admin policy — distinct from
			// a transient probe failure.
			setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionFalse, cfg.Generation,
				"Forbidden", "operator lacks read access to sys/mounts")
			return ctrl.Result{RequeueAfter: RequeueHealthy}
		}
		reason, requeue := classifyVaultErr(err, "ProbeFailed")
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionFalse, cfg.Generation,
			reason, err.Error())
		return ctrl.Result{RequeueAfter: requeue}
	}
	if !exists {
		setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionFalse, cfg.Generation,
			"NotFound", fmt.Sprintf("KV mount %q does not exist", cfg.Spec.Storage.KvMountPath))
		return ctrl.Result{RequeueAfter: RequeueHealthy}
	}
	setCondition(&cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound, metav1.ConditionTrue, cfg.Generation,
		"Found", fmt.Sprintf("KV mount %q exists", cfg.Spec.Storage.KvMountPath))

	return ctrl.Result{RequeueAfter: RequeueHealthy}
}

// countReferences plain-lists the owning claim type and filters client-side
func (r *VaultConfigReconciler) countReferences(ctx context.Context, name string) (int32, error) {
	var count int32
	switch r.VaultConfigOwner {
	case vaultv1alpha1.OwnerVaultSecretOperator:
		var claims vaultv1alpha1.VaultSecretClaimList
		if err := r.List(ctx, &claims); err != nil {
			return 0, fmt.Errorf("list VaultSecretClaims: %w", err)
		}
		for i := range claims.Items {
			if claims.Items[i].Spec.VaultConfigRef.Name == name {
				count++
			}
		}
		return count, nil
	case vaultv1alpha1.OwnerBucketOperator:
		var claims vaultv1alpha1.S3BucketClaimList
		if err := r.List(ctx, &claims); err != nil {
			return 0, fmt.Errorf("list S3BucketClaims: %w", err)
		}
		for i := range claims.Items {
			if claims.Items[i].Spec.VaultConfigRef.Name == name {
				count++
			}
		}
		return count, nil
	}

	var claims vaultv1alpha1.VaultClaimList
	if err := r.List(ctx, &claims); err != nil {
		return 0, fmt.Errorf("list VaultClaims: %w", err)
	}
	for i := range claims.Items {
		if claims.Items[i].Spec.VaultConfigRef.Name == name {
			count++
		}
	}
	return count, nil
}

func (r *VaultConfigReconciler) updateStatusIfChanged(ctx context.Context, cfg *vaultv1alpha1.VaultConfig, old *vaultv1alpha1.VaultConfigStatus) error {
	if apiequality.Semantic.DeepEqual(old, &cfg.Status) {
		return nil
	}
	base := cfg.DeepCopy()
	base.Status = *old
	return r.Status().Patch(ctx, cfg, client.MergeFrom(base))
}

func (r *VaultConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultConfig{}, builder.WithPredicates(vaultConfigOwnerPredicate(r.VaultConfigOwner)))

	switch r.VaultConfigOwner {
	case vaultv1alpha1.OwnerVaultSecretOperator:
		b = b.Watches(
			&vaultv1alpha1.VaultSecretClaim{},
			handler.EnqueueRequestsFromMapFunc(r.findVaultConfigForSecretClaim),
		)
	case vaultv1alpha1.OwnerBucketOperator:
		b = b.Watches(
			&vaultv1alpha1.S3BucketClaim{},
			handler.EnqueueRequestsFromMapFunc(r.findVaultConfigForBucketClaim),
		)
	default:
		b = b.Watches(
			&vaultv1alpha1.VaultClaim{},
			handler.EnqueueRequestsFromMapFunc(r.findVaultConfigForClaim),
		)
	}

	return b.Named("vaultconfig").Complete(r)
}

func (r *VaultConfigReconciler) findVaultConfigForClaim(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*vaultv1alpha1.VaultClaim)
	if !ok || claim.Spec.VaultConfigRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.VaultConfigRef.Name}}}
}

func ptrTime(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}
