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
	"strconv"
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
	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	bucketRequeueConfigNotReady = time.Minute
	bucketRequeueLoginTransient = 30 * time.Second
	bucketRequeueTransient      = time.Minute
	bucketRequeueDriftRecheck   = 10 * time.Minute
	bucketRequeueDeletionStuck  = time.Minute
)

const defaultS3DestinationPath = "backup/s3"
const bucketDestinationError = "Vault destination must be outside the provider namespace"

// S3BucketClaimReconciler provisions a per-cluster S3 bucket and writes its
// credentials into Vault.
type S3BucketClaimReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	VaultFactory SecretVaultClientFactory
	Providers    map[string]bucketprovider.BucketProvider

	Now func() time.Time
}

func (r *S3BucketClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("s3bucketclaim", req.NamespacedName)

	claim := &vaultv1alpha1.S3BucketClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get S3BucketClaim: %w", err)
	}

	if !claim.DeletionTimestamp.IsZero() {
		oldStatus := claim.Status.DeepCopy()
		res, err := r.handleDeletion(ctx, claim)
		if statusErr := r.updateStatusIfChanged(ctx, claim, oldStatus); statusErr != nil {
			logger.V(1).Info("status update during deletion (will retry)", "err", statusErr.Error())
		}
		return res, err
	}

	if controllerutil.AddFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer) {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	oldStatus := claim.Status.DeepCopy()
	result, err := r.reconcile(ctx, claim)
	claim.Status.ObservedGeneration = claim.Generation

	if err := r.updateStatusIfChanged(ctx, claim, oldStatus); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}
	return result, err
}

// reconcile mutates claim.Status; on success it requeues to re-check for
// external key rotation.
func (r *S3BucketClaimReconciler) reconcile(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, error) {
	if !bucketDestinationAllowed(bucketVaultPath(claim)) {
		r.fail(claim, vaultv1alpha1.ConditionKeysWritten, "VaultDestinationInvalid", bucketDestinationError)
		return ctrl.Result{}, nil
	}
	provider := r.Providers[bucketProviderName(claim)]
	if provider == nil {
		r.fail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ProviderUnavailable", "bucket provider is not configured")
		return ctrl.Result{RequeueAfter: bucketRequeueTransient}, nil
	}
	vc, cfg, res, ok := r.resolveAndLogin(ctx, claim)
	if !ok {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
			"Pending", "waiting for VaultConfig to become reachable")
		return res, nil
	}

	claimVault := bucketVault(claim, func(context.Context) (SecretVaultClient, *vaultv1alpha1.VaultConfig, bool) {
		return vc, cfg, true
	})
	bucket, err := provider.Ensure(ctx, bucketprovider.EnsureRequest{
		Claim:           claimVault,
		BucketName:      claim.Status.BucketName,
		CustomerLogin:   claim.Spec.CustomerLogin,
		ClusterName:     claim.Spec.ClusterRef.Name,
		Region:          claim.Spec.Region,
		ConfigurationID: claim.Spec.Bucket.ConfigurationID,
		ManagedBy:       claim.Spec.Bucket.ManagedBy,
		Public:          claim.Spec.Bucket.Public,
	})
	if bucket.BucketName != "" {
		claim.Status.BucketName = bucket.BucketName
	}
	if bucket.BucketStatus != nil {
		claim.Status.BucketStatus = *bucket.BucketStatus
	}
	r.applyBucketStage(claim, vaultv1alpha1.ConditionBucketProvisioned, bucket.Provisioned)
	r.applyBucketStage(claim, vaultv1alpha1.ConditionBucketRunning, bucket.Running)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure bucket: %w", err)
	}
	if bucket.Connection == nil {
		return ctrl.Result{RequeueAfter: bucket.RetryAfter}, nil
	}

	if res, ok := r.writeVault(ctx, vc, cfg, claim, bucket.Connection, bucket.Published); !ok {
		return res, nil
	}

	if bucket.Running.State == bucketprovider.Pending {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
			bucket.Running.Reason, bucket.Running.Message)
		return ctrl.Result{RequeueAfter: bucket.RetryAfter}, nil
	}

	r.markReady(claim)
	return ctrl.Result{RequeueAfter: bucketRequeueDriftRecheck}, nil
}

// resolveAndLogin resolves the VaultConfig, verifies it is Reachable and
// SharedMountFound, then builds a client and logs in.
func (r *S3BucketClaimReconciler) resolveAndLogin(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (SecretVaultClient, *vaultv1alpha1.VaultConfig, ctrl.Result, bool) {
	configName := claim.Spec.VaultConfigRef.Name
	cfg := &vaultv1alpha1.VaultConfig{}
	if err := r.Get(ctx, client.ObjectKey{Name: configName}, cfg); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"NotFound", fmt.Sprintf("VaultConfig %q not found", configName))
		return nil, nil, ctrl.Result{RequeueAfter: bucketRequeueConfigNotReady}, false
	}

	if !isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionReachable) ||
		!isConditionTrue(cfg.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound) {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionFalse, claim.Generation,
			"VaultUnavailable", fmt.Sprintf("VaultConfig %q not Reachable/SharedMountFound", configName))
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"VaultUnavailable", "skipped: VaultConfig not ready")
		return nil, nil, ctrl.Result{RequeueAfter: bucketRequeueConfigNotReady}, false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionConfigResolved, metav1.ConditionTrue, claim.Generation,
		"Resolved", fmt.Sprintf("VaultConfig %q is Reachable and SharedMountFound", configName))

	if r.VaultFactory == nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"FactoryError", "VaultFactory is not configured")
		return nil, nil, ctrl.Result{RequeueAfter: bucketRequeueLoginTransient}, false
	}
	vc, err := r.VaultFactory.For(ctx, r.Client, cfg)
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			"FactoryError", err.Error())
		return nil, nil, ctrl.Result{RequeueAfter: bucketRequeueLoginTransient}, false
	}
	if err := vc.Login(ctx); err != nil {
		reason := ReasonLoginFailed
		if vault.IsCircuitOpen(err) {
			reason = ReasonCircuitOpen
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionFalse, claim.Generation,
			reason, err.Error())
		return nil, nil, ctrl.Result{RequeueAfter: bucketRequeueLoginTransient}, false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionVaultReachable, metav1.ConditionTrue, claim.Generation,
		"LoggedIn", "Vault login succeeded")
	return vc, cfg, ctrl.Result{}, true
}

func (r *S3BucketClaimReconciler) applyBucketStage(claim *vaultv1alpha1.S3BucketClaim, condition string, stage bucketprovider.Stage) {
	switch stage.State {
	case bucketprovider.Succeeded:
		setCondition(&claim.Status.Conditions, condition, metav1.ConditionTrue, claim.Generation, stage.Reason, stage.Message)
	case bucketprovider.Pending:
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, condition, metav1.ConditionFalse, claim.Generation, stage.Reason, stage.Message)
		if stage.Warning != "" {
			r.event(claim, corev1.EventTypeWarning, stage.Reason, stage.Warning)
		}
	case bucketprovider.Failed:
		r.fail(claim, condition, stage.Reason, stage.Message)
	}
}

// writeVault merges the credentials into the Vault path when they changed.
func (r *S3BucketClaimReconciler) writeVault(ctx context.Context, vc SecretVaultClient, cfg *vaultv1alpha1.VaultConfig, claim *vaultv1alpha1.S3BucketClaim, conn *bucketprovider.Connection, published *bool) (ctrl.Result, bool) {
	hash := sha256Hex(conn.AccessKey, conn.SecretKey, conn.BucketName, conn.Endpoint)
	write := hash != claim.Status.KeysWrittenHash
	if published != nil {
		write = !*published
	}
	if write {
		mount := cfg.Spec.Storage.KvMountPath
		path := bucketVaultPath(claim)

		existing, _, err := vc.ReadKV(ctx, mount, path)
		if err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionFalse, claim.Generation,
				"ReadFailed", err.Error())
			claim.Status.Phase = vaultv1alpha1.PhasePending
			return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
		}
		merged := cloneData(existing)
		merged["accessKey"] = conn.AccessKey
		merged["secretKey"] = conn.SecretKey
		merged["bucketName"] = conn.BucketName
		merged["endpoint"] = conn.Endpoint
		merged["region"] = conn.Region
		merged["s3ForcePathStyle"] = strconv.FormatBool(conn.ForcePathStyle)
		if conn.Cname != "" {
			merged["cname"] = conn.Cname
		}
		if err := vc.WriteKV(ctx, mount, path, merged); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionFalse, claim.Generation,
				"WriteFailed", err.Error())
			claim.Status.Phase = vaultv1alpha1.PhasePending
			return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
		}
		r.event(claim, corev1.EventTypeNormal, "KeysWritten", fmt.Sprintf("wrote s3 credentials to %s/%s", mount, path))
	}
	claim.Status.KeysWrittenHash = hash
	claim.Status.Endpoint = conn.Endpoint
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionTrue, claim.Generation,
		"Written", "s3 credentials present in Vault")
	return ctrl.Result{}, true
}

func (r *S3BucketClaimReconciler) handleDeletion(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer) {
		return ctrl.Result{}, nil
	}
	claim.Status.Phase = vaultv1alpha1.PhaseDeleting

	if claim.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyPurge {
		if res, done := r.purge(ctx, claim); !done {
			return res, nil
		}
	}

	controllerutil.RemoveFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)
	if err := r.Update(ctx, claim); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

// purge removes the bucket and its Vault path, keeping the finalizer and
// requeueing if either backend is unavailable.
func (r *S3BucketClaimReconciler) purge(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, bool) {
	if !bucketDestinationAllowed(bucketVaultPath(claim)) {
		r.event(claim, corev1.EventTypeWarning, "VaultDestinationInvalid", bucketDestinationError)
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	provider := r.Providers[bucketProviderName(claim)]
	if provider == nil {
		r.event(claim, corev1.EventTypeWarning, "ProviderUnavailable", "bucket provider is not configured")
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	var vc SecretVaultClient
	var cfg *vaultv1alpha1.VaultConfig
	resolve := func(ctx context.Context) (SecretVaultClient, *vaultv1alpha1.VaultConfig, bool) {
		if vc == nil {
			var ok bool
			vc, cfg, ok = r.clientForDeletion(ctx, claim)
			if !ok {
				return nil, nil, false
			}
		}
		return vc, cfg, true
	}
	result, err := provider.Delete(ctx, bucketprovider.DeleteRequest{
		Claim:         bucketVault(claim, resolve),
		BucketName:    claim.Status.BucketName,
		CustomerLogin: claim.Spec.CustomerLogin,
		ClusterName:   claim.Spec.ClusterRef.Name,
	})
	if result.BucketName != "" {
		claim.Status.BucketName = result.BucketName
	}
	if err != nil {
		r.event(claim, corev1.EventTypeWarning, "DeletionStuck", fmt.Sprintf("delete bucket: %v", err))
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	if result.WarningReason != "" {
		r.event(claim, corev1.EventTypeWarning, result.WarningReason, result.Warning)
	}
	if !result.Done {
		return ctrl.Result{RequeueAfter: result.RetryAfter}, false
	}

	vc, cfg, ok := resolve(ctx)
	if !ok {
		r.event(claim, corev1.EventTypeWarning, "DeletionStuck", "Vault unavailable for purge; retrying")
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	path := bucketVaultPath(claim)
	if err := vc.DeleteKVMetadata(ctx, cfg.Spec.Storage.KvMountPath, path); err != nil {
		r.event(claim, corev1.EventTypeWarning, "DeletionStuck", fmt.Sprintf("delete Vault path: %v", err))
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	return ctrl.Result{}, true
}

// clientForDeletion resolves a logged-in Vault client for Purge, best effort.
func (r *S3BucketClaimReconciler) clientForDeletion(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (SecretVaultClient, *vaultv1alpha1.VaultConfig, bool) {
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

// fail marks the claim terminally failed and emits an event.
func (r *S3BucketClaimReconciler) fail(claim *vaultv1alpha1.S3BucketClaim, condType, reason, msg string) {
	claim.Status.Phase = vaultv1alpha1.PhaseFailed
	setCondition(&claim.Status.Conditions, condType, metav1.ConditionFalse, claim.Generation, reason, msg)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation, reason, msg)
	r.event(claim, corev1.EventTypeWarning, reason, msg)
}

func (r *S3BucketClaimReconciler) markReady(claim *vaultv1alpha1.S3BucketClaim) {
	claim.Status.Phase = vaultv1alpha1.PhaseReady
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionTrue, claim.Generation,
		"Ready", "bucket provisioned and credentials in Vault")
}

func (r *S3BucketClaimReconciler) event(claim *vaultv1alpha1.S3BucketClaim, eventType, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(claim, eventType, reason, msg)
	}
}

func (r *S3BucketClaimReconciler) updateStatusIfChanged(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, old *vaultv1alpha1.S3BucketClaimStatus) error {
	if apiequality.Semantic.DeepEqual(old, &claim.Status) {
		return nil
	}
	base := claim.DeepCopy()
	base.Status = *old
	return r.Status().Patch(ctx, claim, client.MergeFrom(base))
}

func (r *S3BucketClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.S3BucketClaim{}).
		Watches(
			&vaultv1alpha1.VaultConfig{},
			handler.EnqueueRequestsFromMapFunc(r.findBucketClaimsForVaultConfig),
		).
		Named("s3bucketclaim").
		Complete(r)
}
