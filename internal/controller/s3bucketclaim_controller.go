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
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	bucketRequeueConfigNotReady = time.Minute
	bucketRequeueLoginTransient = 30 * time.Second
	bucketRequeueCreating       = 15 * time.Second
	bucketRequeueRace           = 5 * time.Second
	bucketRequeueQuota          = 5 * time.Minute
	bucketRequeueTransient      = time.Minute
	bucketRequeueDriftRecheck   = 10 * time.Minute
	bucketRequeueDeletionStuck  = time.Minute
)

const defaultS3DestinationPath = "backup/s3"

// S3BucketClaimReconciler provisions a per-cluster S3 bucket and writes its
// credentials into Vault.
type S3BucketClaimReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	VaultFactory SecretVaultClientFactory
	Buckets      cloudmanager.BucketAPI

	// DefaultConfigurationID applies when spec.bucket.configurationId is empty.
	DefaultConfigurationID string

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
	result := r.reconcile(ctx, claim)
	claim.Status.ObservedGeneration = claim.Generation

	if err := r.updateStatusIfChanged(ctx, claim, oldStatus); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}
	return result, nil
}

// reconcile mutates claim.Status; on success it requeues to re-check for
// external key rotation.
func (r *S3BucketClaimReconciler) reconcile(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) ctrl.Result {
	vc, cfg, res, ok := r.resolveAndLogin(ctx, claim)
	if !ok {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
			"Pending", "waiting for VaultConfig to become reachable")
		return res
	}

	if res, ok := r.ensureBucket(ctx, claim); !ok {
		return res
	}

	bucket, res, ok := r.fetchCreds(ctx, claim)
	if !ok {
		return res
	}

	if res, ok := r.writeVault(ctx, vc, cfg, claim, bucket); !ok {
		return res
	}

	r.markReady(claim)
	return ctrl.Result{RequeueAfter: bucketRequeueDriftRecheck}
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

// ensureBucket creates the bucket unless status.bucketName is already set, and
// records the server-assigned real name.
func (r *S3BucketClaimReconciler) ensureBucket(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, bool) {
	if claim.Status.BucketName != "" {
		return ctrl.Result{}, true
	}

	requestedName := bucketBaseName(claim.Spec.CustomerLogin, claim.Spec.ClusterRef.Name)
	cfgID := claim.Spec.Bucket.ConfigurationID
	if cfgID == "" {
		cfgID = r.DefaultConfigurationID
	}
	managedBy := claim.Spec.Bucket.ManagedBy
	if managedBy == "" {
		managedBy = cloudmanager.ManagedBySystem
	}

	realName, err := r.Buckets.Create(ctx, cloudmanager.CreateInput{
		CustomerLogin:   claim.Spec.CustomerLogin,
		BucketName:      requestedName,
		ConfigurationID: cfgID,
		Region:          claim.Spec.Region,
		DisplayName:     fmt.Sprintf("k8s cluster %s backup", claim.Spec.ClusterRef.Name),
		Public:          claim.Spec.Bucket.Public,
		ManagedBy:       managedBy,
	})
	switch {
	case err == nil:
		if realName == "" {
			if b, lerr := r.Buckets.FindByCustomerRequested(ctx, claim.Spec.CustomerLogin, requestedName); lerr == nil {
				realName = b.Name
			}
		}
		if realName == "" {
			claim.Status.Phase = vaultv1alpha1.PhasePending
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
				"Locating", "bucket created; resolving its name")
			return ctrl.Result{RequeueAfter: bucketRequeueRace}, false
		}
		claim.Status.BucketName = realName
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionTrue, claim.Generation,
			"Created", fmt.Sprintf("bucket %q create accepted", realName))
		return ctrl.Result{}, true

	case errors.Is(err, cloudmanager.ErrBucketNameAlreadyExists):
		b, lerr := r.Buckets.FindByCustomerRequested(ctx, claim.Spec.CustomerLogin, requestedName)
		if errors.Is(lerr, cloudmanager.ErrBucketNotFound) {
			claim.Status.Phase = vaultv1alpha1.PhasePending
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
				"Locating", fmt.Sprintf("bucket %q exists; resolving its name", requestedName))
			return ctrl.Result{RequeueAfter: bucketRequeueRace}, false
		}
		if lerr != nil {
			claim.Status.Phase = vaultv1alpha1.PhasePending
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
				"FindFailed", lerr.Error())
			return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
		}
		if b.CustLogin != "" && b.CustLogin != claim.Spec.CustomerLogin {
			return r.fail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ForeignBucket",
				fmt.Sprintf("bucket %q owned by %q, expected %q", b.Name, b.CustLogin, claim.Spec.CustomerLogin)), false
		}
		claim.Status.BucketName = b.Name
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionTrue, claim.Generation,
			"Exists", fmt.Sprintf("bucket %q already exists", b.Name))
		return ctrl.Result{}, true

	case errors.Is(err, cloudmanager.ErrConfigurationNotFound):
		return r.fail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ConfigurationMissing",
			fmt.Sprintf("s3 configuration %q not found (create it in cloud-manager)", cfgID)), false

	case errors.Is(err, cloudmanager.ErrInvalidBucketName):
		return r.fail(claim, vaultv1alpha1.ConditionBucketProvisioned, "InvalidBucketName",
			fmt.Sprintf("bucket name %q rejected: %v", requestedName, err)), false

	case errors.Is(err, cloudmanager.ErrBucketLimitReached):
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"QuotaExceeded", "customer bucket limit reached")
		r.event(claim, corev1.EventTypeWarning, "QuotaExceeded", "customer bucket limit reached; retrying")
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return ctrl.Result{RequeueAfter: bucketRequeueQuota}, false

	default:
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"CreateFailed", err.Error())
		r.event(claim, corev1.EventTypeWarning, "CreateFailed", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}
}

// resolveBucket returns the bucket by its stored real name, falling back to a
// requested-name lookup that repairs status.BucketName (self-heal).
func (r *S3BucketClaimReconciler) resolveBucket(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (*cloudmanager.Bucket, error) {
	if name := claim.Status.BucketName; name != "" {
		b, err := r.Buckets.FindByCustomerBucket(ctx, claim.Spec.CustomerLogin, name)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, cloudmanager.ErrBucketNotFound) {
			return nil, err
		}
	}
	requestedName := bucketBaseName(claim.Spec.CustomerLogin, claim.Spec.ClusterRef.Name)
	b, err := r.Buckets.FindByCustomerRequested(ctx, claim.Spec.CustomerLogin, requestedName)
	if err != nil {
		return nil, err
	}
	claim.Status.BucketName = b.Name
	return b, nil
}

// fetchCreds looks up the bucket and validates ownership and RUNNING state.
func (r *S3BucketClaimReconciler) fetchCreds(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (*cloudmanager.Bucket, ctrl.Result, bool) {
	bucket, err := r.resolveBucket(ctx, claim)
	if errors.Is(err, cloudmanager.ErrBucketNotFound) {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionFalse, claim.Generation,
			"NotVisibleYet", fmt.Sprintf("bucket for %q not yet returned by findAll", claim.Spec.ClusterRef.Name))
		return nil, ctrl.Result{RequeueAfter: bucketRequeueRace}, false
	}
	if err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionFalse, claim.Generation,
			"FindFailed", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return nil, ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}

	if bucket.CustLogin != "" && bucket.CustLogin != claim.Spec.CustomerLogin {
		return nil, r.fail(claim, vaultv1alpha1.ConditionBucketRunning, "ForeignBucket",
			fmt.Sprintf("bucket %q owned by %q, expected %q", bucket.Name, bucket.CustLogin, claim.Spec.CustomerLogin)), false
	}

	claim.Status.BucketStatus = bucket.Status
	switch bucket.Status {
	case cloudmanager.StatusRunning:
		// proceed
	case cloudmanager.StatusCreating:
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionFalse, claim.Generation,
			"Creating", "bucket is still CREATING")
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return nil, ctrl.Result{RequeueAfter: bucketRequeueCreating}, false
	default: // ERROR / REMOVING / REMOVED / STOPPED
		return nil, r.fail(claim, vaultv1alpha1.ConditionBucketRunning, "BadStatus",
			fmt.Sprintf("bucket %q in unexpected status %q", bucket.Name, bucket.Status)), false
	}

	if bucket.AccessKey == "" || bucket.SecretKey == "" {
		return nil, r.fail(claim, vaultv1alpha1.ConditionBucketRunning, "NoKeys",
			fmt.Sprintf("bucket %q RUNNING but credentials are empty", bucket.Name)), false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionTrue, claim.Generation,
		"Running", "bucket is RUNNING with credentials")
	return bucket, ctrl.Result{}, true
}

// writeVault merges the credentials into the Vault path when they changed.
func (r *S3BucketClaimReconciler) writeVault(ctx context.Context, vc SecretVaultClient, cfg *vaultv1alpha1.VaultConfig, claim *vaultv1alpha1.S3BucketClaim, bucket *cloudmanager.Bucket) (ctrl.Result, bool) {
	endpoint := s3EndpointForRegion(claim.Spec.Region)
	region := claim.Spec.Region
	if region == "" {
		region = "ru1"
	}
	hash := sha256Hex(bucket.AccessKey, bucket.SecretKey, bucket.Name, endpoint)

	if hash != claim.Status.KeysWrittenHash {
		mount := cfg.Spec.Storage.KvMountPath
		destPath := claim.Spec.Vault.DestinationPath
		if destPath == "" {
			destPath = defaultS3DestinationPath
		}
		path := joinPath(claim.Spec.Vault.SecretsPrefix, destPath)

		existing, _, err := vc.ReadKV(ctx, mount, path)
		if err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionFalse, claim.Generation,
				"ReadFailed", err.Error())
			claim.Status.Phase = vaultv1alpha1.PhasePending
			return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
		}
		merged := cloneData(existing)
		merged["accessKey"] = bucket.AccessKey
		merged["secretKey"] = bucket.SecretKey
		merged["bucketName"] = bucket.Name
		merged["endpoint"] = endpoint
		merged["region"] = region
		merged["s3ForcePathStyle"] = "true"
		if bucket.Cname != "" {
			merged["cname"] = bucket.Cname
		}
		if err := vc.WriteKV(ctx, mount, path, merged); err != nil {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionFalse, claim.Generation,
				"WriteFailed", err.Error())
			claim.Status.Phase = vaultv1alpha1.PhasePending
			return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
		}
		claim.Status.KeysWrittenHash = hash
		r.event(claim, corev1.EventTypeNormal, "KeysWritten", fmt.Sprintf("wrote s3 credentials to %s/%s", mount, path))
	}
	claim.Status.Endpoint = endpoint
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
	bucket, err := r.resolveBucket(ctx, claim)
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		// already gone
	case err != nil:
		r.event(claim, corev1.EventTypeWarning, "DeletionStuck", fmt.Sprintf("find bucket for purge: %v", err))
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	case bucket.CustLogin != "" && bucket.CustLogin != claim.Spec.CustomerLogin:
		r.event(claim, corev1.EventTypeWarning, "ForeignBucket", fmt.Sprintf("refusing to remove bucket %q owned by %q", bucket.Name, bucket.CustLogin))
	default:
		if err := r.Buckets.Remove(ctx, bucket.Name); err != nil {
			r.event(claim, corev1.EventTypeWarning, "DeletionStuck", fmt.Sprintf("remove bucket: %v", err))
			return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
		}
	}

	vc, cfg, ok := r.clientForDeletion(ctx, claim)
	if !ok {
		r.event(claim, corev1.EventTypeWarning, "DeletionStuck", "Vault unavailable for purge; retrying")
		return ctrl.Result{RequeueAfter: bucketRequeueDeletionStuck}, false
	}
	destPath := claim.Spec.Vault.DestinationPath
	if destPath == "" {
		destPath = defaultS3DestinationPath
	}
	path := joinPath(claim.Spec.Vault.SecretsPrefix, destPath)
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
func (r *S3BucketClaimReconciler) fail(claim *vaultv1alpha1.S3BucketClaim, condType, reason, msg string) ctrl.Result {
	claim.Status.Phase = vaultv1alpha1.PhaseFailed
	setCondition(&claim.Status.Conditions, condType, metav1.ConditionFalse, claim.Generation, reason, msg)
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation, reason, msg)
	r.event(claim, corev1.EventTypeWarning, reason, msg)
	return ctrl.Result{}
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
