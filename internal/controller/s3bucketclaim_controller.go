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
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
	bucketRequeueRemoving       = 15 * time.Second
	bucketRequeueConflict       = time.Minute
	// bucketRequeueSpecError retries a spec error that no event may clear
	// (an edit of the claim requeues it at once anyway).
	bucketRequeueSpecError = 30 * time.Minute
	// State errors (STOPPED, ERROR, no keys, a stuck removal) back off
	// exponentially between these bounds.
	bucketBackoffBase = time.Minute
	bucketBackoffMax  = 30 * time.Minute
	// bucketCreateGrace is how long a create in flight (status.pendingCreate)
	// that cloud-manager does not show yet is waited for before creating again.
	bucketCreateGrace = time.Minute
)

const defaultS3DestinationPath = "backup/s3"

// s3OwnKeys are the keys this claim writes into its KV leaf; everything else in
// the leaf belongs to someone else and is never touched.
var s3OwnKeys = []string{"accessKey", "secretKey", "bucketName", "endpoint", "region", "s3ForcePathStyle", "cname"}

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

	// MaxConcurrentReconciles bounds parallel claims (0 → 1).
	MaxConcurrentReconciles int

	Now func() time.Time

	backoff stepBackoff
}

func (r *S3BucketClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("s3bucketclaim", req.NamespacedName)

	claim := &vaultv1alpha1.S3BucketClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		if apierrors.IsNotFound(err) {
			r.backoff.Reset(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get S3BucketClaim: %w", err)
	}

	if !claim.DeletionTimestamp.IsZero() {
		base := claim.Status.DeepCopy()
		res, err := r.handleDeletion(ctx, claim)
		if statusErr := r.updateStatusIfChanged(ctx, claim, base); statusErr != nil {
			logger.V(1).Info("status update during deletion (will retry)", "err", statusErr.Error())
		}
		return res, err
	}

	if controllerutil.AddFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer) {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	base := claim.Status.DeepCopy()
	result := r.reconcile(ctx, claim, base)
	claim.Status.ObservedGeneration = claim.Generation

	if err := r.updateStatusIfChanged(ctx, claim, base); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}
	return result, nil
}

// reconcile mutates claim.Status; on success it requeues to re-check the keys
// in Vault. base is the last persisted status: persist() advances it.
func (r *S3BucketClaimReconciler) reconcile(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, base *vaultv1alpha1.S3BucketClaimStatus) ctrl.Result {
	vc, cfg, res, ok := r.resolveAndLogin(ctx, claim)
	if !ok {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
			"Pending", "waiting for VaultConfig to become reachable")
		return res
	}
	migrateLegacyBucketStatus(claim)

	others, res, ok := r.checkConflicts(ctx, claim)
	if !ok {
		return res
	}
	if res, ok := r.ensureBucket(ctx, claim, base, others); !ok {
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
	r.backoff.Reset(client.ObjectKeyFromObject(claim))
	return ctrl.Result{RequeueAfter: bucketRequeueDriftRecheck}
}

// migrateLegacyBucketStatus fills what a claim written by an earlier release
// lacks: ownership is read from how the bucket was provisioned back then
// ("Created" → Created, any other reason → Adopted), and the deprecated
// credentials hash is dropped from status.
func migrateLegacyBucketStatus(claim *vaultv1alpha1.S3BucketClaim) {
	if claim.Status.BucketOwnership == "" && claim.Status.BucketName != "" {
		claim.Status.BucketOwnership = vaultv1alpha1.BucketOwnershipAdopted
		if c := apimeta.FindStatusCondition(claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned); c != nil && c.Reason == "Created" {
			claim.Status.BucketOwnership = vaultv1alpha1.BucketOwnershipCreated
		}
	}
	claim.Status.KeysWrittenHash = ""
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

// ensureBucket fixes status.bucketName: an explicitly named bucket is adopted;
// otherwise a live bucket of this login with the derived name is looked up
// first (found with status.pendingCreate set: this claim created it; without:
// Adopted), and only then a create is issued, with pendingCreate persisted
// before the call and the name persisted right after it.
func (r *S3BucketClaimReconciler) ensureBucket(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, base *vaultv1alpha1.S3BucketClaimStatus, others []vaultv1alpha1.S3BucketClaim) (ctrl.Result, bool) {
	if claim.Status.BucketName != "" {
		return ctrl.Result{}, true
	}
	login := claim.Spec.CustomerLogin
	if name := claim.Spec.Bucket.Name; name != "" {
		return r.adoptNamed(ctx, claim, name)
	}

	requestedName := bucketBaseName(login, claim.Spec.ClusterRef.Name)
	pending := claim.Status.PendingCreate
	cands, err := r.Buckets.FindByRequested(ctx, login, requestedName, pending != nil)
	if err != nil {
		log.FromContext(ctx).V(1).Info("cloud-manager findAll failed", "err", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"FindFailed", "cloud-manager lookup failed; retrying")
		return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}
	cands = withoutClaimedBuckets(cands, others, claim)
	switch {
	case len(cands) == 1:
		b := cands[0]
		ownership, reason := vaultv1alpha1.BucketOwnershipAdopted, "Adopted"
		if pending != nil {
			ownership, reason = vaultv1alpha1.BucketOwnershipCreated, "Created"
		}
		claim.Status.BucketName = b.Name
		claim.Status.BucketOwnership = ownership
		claim.Status.PendingCreate = nil
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionTrue, claim.Generation,
			reason, fmt.Sprintf("bucket %q found", b.Name))
		return ctrl.Result{}, true
	case len(cands) > 1:
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "AmbiguousBucket",
			fmt.Sprintf("%d buckets of this login match %q; set spec.bucket.name", len(cands), requestedName)), false
	}

	if pending != nil && r.now().Sub(pending.Since.Time) < bucketCreateGrace {
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"Locating", "create in flight; waiting for the bucket to appear")
		return ctrl.Result{RequeueAfter: bucketRequeueCreating}, false
	}
	return r.createBucket(ctx, claim, base, requestedName)
}

func (r *S3BucketClaimReconciler) adoptNamed(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, name string) (ctrl.Result, bool) {
	b, err := r.Buckets.FindByBucket(ctx, claim.Spec.CustomerLogin, name)
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "BucketNotFound",
			fmt.Sprintf("bucket %q not found for this login", name)), false
	case errors.Is(err, cloudmanager.ErrForeignBucket):
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ForeignBucket",
			fmt.Sprintf("bucket %q belongs to another login", name)), false
	case err != nil:
		log.FromContext(ctx).V(1).Info("cloud-manager findAll failed", "err", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"FindFailed", "cloud-manager lookup failed; retrying")
		return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	case b.CustLogin != claim.Spec.CustomerLogin:
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ForeignBucket",
			fmt.Sprintf("bucket %q does not report this login as its owner", name)), false
	}
	claim.Status.BucketName = b.Name
	claim.Status.BucketOwnership = vaultv1alpha1.BucketOwnershipAdopted
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionTrue, claim.Generation,
		"Adopted", fmt.Sprintf("bucket %q adopted", b.Name))
	return ctrl.Result{}, true
}

func (r *S3BucketClaimReconciler) createBucket(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, base *vaultv1alpha1.S3BucketClaimStatus, requestedName string) (ctrl.Result, bool) {
	logger := log.FromContext(ctx)
	claim.Status.PendingCreate = &vaultv1alpha1.PendingBucketCreate{RequestedName: requestedName, Since: metav1.NewTime(r.now())}
	if err := r.persist(ctx, claim, base); err != nil {
		logger.V(1).Info("persist pendingCreate failed; not creating", "err", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return ctrl.Result{RequeueAfter: bucketRequeueRace}, false
	}

	cfgID := claim.Spec.Bucket.ConfigurationID
	if cfgID == "" {
		cfgID = r.DefaultConfigurationID
	}
	realName, err := r.Buckets.Create(ctx, cloudmanager.CreateInput{
		CustomerLogin:   claim.Spec.CustomerLogin,
		BucketName:      requestedName,
		ConfigurationID: cfgID,
		Region:          claim.Spec.Region,
		DisplayName:     fmt.Sprintf("k8s cluster %s backup", claim.Spec.ClusterRef.Name),
		Public:          claim.Spec.Bucket.Public,
		ManagedBy:       effectiveManagedBy(claim),
	})
	switch {
	case err == nil && realName != "":
		claim.Status.BucketName = realName
		claim.Status.BucketOwnership = vaultv1alpha1.BucketOwnershipCreated
		claim.Status.PendingCreate = nil
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionTrue, claim.Generation,
			"Created", fmt.Sprintf("bucket %q create accepted", realName))
		if err := r.persist(ctx, claim, base); err != nil {
			// pendingCreate stays persisted: the next pass finds the bucket
			// and records it as Created.
			logger.V(1).Info("persist bucketName failed; next pass locates the bucket", "err", err.Error())
		}
		return ctrl.Result{}, true

	case err == nil, errors.Is(err, cloudmanager.ErrBucketNameAlreadyExists):
		claim.Status.Phase = vaultv1alpha1.PhasePending
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"Locating", "bucket create accepted; resolving its name")
		return ctrl.Result{RequeueAfter: bucketRequeueRace}, false

	case errors.Is(err, cloudmanager.ErrConfigurationNotFound):
		claim.Status.PendingCreate = nil
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "ConfigurationMissing",
			fmt.Sprintf("s3 configuration %q not found (create it in cloud-manager)", cfgID)), false

	case errors.Is(err, cloudmanager.ErrInvalidBucketName):
		claim.Status.PendingCreate = nil
		return r.specFail(claim, vaultv1alpha1.ConditionBucketProvisioned, "InvalidBucketName",
			fmt.Sprintf("bucket name %q rejected by cloud-manager", requestedName)), false

	case errors.Is(err, cloudmanager.ErrBucketLimitReached), errors.Is(err, cloudmanager.ErrInsufficientFunds):
		claim.Status.PendingCreate = nil
		reason, msg := "QuotaExceeded", "customer bucket limit reached"
		if errors.Is(err, cloudmanager.ErrInsufficientFunds) {
			reason, msg = "InsufficientFunds", "customer balance is insufficient"
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation, reason, msg)
		r.event(claim, corev1.EventTypeWarning, reason, msg+"; retrying")
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return ctrl.Result{RequeueAfter: bucketRequeueQuota}, false

	default:
		// Unknown outcome (timeout, transport): the bucket may exist, so
		// pendingCreate is kept and the next pass looks it up first.
		logger.V(1).Info("cloud-manager create failed", "err", err.Error())
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned, metav1.ConditionFalse, claim.Generation,
			"CreateFailed", "cloud-manager create failed; retrying")
		r.event(claim, corev1.EventTypeWarning, "CreateFailed", "cloud-manager create failed; retrying")
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}
}

// fetchCreds looks the recorded bucket up by its exact name and validates its
// owner, state and keys.
func (r *S3BucketClaimReconciler) fetchCreds(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (*cloudmanager.Bucket, ctrl.Result, bool) {
	login := claim.Spec.CustomerLogin
	bucket, err := r.Buckets.FindByBucket(ctx, login, claim.Status.BucketName)
	if errors.Is(err, cloudmanager.ErrBucketNotFound) {
		bucket, err = r.healPrePrefixName(ctx, claim)
	}
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		return nil, r.stateFail(claim, vaultv1alpha1.ConditionBucketRunning, "BucketMissing", "fetch",
			fmt.Sprintf("bucket %q is not returned by cloud-manager", claim.Status.BucketName)), false
	case errors.Is(err, cloudmanager.ErrForeignBucket):
		return nil, r.specFail(claim, vaultv1alpha1.ConditionBucketRunning, "ForeignBucket",
			fmt.Sprintf("bucket %q belongs to another login", claim.Status.BucketName)), false
	case err != nil:
		log.FromContext(ctx).V(1).Info("cloud-manager findAll failed", "err", err.Error())
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionFalse, claim.Generation,
			"FindFailed", "cloud-manager lookup failed; retrying")
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return nil, ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}
	if bucket.CustLogin == "" {
		// Existing claims are not failed on an unreported owner (purge and
		// adoption are strict); it is counted so it can be made strict later.
		bucketOwnerUnverifiedCounter.Inc()
		log.FromContext(ctx).Info("cloud-manager did not report the bucket owner", "bucket", bucket.Name)
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
		return nil, r.stateFail(claim, vaultv1alpha1.ConditionBucketRunning, "BadStatus", "fetch",
			fmt.Sprintf("bucket %q in unexpected status %q", bucket.Name, bucket.Status)), false
	}

	if bucket.AccessKey == "" || bucket.SecretKey == "" {
		return nil, r.stateFail(claim, vaultv1alpha1.ConditionBucketRunning, "NoKeys", "fetch",
			fmt.Sprintf("bucket %q RUNNING but credentials are empty", bucket.Name)), false
	}
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning, metav1.ConditionTrue, claim.Generation,
		"Running", "bucket is RUNNING with credentials")
	return bucket, ctrl.Result{}, true
}

// healPrePrefixName repairs a status written before the server prefix was
// known: status.bucketName holds the requested name itself. Only that exact
// shape is repaired, and only here: deletion never searches by name.
func (r *S3BucketClaimReconciler) healPrePrefixName(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (*cloudmanager.Bucket, error) {
	requestedName := bucketBaseName(claim.Spec.CustomerLogin, claim.Spec.ClusterRef.Name)
	if claim.Status.BucketName != requestedName {
		return nil, cloudmanager.ErrBucketNotFound
	}
	cands, err := r.Buckets.FindByRequested(ctx, claim.Spec.CustomerLogin, requestedName, false)
	if err != nil {
		return nil, err
	}
	if len(cands) != 1 {
		return nil, cloudmanager.ErrBucketNotFound
	}
	claim.Status.BucketName = cands[0].Name
	return cands[0], nil
}

func effectiveManagedBy(claim *vaultv1alpha1.S3BucketClaim) string {
	if mb := claim.Spec.Bucket.ManagedBy; mb != "" {
		return mb
	}
	return cloudmanager.ManagedBySystem
}

func effectiveS3DestinationPath(claim *vaultv1alpha1.S3BucketClaim) string {
	if p := claim.Spec.Vault.DestinationPath; p != "" {
		return p
	}
	return defaultS3DestinationPath
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

// specFail marks a terminal spec error: Failed, retried after a long interval
// (an edit of the claim requeues it at once).
func (r *S3BucketClaimReconciler) specFail(claim *vaultv1alpha1.S3BucketClaim, condType, reason, msg string) ctrl.Result {
	r.fail(claim, condType, reason, msg)
	return ctrl.Result{RequeueAfter: bucketRequeueSpecError}
}

// stateFail marks an error of the bucket state: Failed, re-checked with an
// exponential backoff per claim so it recovers on its own.
func (r *S3BucketClaimReconciler) stateFail(claim *vaultv1alpha1.S3BucketClaim, condType, reason, step, msg string) ctrl.Result {
	r.fail(claim, condType, reason, msg)
	return ctrl.Result{RequeueAfter: r.backoff.Next(client.ObjectKeyFromObject(claim), step, bucketBackoffBase, bucketBackoffMax)}
}

// fail marks the claim failed and emits an event.
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

func (r *S3BucketClaimReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *S3BucketClaimReconciler) updateStatusIfChanged(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, old *vaultv1alpha1.S3BucketClaimStatus) error {
	if apiequality.Semantic.DeepEqual(old, &claim.Status) {
		return nil
	}
	base := claim.DeepCopy()
	base.Status = *old
	return r.Status().Patch(ctx, claim, client.MergeFrom(base))
}

// persist patches the status now and, on success, advances base, so the
// final patch of the pass sends only what changed after it.
func (r *S3BucketClaimReconciler) persist(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, base *vaultv1alpha1.S3BucketClaimStatus) error {
	want := claim.Status.DeepCopy()
	if err := r.updateStatusIfChanged(ctx, claim, base); err != nil {
		claim.Status = *want
		return err
	}
	// The patch response overwrites claim with the server object; keep the
	// in-memory status this pass is building.
	claim.Status = *want
	*base = *want.DeepCopy()
	return nil
}

func (r *S3BucketClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.S3BucketClaim{}).
		Watches(
			&vaultv1alpha1.VaultConfig{},
			handler.EnqueueRequestsFromMapFunc(r.findBucketClaimsForVaultConfig),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: max(1, r.MaxConcurrentReconciles)}).
		Named("s3bucketclaim").
		Complete(r)
}
