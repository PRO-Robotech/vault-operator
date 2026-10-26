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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

func (r *S3BucketClaimReconciler) handleDeletion(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer) {
		return ctrl.Result{}, nil
	}
	claim.Status.Phase = vaultv1alpha1.PhaseDeleting
	migrateLegacyBucketStatus(claim)

	if claim.Spec.DeletionPolicy == vaultv1alpha1.DeletionPolicyPurge {
		if res, done := r.purge(ctx, claim); !done {
			return res, nil
		}
	}

	controllerutil.RemoveFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)
	if err := r.Update(ctx, claim); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	r.backoff.Reset(client.ObjectKeyFromObject(claim))
	return ctrl.Result{}, nil
}

// purge removes the recorded bucket, only when it is provably this claim's,
// waits for cloud-manager to report it REMOVED, and then removes this claim's
// own keys from its KV leaf. The bucket is addressed by status.bucketName
// only: an unrecorded bucket is never searched for by name and removed.
func (r *S3BucketClaimReconciler) purge(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) (ctrl.Result, bool) {
	name := claim.Status.BucketName
	if name == "" {
		if claim.Status.PendingCreate != nil {
			r.event(claim, corev1.EventTypeWarning, "BucketNotRecorded",
				"a create was in flight and no bucket name was recorded; no bucket is removed")
		}
		return ctrl.Result{}, true
	}
	if res, done := r.purgeBucket(ctx, claim, name); !done {
		return res, false
	}

	vc, cfg, ok := r.clientForDeletion(ctx, claim)
	if !ok {
		return r.deletionStuck(claim, "Vault unavailable for purge; retrying"), false
	}
	path := joinPath(claim.Spec.Vault.SecretsPrefix, writtenOrSpecPath(claim))
	if err := removeOwnS3Keys(ctx, vc, cfg.Spec.Storage.KvMountPath, path, name); err != nil {
		log.FromContext(ctx).V(1).Info("removing keys on purge failed", "err", err.Error())
		return r.deletionStuck(claim, "removing the keys from Vault failed; retrying"), false
	}
	return ctrl.Result{}, true
}

func (r *S3BucketClaimReconciler) purgeBucket(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, name string) (ctrl.Result, bool) {
	login := claim.Spec.CustomerLogin
	b, err := r.Buckets.FindByBucket(ctx, login, name)
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		// cloud-manager keeps REMOVED rows, so absent means it never existed.
		return ctrl.Result{}, true
	case errors.Is(err, cloudmanager.ErrForeignBucket):
		return r.deletionBlocked(claim, fmt.Sprintf("bucket %q belongs to another login; not removed", name)), false
	case err != nil:
		log.FromContext(ctx).V(1).Info("cloud-manager findAll failed", "err", err.Error())
		return r.deletionStuck(claim, "cloud-manager lookup failed; retrying"), false
	case b.CustLogin != login:
		return r.deletionBlocked(claim, fmt.Sprintf("bucket %q does not report this login as its owner; not removed", name)), false
	case b.ManagedBy != effectiveManagedBy(claim):
		return r.deletionBlocked(claim, fmt.Sprintf("bucket %q is managed by %s, the claim says %s; not removed", name, b.ManagedBy, effectiveManagedBy(claim))), false
	}
	switch own := claim.Status.BucketOwnership; {
	case own == vaultv1alpha1.BucketOwnershipCreated:
	case own == vaultv1alpha1.BucketOwnershipAdopted && claim.Spec.Bucket.PurgeAdopted:
	default:
		return r.deletionBlocked(claim, fmt.Sprintf("bucket %q was adopted, not created by this claim; set spec.bucket.purgeAdopted or deletionPolicy Retain", name)), false
	}

	switch b.Status {
	case cloudmanager.StatusRemoved:
		return ctrl.Result{}, true
	case cloudmanager.StatusRemoving:
		return r.bucketRemoving(claim, name), false
	case cloudmanager.StatusError:
		return r.deletionStuck(claim, fmt.Sprintf("bucket %q is in ERROR; waiting for cloud-manager", name)), false
	}
	switch holder, err := r.bucketHolder(ctx, claim, name); {
	case err != nil:
		log.FromContext(ctx).V(1).Info("list S3BucketClaims failed", "err", err.Error())
		return r.deletionStuck(claim, "listing S3BucketClaims failed; retrying"), false
	case holder != "":
		res := r.deletionBlocked(claim, fmt.Sprintf("bucket %q is held by claim %s; not removed while it holds the name", name, holder))
		// Держание снимает не правка этой заявки, а снятие или правка соседа:
		// пересчёт идёт с шагом проверки единственности, а не ошибки spec.
		res.RequeueAfter = bucketRequeueConflict
		return res, false
	}
	switch err := r.Buckets.Remove(ctx, name); {
	case err == nil:
		r.event(claim, corev1.EventTypeNormal, "BucketRemoving", fmt.Sprintf("removal of bucket %q requested", name))
		return r.bucketRemoving(claim, name), false
	case errors.Is(err, cloudmanager.ErrAlreadyRemoved), errors.Is(err, cloudmanager.ErrBucketNotFound):
		return ctrl.Result{}, true
	default:
		log.FromContext(ctx).V(1).Info("cloud-manager removeBucket failed", "err", err.Error())
		return r.deletionStuck(claim, fmt.Sprintf("removal of bucket %q failed; retrying", name)), false
	}
}

// bucketHolder называет другую живую (без deletionTimestamp) заявку любого
// пространства имён, у которой то же имя бакета записано в status.bucketName или
// задано в spec.bucket.name; пустая строка — такой заявки нет. Одно имя может
// оказаться у двух заявок: ответ create записывается после того, как сосед
// успел принять тот же бакет. Снимаемая соседом заявка не держит: её Purge
// снимает тот же бакет, Retain отпускает финализатор сразу.
func (r *S3BucketClaimReconciler) bucketHolder(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim, name string) (string, error) {
	var list vaultv1alpha1.S3BucketClaimList
	if err := r.List(ctx, &list); err != nil {
		return "", err
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID == claim.UID || !o.DeletionTimestamp.IsZero() {
			continue
		}
		if o.Status.BucketName == name || o.Spec.Bucket.Name == name {
			return o.Namespace + "/" + o.Name, nil
		}
	}
	return "", nil
}

func (r *S3BucketClaimReconciler) bucketRemoving(claim *vaultv1alpha1.S3BucketClaim, name string) ctrl.Result {
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation,
		"BucketRemoving", fmt.Sprintf("waiting for bucket %q to be REMOVED", name))
	return ctrl.Result{RequeueAfter: bucketRequeueRemoving}
}

// deletionBlocked holds the finalizer: removing the bucket would remove one
// that is not provably this claim's. An edit of the claim re-evaluates at once.
func (r *S3BucketClaimReconciler) deletionBlocked(claim *vaultv1alpha1.S3BucketClaim, msg string) ctrl.Result {
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation, "DeletionBlocked", msg)
	r.event(claim, corev1.EventTypeWarning, "DeletionBlocked", msg)
	return ctrl.Result{RequeueAfter: bucketRequeueSpecError}
}

func (r *S3BucketClaimReconciler) deletionStuck(claim *vaultv1alpha1.S3BucketClaim, msg string) ctrl.Result {
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionReady, metav1.ConditionFalse, claim.Generation, "DeletionStuck", msg)
	r.event(claim, corev1.EventTypeWarning, "DeletionStuck", msg)
	return ctrl.Result{RequeueAfter: r.backoff.Next(client.ObjectKeyFromObject(claim), "purge", bucketBackoffBase, bucketBackoffMax)}
}

func writtenOrSpecPath(claim *vaultv1alpha1.S3BucketClaim) string {
	if p := claim.Status.WrittenPath; p != "" {
		return p
	}
	return effectiveS3DestinationPath(claim)
}
