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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// writeVault makes the KV leaf hold this bucket's credentials. It compares the
// keys with what Vault holds on every pass (repairing an outside edit), writes
// with check-and-set so a concurrent writer of the same leaf is not
// overwritten, and on a destinationPath change removes its own keys from the
// previous leaf.
func (r *S3BucketClaimReconciler) writeVault(ctx context.Context, vc SecretVaultClient, cfg *vaultv1alpha1.VaultConfig, claim *vaultv1alpha1.S3BucketClaim, bucket *cloudmanager.Bucket) (ctrl.Result, bool) {
	logger := log.FromContext(ctx)
	endpoint := s3EndpointForRegion(claim.Spec.Region)
	region := claim.Spec.Region
	if region == "" {
		region = "ru1"
	}
	desired := s3LeafKeys(bucket, endpoint, region)

	mount := cfg.Spec.Storage.KvMountPath
	dest := effectiveS3DestinationPath(claim)
	path := joinPath(claim.Spec.Vault.SecretsPrefix, dest)

	// version is the leaf's current version also when it holds no data (soft
	// deleted): the check-and-set write must name it.
	existing, version, _, err := vc.ReadKVVersioned(ctx, mount, path)
	if err != nil {
		logger.V(1).Info("vault read failed", "err", err.Error())
		return r.keysPending(claim, "ReadFailed", "reading the Vault path failed; retrying", bucketRequeueTransient), false
	}
	if !containsAll(existing, desired) {
		merged := cloneData(existing)
		for k, v := range desired {
			merged[k] = v
		}
		if err := vc.WriteKVCAS(ctx, mount, path, merged, version); err != nil {
			if vault.IsCASMismatch(err) {
				return r.keysPending(claim, "WriteConflict", "the Vault path changed concurrently; re-reading", bucketRequeueRace), false
			}
			logger.V(1).Info("vault write failed", "err", err.Error())
			return r.keysPending(claim, "WriteFailed", "writing the Vault path failed; retrying", bucketRequeueTransient), false
		}
		r.event(claim, corev1.EventTypeNormal, "KeysWritten", fmt.Sprintf("wrote s3 credentials to %s/%s", mount, path))
	}

	if prev := claim.Status.WrittenPath; prev != "" && prev != dest {
		if err := removeOwnS3Keys(ctx, vc, mount, joinPath(claim.Spec.Vault.SecretsPrefix, prev), bucket.Name); err != nil {
			logger.V(1).Info("removing keys from the previous path failed", "err", err.Error())
			return r.keysPending(claim, "CleanupFailed", "removing keys from the previous path failed; retrying", bucketRequeueTransient), false
		}
	}
	claim.Status.WrittenPath = dest
	claim.Status.KeysWrittenHash = ""
	claim.Status.Endpoint = endpoint
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionTrue, claim.Generation,
		"Written", "s3 credentials present in Vault")
	return ctrl.Result{}, true
}

func (r *S3BucketClaimReconciler) keysPending(claim *vaultv1alpha1.S3BucketClaim, reason, msg string, after time.Duration) ctrl.Result {
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionKeysWritten, metav1.ConditionFalse, claim.Generation, reason, msg)
	claim.Status.Phase = vaultv1alpha1.PhasePending
	return ctrl.Result{RequeueAfter: after}
}

// removeOwnS3Keys removes this claim's keys from a leaf, but only when the leaf
// names this claim's bucket: keys there under another bucket name were written
// by someone else. A leaf left empty is deleted with its metadata.
func removeOwnS3Keys(ctx context.Context, vc SecretVaultClient, mount, path, bucketName string) error {
	data, version, exists, err := vc.ReadKVVersioned(ctx, mount, path)
	if err != nil || !exists {
		return err
	}
	if data[s3KeyBucketName] != bucketName {
		return nil
	}
	for _, k := range s3OwnKeys {
		delete(data, k)
	}
	if len(data) == 0 {
		return vc.DeleteKVMetadata(ctx, mount, path)
	}
	return vc.WriteKVCAS(ctx, mount, path, data, version)
}

// s3OwnKeys are the keys this claim writes into its KV leaf (s3LeafKeys);
// everything else in the leaf belongs to someone else and is never touched.
var s3OwnKeys = []string{s3KeyAccessKey, s3KeySecretKey, s3KeyBucketName, s3KeyEndpoint, s3KeyRegion, s3KeyForcePathStyle, s3KeyCname}

const (
	s3KeyAccessKey      = "accessKey"
	s3KeySecretKey      = "secretKey"
	s3KeyBucketName     = "bucketName"
	s3KeyEndpoint       = "endpoint"
	s3KeyRegion         = "region"
	s3KeyForcePathStyle = "s3ForcePathStyle"
	s3KeyCname          = "cname"
)

// s3LeafKeys is what the leaf holds for this bucket; every key is one of
// s3OwnKeys, so Purge and a destinationPath change remove all of them.
func s3LeafKeys(bucket *cloudmanager.Bucket, endpoint, region string) map[string]any {
	keys := map[string]any{
		s3KeyAccessKey:      bucket.AccessKey,
		s3KeySecretKey:      bucket.SecretKey,
		s3KeyBucketName:     bucket.Name,
		s3KeyEndpoint:       endpoint,
		s3KeyRegion:         region,
		s3KeyForcePathStyle: "true",
	}
	if bucket.Cname != "" {
		keys[s3KeyCname] = bucket.Cname
	}
	return keys
}

// containsAll reports whether data already holds every desired key and value.
func containsAll(data, desired map[string]any) bool {
	for k, v := range desired {
		if got, ok := data[k]; !ok || got != v {
			return false
		}
	}
	return true
}
