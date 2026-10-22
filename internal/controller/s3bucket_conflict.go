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
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

// checkConflicts enforces one owner per bucket identity across all claims:
// the same (customerLogin, clusterRef.name) — which derives the bucket name —,
// the same KV leaf, or the same bucket name. The oldest claim (by
// creationTimestamp, then namespace/name) keeps it; a younger one is Failed with
// Conflict and does nothing. It returns the other claims for later checks.
func (r *S3BucketClaimReconciler) checkConflicts(ctx context.Context, claim *vaultv1alpha1.S3BucketClaim) ([]vaultv1alpha1.S3BucketClaim, ctrl.Result, bool) {
	var list vaultv1alpha1.S3BucketClaimList
	if err := r.List(ctx, &list); err != nil {
		log.FromContext(ctx).V(1).Info("list S3BucketClaims failed", "err", err.Error())
		claim.Status.Phase = vaultv1alpha1.PhasePending
		return nil, ctrl.Result{RequeueAfter: bucketRequeueTransient}, false
	}
	others := make([]vaultv1alpha1.S3BucketClaim, 0, len(list.Items))
	for i := range list.Items {
		o := &list.Items[i]
		if o.UID == claim.UID {
			continue
		}
		others = append(others, *o)
		what := sharedBucketIdentity(claim, o)
		if what == "" || !olderClaim(o, claim) {
			continue
		}
		msg := fmt.Sprintf("%s is already claimed by %s/%s", what, o.Namespace, o.Name)
		r.fail(claim, vaultv1alpha1.ConditionReady, "Conflict", msg)
		return nil, ctrl.Result{RequeueAfter: bucketRequeueConflict}, false
	}
	return others, ctrl.Result{}, true
}

func sharedBucketIdentity(a, b *vaultv1alpha1.S3BucketClaim) string {
	switch {
	case a.Spec.CustomerLogin == b.Spec.CustomerLogin && a.Spec.ClusterRef.Name == b.Spec.ClusterRef.Name:
		return fmt.Sprintf("bucket identity (login, cluster %q)", a.Spec.ClusterRef.Name)
	case a.Spec.VaultConfigRef.Name == b.Spec.VaultConfigRef.Name &&
		joinPath(a.Spec.Vault.SecretsPrefix, effectiveS3DestinationPath(a)) == joinPath(b.Spec.Vault.SecretsPrefix, effectiveS3DestinationPath(b)):
		return fmt.Sprintf("Vault path %q", joinPath(a.Spec.Vault.SecretsPrefix, effectiveS3DestinationPath(a)))
	}
	for _, n := range []string{a.Spec.Bucket.Name, a.Status.BucketName} {
		if n != "" && (n == b.Spec.Bucket.Name || n == b.Status.BucketName) {
			return fmt.Sprintf("bucket %q", n)
		}
	}
	return ""
}

func olderClaim(a, b *vaultv1alpha1.S3BucketClaim) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
}

// withoutClaimedBuckets drops candidates another claim already records, or
// whose name is the derived name of another claim of the same login (a
// "-N"-suffixed candidate can otherwise be a neighbour cluster "<name>-N").
func withoutClaimedBuckets(cands []*cloudmanager.Bucket, others []vaultv1alpha1.S3BucketClaim, login string) []*cloudmanager.Bucket {
	out := cands[:0:0]
	for _, c := range cands {
		if !claimedElsewhere(c.Name, others, login) {
			out = append(out, c)
		}
	}
	return out
}

func claimedElsewhere(name string, others []vaultv1alpha1.S3BucketClaim, login string) bool {
	for i := range others {
		o := &others[i]
		if o.Status.BucketName == name || o.Spec.Bucket.Name == name {
			return true
		}
		if o.Spec.CustomerLogin != login {
			continue
		}
		if i := strings.IndexByte(name, '-'); i >= 0 && name[i+1:] == bucketBaseName(o.Spec.CustomerLogin, o.Spec.ClusterRef.Name) {
			return true
		}
	}
	return false
}
