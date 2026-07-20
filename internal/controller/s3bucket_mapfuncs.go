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

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// findBucketClaimsForVaultConfig fans a VaultConfig change out to its claims.
func (r *S3BucketClaimReconciler) findBucketClaimsForVaultConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	cfg, ok := obj.(*vaultv1alpha1.VaultConfig)
	if !ok || cfg.Name == "" {
		return nil
	}
	var claims vaultv1alpha1.S3BucketClaimList
	if err := r.List(ctx, &claims); err != nil {
		log.FromContext(ctx).Error(err, "list S3BucketClaims for VaultConfig fan-out", "config", cfg.Name)
		return nil
	}
	out := make([]reconcile.Request, 0, len(claims.Items))
	for i := range claims.Items {
		if claims.Items[i].Spec.VaultConfigRef.Name == cfg.Name {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&claims.Items[i])})
		}
	}
	return out
}

// findVaultConfigForBucketClaim maps an S3BucketClaim to its VaultConfig.
func (r *VaultConfigReconciler) findVaultConfigForBucketClaim(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*vaultv1alpha1.S3BucketClaim)
	if !ok || claim.Spec.VaultConfigRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.VaultConfigRef.Name}}}
}
