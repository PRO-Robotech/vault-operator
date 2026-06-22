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
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// ownerMatches reports whether a VaultConfig with the given owner label belongs
// to a reconciler configured for reconcilerOwner. A label-less config belongs to
// vault-operator for backwards compatibility.
func ownerMatches(label, reconcilerOwner string) bool {
	if reconcilerOwner == vaultv1alpha1.OwnerVaultSecretOperator {
		return label == vaultv1alpha1.OwnerVaultSecretOperator
	}
	return label == "" || label == vaultv1alpha1.OwnerVaultOperator
}

// vaultConfigOwnerPredicate filters the VaultConfig watch at the cache layer to
// configs this reconciler owns.
func vaultConfigOwnerPredicate(owner string) predicate.Predicate {
	matches := func(obj client.Object) bool {
		return obj != nil && ownerMatches(obj.GetLabels()[vaultv1alpha1.LabelVaultConfigOwner], owner)
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return matches(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return matches(e.ObjectNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return matches(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return matches(e.Object) },
	}
}

// findSecretClaimsForVaultConfig fans a VaultConfig change out to the
// VaultSecretClaims that reference it.
func (r *VaultSecretClaimReconciler) findSecretClaimsForVaultConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	cfg, ok := obj.(*vaultv1alpha1.VaultConfig)
	if !ok || cfg.Name == "" {
		return nil
	}
	var claims vaultv1alpha1.VaultSecretClaimList
	if err := r.List(ctx, &claims); err != nil {
		log.FromContext(ctx).Error(err, "list VaultSecretClaims for VaultConfig fan-out", "config", cfg.Name)
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

// findVaultConfigForSecretClaim maps a VaultSecretClaim to its VaultConfig.
func (r *VaultConfigReconciler) findVaultConfigForSecretClaim(_ context.Context, obj client.Object) []reconcile.Request {
	claim, ok := obj.(*vaultv1alpha1.VaultSecretClaim)
	if !ok || claim.Spec.VaultConfigRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: claim.Spec.VaultConfigRef.Name}}}
}
