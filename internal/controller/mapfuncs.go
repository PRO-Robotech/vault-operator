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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// kubeconfigSecretSuffix is the naming convention used by certificate-set +
// cluster-claim-operator for the infra kubeconfig Secret.
const kubeconfigSecretSuffix = "-infra-kubeconfig"

func (r *VaultClaimReconciler) findClaimsForVaultConfig(ctx context.Context, obj client.Object) []reconcile.Request {
	cfg, ok := obj.(*vaultv1alpha1.VaultConfig)
	if !ok || cfg.Name == "" {
		return nil
	}
	var claims vaultv1alpha1.VaultClaimList
	if err := r.List(ctx, &claims, client.MatchingFields{IndexVaultConfigRef: cfg.Name}); err != nil {
		log.FromContext(ctx).Error(err, "list VaultClaims for VaultConfig fan-out", "config", cfg.Name)
		return nil
	}
	out := make([]reconcile.Request, 0, len(claims.Items))
	for i := range claims.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&claims.Items[i])})
	}
	return out
}

// findClaimsForSecret maps a kubeconfig Secret to the claims of its namespace
// that read it. The watch holds Secret metadata only, so obj is a
// PartialObjectMetadata there; a typed Secret is accepted as well.
func (r *VaultClaimReconciler) findClaimsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	switch o := obj.(type) {
	case *corev1.Secret:
	case *metav1.PartialObjectMetadata:
		if o.Kind != "" && o.Kind != "Secret" {
			return nil
		}
	default:
		return nil
	}
	var claims vaultv1alpha1.VaultClaimList
	if err := r.List(ctx, &claims, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "list VaultClaims for Secret fan-out", "secret", obj.GetName())
		return nil
	}
	out := make([]reconcile.Request, 0)
	for i := range claims.Items {
		if kubeconfigSecretName(&claims.Items[i]) != obj.GetName() {
			continue
		}
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&claims.Items[i])})
	}
	return out
}

// kubeconfigSecretPredicate filters the Secret watch at the cache layer so it
// only fires on `*-infra-kubeconfig` names. Claims pointing at a custom name
// still get the 5m RequeueClaimKubeconfigWait fallback.
func kubeconfigSecretPredicate() predicate.Predicate {
	matches := func(obj client.Object) bool {
		return obj != nil && strings.HasSuffix(obj.GetName(), kubeconfigSecretSuffix)
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return matches(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return matches(e.ObjectNew) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return matches(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return matches(e.Object) },
	}
}
