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

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// IndexVaultConfigRef indexes every claim kind by spec.vaultConfigRef.name,
// so a VaultConfig event reaches its claims through one index lookup instead
// of a scan of every claim.
const IndexVaultConfigRef = "spec.vaultConfigRef.name"

func vaultClaimConfigRef(obj client.Object) string {
	if c, ok := obj.(*vaultv1alpha1.VaultClaim); ok {
		return c.Spec.VaultConfigRef.Name
	}
	return ""
}

func bucketClaimConfigRef(obj client.Object) string {
	if c, ok := obj.(*vaultv1alpha1.S3BucketClaim); ok {
		return c.Spec.VaultConfigRef.Name
	}
	return ""
}

func secretClaimConfigRef(obj client.Object) string {
	if c, ok := obj.(*vaultv1alpha1.VaultSecretClaim); ok {
		return c.Spec.VaultConfigRef.Name
	}
	return ""
}

// configRefIndex is the IndexVaultConfigRef extractor for one claim kind.
func configRefIndex(ref func(client.Object) string) client.IndexerFunc {
	return func(obj client.Object) []string {
		if name := ref(obj); name != "" {
			return []string{name}
		}
		return nil
	}
}

// indexConfigRef registers IndexVaultConfigRef for the claim kind obj. The
// claim controller that fans VaultConfig events out registers it, once per
// manager.
func indexConfigRef(mgr ctrl.Manager, obj client.Object, ref func(client.Object) string) error {
	return mgr.GetFieldIndexer().IndexField(context.Background(), obj, IndexVaultConfigRef, configRefIndex(ref))
}

// vaultConfigFanOutPredicate passes the VaultConfig events a claim acts on:
// creation, deletion, a spec change, and a change of Reachable or
// SharedMountFound, the conditions the claim pipelines read. A probe that
// only refreshed its heartbeat or another condition wakes no claim.
func vaultConfigFanOutPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldCfg, okOld := e.ObjectOld.(*vaultv1alpha1.VaultConfig)
			newCfg, okNew := e.ObjectNew.(*vaultv1alpha1.VaultConfig)
			if !okOld || !okNew || oldCfg.Generation != newCfg.Generation {
				return true
			}
			for _, t := range []string{vaultv1alpha1.ConditionReachable, vaultv1alpha1.ConditionSharedMountFound} {
				if findConditionStatus(oldCfg.Status.Conditions, t) != findConditionStatus(newCfg.Status.Conditions, t) {
					return true
				}
			}
			return false
		},
	}
}

// configRefPredicate passes the claim events that change which VaultConfig
// counts the claim: creation, deletion and a change of the reference. The
// handler maps both the old and the new object of an update.
func configRefPredicate(ref func(client.Object) string) predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return ref(e.ObjectOld) != ref(e.ObjectNew)
		},
	}
}
