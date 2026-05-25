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

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

const IndexVaultConfigRef = "spec.vaultConfigRef.name"

// SetupIndexers must be called once during manager setup, before any
// reconciler starts.
func SetupIndexers(mgr ctrl.Manager) error {
	return mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&vaultv1alpha1.VaultClaim{},
		IndexVaultConfigRef,
		func(obj client.Object) []string {
			claim, ok := obj.(*vaultv1alpha1.VaultClaim)
			if !ok || claim.Spec.VaultConfigRef.Name == "" {
				return nil
			}
			return []string{claim.Spec.VaultConfigRef.Name}
		},
	)
}
