/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vaultsecret holds the RBAC markers for the vault-secret-manager binary.
// Markers live per binary because controller-gen scopes generation by package.
package vaultsecret

// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultsecretclaims,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultsecretclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultsecretclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
