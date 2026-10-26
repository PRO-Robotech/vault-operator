/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vaultoperator holds the RBAC markers for the vault-operator binary.
// Markers live per binary because controller-gen scopes generation by package.
package vaultoperator

// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs/finalizers,verbs=update
// Secrets: list and watch feed a metadata-only watch (kubeconfig and CA
// bundle changes); bodies are read one by one with get. ConfigMaps hold CA
// bundles and are only read.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
