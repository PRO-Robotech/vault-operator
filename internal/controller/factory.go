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
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// VaultClient is the subset of *vault.Client consumed by reconcilers; tests
// substitute a fake without spinning up an HTTP server.
type VaultClient interface {
	SealStatus(ctx context.Context) (*vault.SealStatus, error)
	Login(ctx context.Context) error
	SharedMountExists(ctx context.Context, path string) (bool, error)
	Token() string
	ClearToken()

	EnableAuthMethod(ctx context.Context, path string, req vault.EnableAuthRequest) error
	DisableAuthMethod(ctx context.Context, path string) error
	WriteKubernetesAuthConfig(ctx context.Context, mount string, cfg vault.KubernetesAuthConfig) error
	GetAuthMountAccessor(ctx context.Context, mount string) (string, error)
	ListAuthMounts(ctx context.Context) (map[string]vault.AuthMountInfo, error)

	PutPolicy(ctx context.Context, name, hcl string) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]string, error)

	PutKubernetesRole(ctx context.Context, mount, name string, role vault.KubernetesRole) error
	DeleteKubernetesRole(ctx context.Context, mount, name string) error
	ListKubernetesRoles(ctx context.Context, mount string) ([]string, error)
}

var _ VaultClient = (*vault.Client)(nil)

// VaultClientFactory builds a VaultClient for a given VaultConfig and may
// cache it by name/generation.
type VaultClientFactory interface {
	For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (VaultClient, error)
	Invalidate(name string)
}

// DefaultVaultClientFactory caches one VaultClient per VaultConfig name,
// rebuilding on generation bumps. JWT source defaults to the in-cluster
// projected token mount.
type DefaultVaultClientFactory struct {
	JWTSource vault.JWTSource

	mu      sync.Mutex
	entries map[string]*factoryEntry
}

type factoryEntry struct {
	generation int64
	client     *vault.Client
}

func (f *DefaultVaultClientFactory) For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (VaultClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.entries == nil {
		f.entries = make(map[string]*factoryEntry)
	}

	if entry, ok := f.entries[cfg.Name]; ok && entry.generation == cfg.Generation {
		return entry.client, nil
	}

	jwtSrc := f.JWTSource
	if jwtSrc == nil {
		jwtSrc = vault.NewFileJWTSource("")
	}

	var caBundle []byte
	var serverName string
	if cfg.Spec.TLS != nil {
		serverName = cfg.Spec.TLS.ServerName
		if cfg.Spec.TLS.CABundleRef != nil {
			bundle, err := loadCABundle(ctx, cli, cfg.Spec.TLS.CABundleRef)
			if err != nil {
				return nil, fmt.Errorf("load CA bundle: %w", err)
			}
			caBundle = bundle
		}
	}

	vc, err := vault.New(vault.Config{
		Address:    cfg.Spec.Address,
		AuthPath:   cfg.Spec.ManagerAuth.MountPath,
		Role:       cfg.Spec.ManagerAuth.Role,
		JWTSource:  jwtSrc,
		CABundle:   caBundle,
		ServerName: serverName,
	})
	if err != nil {
		return nil, err
	}

	f.entries[cfg.Name] = &factoryEntry{generation: cfg.Generation, client: vc}
	return vc, nil
}

func (f *DefaultVaultClientFactory) Invalidate(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, name)
}

// loadCABundle reads "ca.crt" from a Secret, falling back to a ConfigMap.
func loadCABundle(ctx context.Context, cli client.Client, ref *vaultv1alpha1.LocalObjectRef) ([]byte, error) {
	const key = "ca.crt"

	secret := &corev1.Secret{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err == nil {
		if data, ok := secret.Data[key]; ok && len(data) > 0 {
			return data, nil
		}
		return nil, fmt.Errorf("secret %s/%s has no %q entry", ref.Namespace, ref.Name, key)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	cm := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, cm); err != nil {
		return nil, fmt.Errorf("get CA bundle from %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	if data, ok := cm.Data[key]; ok && data != "" {
		return []byte(data), nil
	}
	return nil, fmt.Errorf("configmap %s/%s has no %q entry", ref.Namespace, ref.Name, key)
}
