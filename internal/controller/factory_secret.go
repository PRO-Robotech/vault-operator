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

	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// SecretVaultClient is the subset of *vault.Client consumed by the
// VaultSecretClaim reconciler — login plus KV-v2 read/write/delete.
type SecretVaultClient interface {
	Login(ctx context.Context) error
	Token() string
	ClearToken()

	ReadKV(ctx context.Context, mount, path string) (map[string]any, bool, error)
	WriteKV(ctx context.Context, mount, path string, data map[string]any) error
	KVMetadataExists(ctx context.Context, mount, path string) (bool, error)
	DeleteKVMetadata(ctx context.Context, mount, path string) error
}

var _ SecretVaultClient = (*vault.Client)(nil)

// SecretVaultClientFactory builds a SecretVaultClient for a given VaultConfig.
type SecretVaultClientFactory interface {
	For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (SecretVaultClient, error)
	Invalidate(name string)
}

// buildVaultClient constructs a *vault.Client from a VaultConfig; shared by both
// the VaultClient and SecretVaultClient factories.
func buildVaultClient(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig, jwtSrc vault.JWTSource) (*vault.Client, error) {
	if jwtSrc == nil {
		jwtSrc = vault.NewFileJWTSource("")
	}

	var caBundle []byte
	var serverName string
	var insecure bool
	if cfg.Spec.TLS != nil {
		serverName = cfg.Spec.TLS.ServerName
		insecure = cfg.Spec.TLS.InsecureSkipVerify
		bundle, err := loadCABundle(ctx, cli, cfg.Spec.TLS)
		if err != nil {
			return nil, fmt.Errorf("load CA bundle: %w", err)
		}
		caBundle = bundle
	}

	return vault.New(vault.Config{
		Address:            cfg.Spec.Address,
		AuthPath:           cfg.Spec.ManagerAuth.MountPath,
		Role:               cfg.Spec.ManagerAuth.Role,
		JWTSource:          jwtSrc,
		CABundle:           caBundle,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	})
}

// DefaultSecretVaultClientFactory caches one SecretVaultClient per VaultConfig
// name, rebuilding on generation bumps.
type DefaultSecretVaultClientFactory struct {
	JWTSource vault.JWTSource

	mu      sync.Mutex
	entries map[string]*secretFactoryEntry
}

type secretFactoryEntry struct {
	generation int64
	client     *vault.Client
}

func (f *DefaultSecretVaultClientFactory) For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (SecretVaultClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.entries == nil {
		f.entries = make(map[string]*secretFactoryEntry)
	}
	if entry, ok := f.entries[cfg.Name]; ok && entry.generation == cfg.Generation {
		return entry.client, nil
	}

	vc, err := buildVaultClient(ctx, cli, cfg, f.JWTSource)
	if err != nil {
		return nil, err
	}
	f.entries[cfg.Name] = &secretFactoryEntry{generation: cfg.Generation, client: vc}
	return vc, nil
}

func (f *DefaultSecretVaultClientFactory) Invalidate(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, name)
}
