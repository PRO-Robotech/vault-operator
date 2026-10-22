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

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// SecretVaultClient is the subset of *vault.Client consumed by the
// VaultSecretClaim and S3BucketClaim reconcilers — login plus KV-v2
// read/write/delete.
type SecretVaultClient interface {
	EnsureLoggedIn(ctx context.Context) error
	Token() string
	ClearToken()

	ReadKV(ctx context.Context, mount, path string) (map[string]any, bool, error)
	WriteKV(ctx context.Context, mount, path string, data map[string]any) error
	ReadKVVersioned(ctx context.Context, mount, path string) (map[string]any, int, bool, error)
	WriteKVCAS(ctx context.Context, mount, path string, data map[string]any, cas int) error
	KVMetadataExists(ctx context.Context, mount, path string) (bool, error)
	DeleteKVMetadata(ctx context.Context, mount, path string) error
}

var _ SecretVaultClient = (*vault.Client)(nil)

// SecretVaultClientFactory builds a SecretVaultClient for a given VaultConfig.
type SecretVaultClientFactory interface {
	For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (SecretVaultClient, error)
	Invalidate(name string)
}

// buildVaultClient constructs a *vault.Client from a VaultConfig and its
// already loaded CA bundle; shared by both factories.
func buildVaultClient(cfg *vaultv1alpha1.VaultConfig, caBundle []byte, jwtSrc vault.JWTSource, opts VaultClientOptions) (*vault.Client, error) {
	if jwtSrc == nil {
		jwtSrc = vault.NewFileJWTSource("")
	}

	var serverName string
	var insecure bool
	if cfg.Spec.TLS != nil {
		serverName = cfg.Spec.TLS.ServerName
		insecure = cfg.Spec.TLS.InsecureSkipVerify
	}

	return vault.New(vault.Config{
		Address:            cfg.Spec.Address,
		AuthPath:           cfg.Spec.ManagerAuth.MountPath,
		Role:               cfg.Spec.ManagerAuth.Role,
		JWTSource:          jwtSrc,
		Name:               cfg.Name,
		CABundle:           caBundle,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
		Timeout:            opts.Timeout,
		QPS:                opts.QPS,
		Burst:              opts.Burst,
		MaxConnsPerHost:    opts.MaxConnsPerHost,
	})
}

// DefaultSecretVaultClientFactory caches one SecretVaultClient per VaultConfig
// name. With Shared set it hands out the clients of that factory instead: a
// process running a VaultConfig probe and a claim controller on one
// VaultConfig then holds one client and one token, not two.
type DefaultSecretVaultClientFactory struct {
	JWTSource vault.JWTSource
	Options   VaultClientOptions
	Shared    *DefaultVaultClientFactory

	cache clientCache
}

func (f *DefaultSecretVaultClientFactory) For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (SecretVaultClient, error) {
	var vc *vault.Client
	var err error
	if f.Shared != nil {
		vc, err = f.Shared.client(ctx, cli, cfg)
	} else {
		vc, err = f.cache.get(ctx, cli, cfg, f.JWTSource, f.Options)
	}
	if err != nil {
		return nil, err
	}
	return vc, nil
}

func (f *DefaultSecretVaultClientFactory) Invalidate(name string) {
	if f.Shared != nil {
		f.Shared.Invalidate(name)
		return
	}
	f.cache.invalidate(name)
}

// RevokeAll revokes the tokens of the clients this factory cached itself; a
// shared factory's are revoked by their owner.
func (f *DefaultSecretVaultClientFactory) RevokeAll(ctx context.Context) {
	if f.Shared == nil {
		f.cache.revokeAll(ctx)
	}
}
