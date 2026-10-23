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
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// VaultClient is the subset of *vault.Client consumed by reconcilers; tests
// substitute a fake without spinning up an HTTP server.
type VaultClient interface {
	SealStatus(ctx context.Context) (*vault.SealStatus, error)
	// EnsureLoggedIn makes sure the client holds a token; a fresh one costs
	// no request.
	EnsureLoggedIn(ctx context.Context) error
	// LookupSelf asks Vault about the token the client holds.
	LookupSelf(ctx context.Context) error
	SharedMountExists(ctx context.Context, path string) (bool, error)
	MountExists(ctx context.Context, path, typePrefix string) (bool, error)
	Token() string
	ClearToken()

	EnableAuthMethod(ctx context.Context, path string, req vault.EnableAuthRequest) error
	DisableAuthMethod(ctx context.Context, path string) error
	WriteKubernetesAuthConfig(ctx context.Context, mount string, cfg vault.KubernetesAuthConfig) error
	ReadKubernetesAuthConfig(ctx context.Context, mount string) (*vault.KubernetesAuthState, error)
	GetAuthMountAccessor(ctx context.Context, mount string) (string, error)
	ListAuthMounts(ctx context.Context) (map[string]vault.AuthMountInfo, error)
	// ReadAuthMount reads one sys/auth entry; found is false for an absent mount.
	ReadAuthMount(ctx context.Context, mount string) (info vault.AuthMountInfo, found bool, err error)

	PutPolicy(ctx context.Context, name, hcl string) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]string, error)
	ReadPolicy(ctx context.Context, name string) (string, error)

	PutKubernetesRole(ctx context.Context, mount, name string, role vault.KubernetesRole) error
	DeleteKubernetesRole(ctx context.Context, mount, name string) error
	ListKubernetesRoles(ctx context.Context, mount string) ([]string, error)
	ReadKubernetesRole(ctx context.Context, mount, name string) (*vault.KubernetesRole, error)

	ReadTransitKey(ctx context.Context, mount, name string) (*vault.TransitKey, error)
	CreateTransitKey(ctx context.Context, mount, name string, req vault.CreateTransitKeyRequest) error
	UpdateTransitKeyConfig(ctx context.Context, mount, name string, cfg vault.TransitKeyConfig) error
}

var _ VaultClient = (*vault.Client)(nil)

// VaultClientFactory builds a VaultClient for a given VaultConfig and may
// cache it by name/generation.
type VaultClientFactory interface {
	For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (VaultClient, error)
	Invalidate(name string)
}

// caRevalidator is implemented by factories that cache a client per CA
// bundle: the VaultConfig probe has it re-read the bundle, so a rotated CA
// reaches the cached client within one probe interval. An error is the
// probe's to report; the claims keep the client they have.
type caRevalidator interface {
	Revalidate(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) error
}

// VaultClientOptions are applied to every client a factory builds. Zero
// values keep the vault package defaults.
type VaultClientOptions struct {
	Timeout         time.Duration
	QPS             float64
	Burst           int
	MaxConnsPerHost int
}

// DefaultVaultClientFactory caches one VaultClient per VaultConfig name, and
// so one Vault token. A new generation rebuilds the client and revokes the
// old token; a changed CA bundle rebuilds it with the token kept. JWT source
// defaults to the in-cluster projected token mount.
type DefaultVaultClientFactory struct {
	JWTSource vault.JWTSource
	Options   VaultClientOptions

	cache clientCache
}

func (f *DefaultVaultClientFactory) For(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (VaultClient, error) {
	vc, err := f.client(ctx, cli, cfg)
	if err != nil {
		return nil, err
	}
	return vc, nil
}

func (f *DefaultVaultClientFactory) client(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) (*vault.Client, error) {
	return f.cache.get(ctx, cli, cfg, f.JWTSource, f.Options)
}

// Invalidate drops the client of a deleted VaultConfig and revokes its token.
func (f *DefaultVaultClientFactory) Invalidate(name string) { f.cache.invalidate(name) }

// Revalidate re-reads the CA bundle of cfg and, when it changed, rebuilds the
// cached client with the token kept.
func (f *DefaultVaultClientFactory) Revalidate(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) error {
	return f.cache.revalidate(ctx, cli, cfg, f.JWTSource, f.Options)
}

// RevokeAll revokes every cached token. Run once the controllers have stopped.
func (f *DefaultVaultClientFactory) RevokeAll(ctx context.Context) { f.cache.revokeAll(ctx) }

// clientCache holds one *vault.Client per VaultConfig name.
type clientCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	generation int64
	caHash     [sha256.Size]byte
	client     *vault.Client
}

func (c *clientCache) get(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig,
	jwtSrc vault.JWTSource, opts VaultClientOptions) (*vault.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*cacheEntry)
	}
	entry, ok := c.entries[cfg.Name]
	if ok && entry.generation == cfg.Generation {
		return entry.client, nil
	}

	caBundle, err := caBundleOf(ctx, cli, cfg)
	if err != nil {
		return nil, err
	}
	vc, err := buildVaultClient(cfg, caBundle, jwtSrc, opts)
	if err != nil {
		return nil, err
	}
	if ok {
		retire(entry.client)
	}
	c.entries[cfg.Name] = &cacheEntry{generation: cfg.Generation, caHash: sha256.Sum256(caBundle), client: vc}
	return vc, nil
}

// revalidate re-reads the CA bundle of a cached client of the same
// generation. The read runs without the cache lock: claims keep getting the
// client meanwhile.
func (c *clientCache) revalidate(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig,
	jwtSrc vault.JWTSource, opts VaultClientOptions) error {
	c.mu.Lock()
	entry, ok := c.entries[cfg.Name]
	c.mu.Unlock()
	if !ok || entry.generation != cfg.Generation {
		// The next get builds the client from the bundle as it is now.
		return nil
	}
	caBundle, err := caBundleOf(ctx, cli, cfg)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(caBundle)

	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok = c.entries[cfg.Name]
	if !ok || entry.generation != cfg.Generation || entry.caHash == hash {
		return nil
	}
	vc, err := buildVaultClient(cfg, caBundle, jwtSrc, opts)
	if err != nil {
		return err
	}
	// Same Vault, same role, new CA bundle: the token is still good.
	vc.AdoptToken(entry.client)
	c.entries[cfg.Name] = &cacheEntry{generation: cfg.Generation, caHash: hash, client: vc}
	return nil
}

// caBundleOf loads the CA bundle cfg names; nil means the system pool.
func caBundleOf(ctx context.Context, cli client.Client, cfg *vaultv1alpha1.VaultConfig) ([]byte, error) {
	if cfg.Spec.TLS == nil {
		return nil, nil
	}
	bundle, err := loadCABundle(ctx, cli, cfg.Spec.TLS)
	if err != nil {
		return nil, fmt.Errorf("load CA bundle: %w", err)
	}
	return bundle, nil
}

func (c *clientCache) invalidate(name string) {
	c.mu.Lock()
	entry, ok := c.entries[name]
	delete(c.entries, name)
	c.mu.Unlock()
	if ok {
		retire(entry.client)
		vault.ForgetClient(name)
	}
}

func (c *clientCache) revokeAll(ctx context.Context) {
	c.mu.Lock()
	clients := make([]*vault.Client, 0, len(c.entries))
	for _, entry := range c.entries {
		clients = append(clients, entry.client)
	}
	c.mu.Unlock()
	for _, vc := range clients {
		vc.Revoke(ctx)
	}
}

// retireTimeout bounds the revoke of a client that is no longer handed out.
const retireTimeout = 10 * time.Second

// retire revokes the token of a client the cache no longer hands out. It runs
// on its own: the caller holds the cache lock, and a slow Vault must not hold
// every other VaultConfig with it.
func retire(vc *vault.Client) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), retireTimeout)
		defer cancel()
		vc.Revoke(ctx)
	}()
}

// loadCABundle resolves the CA bundle from whichever source the spec selects.
// Returns nil bytes (system CAs) if no source is set.
func loadCABundle(ctx context.Context, cli client.Client, tls *vaultv1alpha1.TLSSpec) ([]byte, error) {
	switch {
	case tls.CABundleSecretRef != nil:
		ref := tls.CABundleSecretRef
		secret := &corev1.Secret{}
		if err := cli.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
			return nil, fmt.Errorf("get secret %s/%s: %w", ref.Namespace, ref.Name, err)
		}
		data, ok := secret.Data[ref.Key]
		if !ok || len(data) == 0 {
			return nil, fmt.Errorf("secret %s/%s has no %q entry", ref.Namespace, ref.Name, ref.Key)
		}
		return data, nil

	case tls.CABundleConfigMapRef != nil:
		ref := tls.CABundleConfigMapRef
		cm := &corev1.ConfigMap{}
		if err := cli.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, cm); err != nil {
			return nil, fmt.Errorf("get configmap %s/%s: %w", ref.Namespace, ref.Name, err)
		}
		data, ok := cm.Data[ref.Key]
		if !ok || data == "" {
			return nil, fmt.Errorf("configmap %s/%s has no %q entry", ref.Namespace, ref.Name, ref.Key)
		}
		return []byte(data), nil

	case tls.CABundleFile != "":
		data, err := os.ReadFile(tls.CABundleFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle file %q: %w", tls.CABundleFile, err)
		}
		return data, nil
	}
	return nil, nil
}
