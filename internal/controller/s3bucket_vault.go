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
	"errors"
	"net/url"
	"path"
	"strings"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

func bucketProviderName(claim *vaultv1alpha1.S3BucketClaim) string {
	if claim.Spec.Bucket.Provider == "" {
		return vaultv1alpha1.S3ProviderInternal
	}
	return claim.Spec.Bucket.Provider
}

func bucketVaultPath(claim *vaultv1alpha1.S3BucketClaim) string {
	destination := claim.Spec.Vault.DestinationPath
	if destination == "" {
		destination = defaultS3DestinationPath
	}
	return joinPath(claim.Spec.Vault.SecretsPrefix, destination)
}

func bucketDestinationAllowed(destination string) bool {
	parsed, err := url.ParseRequestURI("/" + destination)
	if err != nil || parsed.RawQuery != "" {
		return false
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	clean := path.Clean(parsed.Path)
	return clean != "/providers" && !strings.HasPrefix(clean, "/providers/")
}

type bucketVaultResolver func(context.Context) (SecretVaultClient, *vaultv1alpha1.VaultConfig, bool)

func bucketVault(claim *vaultv1alpha1.S3BucketClaim, resolve bucketVaultResolver) bucketprovider.ClaimContext {
	base := "providers/" + bucketProviderName(claim)
	return bucketprovider.ClaimContext{
		UID:     string(claim.UID),
		Profile: claim.Spec.Bucket.ProviderConfigRef,
		Vault: claimVault{
			resolve: resolve, published: bucketVaultPath(claim),
			profiles: base + "/profiles/", state: base + "/state/" + string(claim.UID) + "/",
		},
	}
}

type claimVault struct {
	resolve   bucketVaultResolver
	published string
	profiles  string
	state     string
}

var errBucketVaultUnavailable = errors.New("unable to access Vault")

func (v claimVault) ReadProfile(ctx context.Context, name string) (map[string]any, bool, error) {
	vc, cfg, ok := v.resolve(ctx)
	if !ok {
		return nil, false, errBucketVaultUnavailable
	}
	return vc.ReadKV(ctx, cfg.Spec.Storage.KvMountPath, v.profiles+name)
}

func (v claimVault) ReadPublished(ctx context.Context) (map[string]any, bool, error) {
	vc, cfg, ok := v.resolve(ctx)
	if !ok {
		return nil, false, errBucketVaultUnavailable
	}
	return vc.ReadKV(ctx, cfg.Spec.Storage.KvMountPath, v.published)
}

type bucketStateVault interface {
	ReadKVVersion(context.Context, string, string) (map[string]any, int, error)
	WriteKVCAS(context.Context, string, string, map[string]any, int) error
	KVMetadataExists(context.Context, string, string) (bool, error)
}

func (v claimVault) ReadState(ctx context.Context, key string) (map[string]any, int, error) {
	vc, mount, err := v.stateClient(ctx)
	if err != nil {
		return nil, 0, err
	}
	statePath := v.state + key
	data, version, err := vc.ReadKVVersion(ctx, mount, statePath)
	if err != nil || version != 0 {
		return data, version, err
	}
	found, err := vc.KVMetadataExists(ctx, mount, statePath)
	if found && err == nil {
		return nil, 0, errors.New("state metadata exists without readable data in Vault")
	}
	return nil, 0, err
}

func (v claimVault) WriteState(ctx context.Context, key string, data map[string]any, version int) error {
	vc, mount, err := v.stateClient(ctx)
	if err != nil {
		return err
	}
	return vc.WriteKVCAS(ctx, mount, v.state+key, data, version)
}

func (v claimVault) DeleteState(ctx context.Context, key string) error {
	vc, cfg, ok := v.resolve(ctx)
	if !ok {
		return errBucketVaultUnavailable
	}
	return vc.DeleteKVMetadata(ctx, cfg.Spec.Storage.KvMountPath, v.state+key)
}

func (v claimVault) stateClient(ctx context.Context) (bucketStateVault, string, error) {
	vc, cfg, ok := v.resolve(ctx)
	if !ok {
		return nil, "", errBucketVaultUnavailable
	}
	state, ok := vc.(bucketStateVault)
	if !ok {
		return nil, "", errors.New("versioned state is unsupported by the Vault client")
	}
	return state, cfg.Spec.Storage.KvMountPath, nil
}
