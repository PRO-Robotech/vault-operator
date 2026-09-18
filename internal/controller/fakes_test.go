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
	"net/http"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// fakeVaultClient is a thread-safe stub used by reconciler tests.
//
// Each method returns the value configured on the struct; nil errors mean
// success. The shared SealResp/SharedMountResp allow flipping between sealed,
// uninitialized, unreachable and healthy in one test scenario.
type fakeVaultClient struct {
	mu sync.Mutex

	SealResp        *vault.SealStatus
	SealErr         error
	LoginErr        error
	SharedMountResp bool
	SharedMountErr  error

	// Step 5 + deletion — auth method.
	EnableAuthErr      error
	DisableAuthErr     error
	WriteConfigErr     error
	AccessorResp       string
	AccessorErr        error
	WrittenAuthCfgs    []vault.KubernetesAuthConfig
	EnabledAuthPaths   []string
	DisabledAuthPaths  []string
	ListAuthMountsResp map[string]vault.AuthMountInfo
	ListAuthMountsErr  error

	// Step 6 — policies.
	PutPolicyErr     error
	DeletePolicyErr  error
	ListPoliciesResp []string
	ListPoliciesErr  error
	WrittenPolicies  map[string]string // name -> hcl
	DeletedPolicies  []string

	// Step 7 — roles.
	PutRoleErr    error
	DeleteRoleErr error
	ListRolesResp []string
	ListRolesErr  error
	WrittenRoles  map[string]vault.KubernetesRole
	DeletedRoles  []string

	// Transit. TransitKeys is keyed "mount/name" and doubles as the engine's
	// contents: absent means the read returns NotFound.
	MountExistsResp       map[string]bool
	MountExistsErr        error
	MountExistsArgs       []string
	TransitKeys           map[string]*vault.TransitKey
	ReadTransitKeyErr     error
	CreateTransitKeyErr   error
	UpdateTransitCfgErr   error
	CreatedTransitKeys    map[string]vault.CreateTransitKeyRequest
	UpdatedTransitCfgs    map[string]vault.TransitKeyConfig
	ReadPolicyErr         error
	ReadRoleErr           error
	ReadPolicyCalls       int
	ReadRoleCalls         int
	MountExistsCalls      int
	ReadTransitKeyCalls   int
	CreateTransitKeyCalls int
	UpdateTransitCfgCalls int

	SealCalls           int
	LoginCalls          int
	MountCalls          int
	ClearCalls          int
	EnableAuthCalls     int
	DisableAuthCalls    int
	WriteConfigCalls    int
	AccessorCalls       int
	PutPolicyCalls      int
	ListPoliciesCalls   int
	PutRoleCalls        int
	ListRolesCalls      int
	ListAuthMountsCalls int
	tokenString         string
}

func (f *fakeVaultClient) SealStatus(_ context.Context) (*vault.SealStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.SealCalls++
	if f.SealErr != nil {
		return nil, f.SealErr
	}
	if f.SealResp == nil {
		return &vault.SealStatus{Sealed: false, Initialized: true, Version: "1.17.6"}, nil
	}
	return f.SealResp, nil
}

func (f *fakeVaultClient) Login(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LoginCalls++
	if f.LoginErr != nil {
		return f.LoginErr
	}
	f.tokenString = "stub-token"
	return nil
}

func (f *fakeVaultClient) SharedMountExists(_ context.Context, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.MountCalls++
	return f.SharedMountResp, f.SharedMountErr
}

func (f *fakeVaultClient) Token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenString
}

func (f *fakeVaultClient) ClearToken() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ClearCalls++
	f.tokenString = ""
}

func (f *fakeVaultClient) EnableAuthMethod(_ context.Context, path string, _ vault.EnableAuthRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.EnableAuthCalls++
	if f.EnableAuthErr != nil {
		return f.EnableAuthErr
	}
	f.EnabledAuthPaths = append(f.EnabledAuthPaths, path)
	return nil
}

func (f *fakeVaultClient) DisableAuthMethod(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.DisableAuthCalls++
	if f.DisableAuthErr != nil {
		return f.DisableAuthErr
	}
	f.DisabledAuthPaths = append(f.DisabledAuthPaths, path)
	return nil
}

func (f *fakeVaultClient) WriteKubernetesAuthConfig(_ context.Context, _ string, cfg vault.KubernetesAuthConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.WriteConfigCalls++
	if f.WriteConfigErr != nil {
		return f.WriteConfigErr
	}
	f.WrittenAuthCfgs = append(f.WrittenAuthCfgs, cfg)
	return nil
}

func (f *fakeVaultClient) GetAuthMountAccessor(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.AccessorCalls++
	if f.AccessorErr != nil {
		return "", f.AccessorErr
	}
	return f.AccessorResp, nil
}

func (f *fakeVaultClient) ListAuthMounts(_ context.Context) (map[string]vault.AuthMountInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListAuthMountsCalls++
	if f.ListAuthMountsErr != nil {
		return nil, f.ListAuthMountsErr
	}
	return f.ListAuthMountsResp, nil
}

func (f *fakeVaultClient) PutPolicy(_ context.Context, name, hcl string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PutPolicyCalls++
	if f.PutPolicyErr != nil {
		return f.PutPolicyErr
	}
	if f.WrittenPolicies == nil {
		f.WrittenPolicies = make(map[string]string)
	}
	f.WrittenPolicies[name] = hcl
	return nil
}

func (f *fakeVaultClient) DeletePolicy(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeletePolicyErr != nil {
		return f.DeletePolicyErr
	}
	f.DeletedPolicies = append(f.DeletedPolicies, name)
	return nil
}

func (f *fakeVaultClient) ListPolicies(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListPoliciesCalls++
	if f.ListPoliciesErr != nil {
		return nil, f.ListPoliciesErr
	}
	return f.ListPoliciesResp, nil
}

func (f *fakeVaultClient) PutKubernetesRole(_ context.Context, _, name string, role vault.KubernetesRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PutRoleCalls++
	if f.PutRoleErr != nil {
		return f.PutRoleErr
	}
	if f.WrittenRoles == nil {
		f.WrittenRoles = make(map[string]vault.KubernetesRole)
	}
	f.WrittenRoles[name] = role
	return nil
}

func (f *fakeVaultClient) DeleteKubernetesRole(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeleteRoleErr != nil {
		return f.DeleteRoleErr
	}
	f.DeletedRoles = append(f.DeletedRoles, name)
	return nil
}

func (f *fakeVaultClient) ListKubernetesRoles(_ context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ListRolesCalls++
	if f.ListRolesErr != nil {
		return nil, f.ListRolesErr
	}
	return f.ListRolesResp, nil
}

func (f *fakeVaultClient) ReadPolicy(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ReadPolicyCalls++
	if f.ReadPolicyErr != nil {
		return "", f.ReadPolicyErr
	}
	if hcl, ok := f.WrittenPolicies[name]; ok {
		return hcl, nil
	}
	return "", &vault.APIError{Method: http.MethodGet, Path: "sys/policies/acl/" + name, StatusCode: http.StatusNotFound}
}

func (f *fakeVaultClient) ReadKubernetesRole(_ context.Context, _, name string) (*vault.KubernetesRole, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ReadRoleCalls++
	if f.ReadRoleErr != nil {
		return nil, f.ReadRoleErr
	}
	if role, ok := f.WrittenRoles[name]; ok {
		clone := role
		return &clone, nil
	}
	return nil, &vault.APIError{Method: http.MethodGet, Path: "role/" + name, StatusCode: http.StatusNotFound}
}

func (f *fakeVaultClient) MountExists(_ context.Context, path, typePrefix string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.MountExistsCalls++
	f.MountExistsArgs = append(f.MountExistsArgs, path+":"+typePrefix)
	if f.MountExistsErr != nil {
		return false, f.MountExistsErr
	}
	if resp, ok := f.MountExistsResp[path]; ok {
		return resp, nil
	}
	// Default to "kv mounts exist, everything else does not" so tests that
	// predate Transit keep their old SharedMountExists behaviour.
	if typePrefix == "kv" {
		return f.SharedMountResp, nil
	}
	return false, nil
}

// TransitKeys is the fake's stand-in for the engine: present names decode as
// live keys, absent ones produce the NotFound the real client returns.
func (f *fakeVaultClient) ReadTransitKey(_ context.Context, mount, name string) (*vault.TransitKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ReadTransitKeyCalls++
	if f.ReadTransitKeyErr != nil {
		return nil, f.ReadTransitKeyErr
	}
	key, ok := f.TransitKeys[mount+"/"+name]
	if !ok {
		return nil, &vault.APIError{
			Method:     http.MethodGet,
			Path:       mount + "/keys/" + name,
			StatusCode: http.StatusNotFound,
		}
	}
	clone := *key
	return &clone, nil
}

func (f *fakeVaultClient) CreateTransitKey(_ context.Context, mount, name string, req vault.CreateTransitKeyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CreateTransitKeyCalls++
	if f.CreateTransitKeyErr != nil {
		return f.CreateTransitKeyErr
	}
	if f.TransitKeys == nil {
		f.TransitKeys = map[string]*vault.TransitKey{}
	}
	if f.CreatedTransitKeys == nil {
		f.CreatedTransitKeys = map[string]vault.CreateTransitKeyRequest{}
	}
	f.CreatedTransitKeys[mount+"/"+name] = req
	f.TransitKeys[mount+"/"+name] = &vault.TransitKey{
		Name:                 name,
		Type:                 req.Type,
		Derived:              req.Derived,
		Exportable:           req.Exportable,
		AllowPlaintextBackup: req.AllowPlaintextBackup,
		AutoRotatePeriod:     req.AutoRotatePeriodSecs,
		LatestVersion:        1,
	}
	return nil
}

func (f *fakeVaultClient) UpdateTransitKeyConfig(_ context.Context, mount, name string, cfg vault.TransitKeyConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.UpdateTransitCfgCalls++
	if f.UpdateTransitCfgErr != nil {
		return f.UpdateTransitCfgErr
	}
	if f.UpdatedTransitCfgs == nil {
		f.UpdatedTransitCfgs = map[string]vault.TransitKeyConfig{}
	}
	f.UpdatedTransitCfgs[mount+"/"+name] = cfg
	if key, ok := f.TransitKeys[mount+"/"+name]; ok {
		key.DeletionAllowed = cfg.DeletionAllowed
		key.Exportable = cfg.Exportable
		key.AllowPlaintextBackup = cfg.AllowPlaintextBackup
		key.AutoRotatePeriod = cfg.AutoRotatePeriodSecs
	}
	return nil
}

// fakeVaultFactory always returns the same fakeVaultClient.
type fakeVaultFactory struct {
	Client *fakeVaultClient

	mu          sync.Mutex
	Invalidated []string
}

func (f *fakeVaultFactory) For(_ context.Context, _ client.Client, _ *vaultv1alpha1.VaultConfig) (VaultClient, error) {
	if f.Client == nil {
		return nil, errors.New("fakeVaultFactory.Client not set")
	}
	return f.Client, nil
}

func (f *fakeVaultFactory) Invalidate(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Invalidated = append(f.Invalidated, name)
}
