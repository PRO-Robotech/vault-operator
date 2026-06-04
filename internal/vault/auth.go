/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type EnableAuthRequest struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// EnableAuthMethod creates an auth method at sys/auth/{path}. Vault returns
// 400 if the path already exists; callers can check IsBadRequest to treat
// that as "already enabled".
func (c *Client) EnableAuthMethod(ctx context.Context, path string, req EnableAuthRequest) error {
	p := strings.Trim(path, "/")
	if p == "" {
		return fmt.Errorf("auth mount path is empty")
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   "sys/auth/" + p,
		Body:   req,
	})
	return err
}

// DisableAuthMethod deletes an auth method at sys/auth/{path}. Returns nil
// when the path does not exist.
func (c *Client) DisableAuthMethod(ctx context.Context, path string) error {
	p := strings.Trim(path, "/")
	if p == "" {
		return fmt.Errorf("auth mount path is empty")
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodDelete,
		Path:   "sys/auth/" + p,
	})
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// KubernetesAuthConfig is the modelled subset of auth/{mount}/config.
type KubernetesAuthConfig struct {
	KubernetesHost   string `json:"kubernetes_host"`
	KubernetesCACert string `json:"kubernetes_ca_cert,omitempty"`
	TokenReviewerJWT string `json:"token_reviewer_jwt,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	// DisableISSValidation must be true when Issuer is empty.
	DisableISSValidation bool `json:"disable_iss_validation,omitempty"`
	// DisableLocalCAJWT must be true because Vault runs outside the target
	// cluster and the in-pod fallback reads /var/run/secrets which would point
	// at Vault's own cluster.
	DisableLocalCAJWT bool `json:"disable_local_ca_jwt,omitempty"`
}

func (c *Client) WriteKubernetesAuthConfig(ctx context.Context, mount string, cfg KubernetesAuthConfig) error {
	m := strings.Trim(mount, "/")
	if m == "" {
		return fmt.Errorf("mount path is empty")
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   "auth/" + m + "/config",
		Body:   cfg,
	})
	return err
}

type AuthMountInfo struct {
	Type     string `json:"type"`
	Accessor string `json:"accessor"`
}

// ListAuthMounts returns the sys/auth map. Each key is the mount path with a
// trailing slash, e.g. "kubernetes-ec8a00/" — callers strip before comparison.
func (c *Client) ListAuthMounts(ctx context.Context) (map[string]AuthMountInfo, error) {
	resp, err := c.Do(ctx, &Request{
		Method: http.MethodGet,
		Path:   "sys/auth",
	})
	if err != nil {
		return nil, err
	}
	// sys/auth returns the mount map both at top level (legacy) and under "data".
	var raw struct {
		Data map[string]AuthMountInfo `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode sys/auth: %w", err)
	}
	if raw.Data != nil {
		return raw.Data, nil
	}
	var top map[string]AuthMountInfo
	if err := resp.Decode(&top); err != nil {
		return nil, fmt.Errorf("decode sys/auth (top-level): %w", err)
	}
	return top, nil
}

func (c *Client) GetAuthMountAccessor(ctx context.Context, mount string) (string, error) {
	mounts, err := c.ListAuthMounts(ctx)
	if err != nil {
		return "", err
	}
	key := strings.TrimSuffix(strings.Trim(mount, "/"), "/") + "/"
	info, ok := mounts[key]
	if !ok {
		return "", fmt.Errorf("auth mount %q not found", mount)
	}
	if info.Accessor == "" {
		return "", fmt.Errorf("auth mount %q has no accessor", mount)
	}
	return info.Accessor, nil
}

func (c *Client) SharedMountExists(ctx context.Context, path string) (bool, error) {
	resp, err := c.Do(ctx, &Request{
		Method: http.MethodGet,
		Path:   "sys/mounts",
	})
	if err != nil {
		return false, err
	}
	var raw struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return false, fmt.Errorf("decode sys/mounts: %w", err)
	}
	key := strings.TrimSuffix(strings.Trim(path, "/"), "/") + "/"
	info, ok := raw.Data[key]
	if !ok {
		var top map[string]struct {
			Type string `json:"type"`
		}
		if err := resp.Decode(&top); err != nil {
			return false, nil
		}
		info, ok = top[key]
		if !ok {
			return false, nil
		}
	}
	return strings.HasPrefix(info.Type, "kv"), nil
}
