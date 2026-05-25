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
	"net/url"
	"strings"
)

// KubernetesRole is the modelled subset of POST /v1/auth/{mount}/role/{name}.
// TTL fields are wire-level seconds; zero means "use system default".
type KubernetesRole struct {
	BoundServiceAccountNames      []string `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
	TokenPolicies                 []string `json:"token_policies"`
	TokenTTLSeconds               int      `json:"token_ttl"`
	TokenMaxTTLSeconds            int      `json:"token_max_ttl"`
}

func (c *Client) PutKubernetesRole(ctx context.Context, mount, name string, role KubernetesRole) error {
	m := strings.Trim(mount, "/")
	n := strings.Trim(name, "/")
	if m == "" || n == "" {
		return fmt.Errorf("mount or role name is empty")
	}
	if len(role.BoundServiceAccountNames) == 0 || len(role.BoundServiceAccountNamespaces) == 0 {
		return fmt.Errorf("role %q must bind at least one SA name and namespace", name)
	}
	if len(role.TokenPolicies) == 0 {
		return fmt.Errorf("role %q must reference at least one policy", name)
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   "auth/" + m + "/role/" + n,
		Body:   role,
	})
	return err
}

// DeleteKubernetesRole removes a role; NotFound is treated as success.
func (c *Client) DeleteKubernetesRole(ctx context.Context, mount, name string) error {
	m := strings.Trim(mount, "/")
	n := strings.Trim(name, "/")
	if m == "" || n == "" {
		return fmt.Errorf("mount or role name is empty")
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodDelete,
		Path:   "auth/" + m + "/role/" + n,
	})
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// ListKubernetesRoles uses GET ?list=true (over the LIST verb) so we are
// portable through proxies that strip uncommon HTTP methods.
func (c *Client) ListKubernetesRoles(ctx context.Context, mount string) ([]string, error) {
	m := strings.Trim(mount, "/")
	if m == "" {
		return nil, fmt.Errorf("mount path is empty")
	}
	resp, err := c.Do(ctx, &Request{
		Method: http.MethodGet,
		Path:   "auth/" + m + "/role",
		Query:  url.Values{"list": []string{"true"}},
	})
	if err != nil {
		if IsNotFound(err) {
			// Empty list = 404 in Vault.
			return nil, nil
		}
		return nil, err
	}
	var raw struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode auth/%s/role list: %w", m, err)
	}
	return raw.Data.Keys, nil
}
