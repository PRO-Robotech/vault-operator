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

// PutPolicy writes an ACL policy; an existing policy is overwritten in place.
func (c *Client) PutPolicy(ctx context.Context, name, hcl string) error {
	n := strings.Trim(name, "/")
	if n == "" {
		return fmt.Errorf("policy name is empty")
	}
	if hcl == "" {
		return fmt.Errorf("policy %q HCL body is empty", name)
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodPut,
		Path:   "sys/policies/acl/" + n,
		Body: map[string]string{
			"policy": hcl,
		},
	})
	return err
}

// DeletePolicy removes an ACL policy; NotFound is treated as success.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	n := strings.Trim(name, "/")
	if n == "" {
		return fmt.Errorf("policy name is empty")
	}
	_, err := c.Do(ctx, &Request{
		Method: http.MethodDelete,
		Path:   "sys/policies/acl/" + n,
	})
	if err != nil && IsNotFound(err) {
		return nil
	}
	return err
}

// ListPolicies uses GET ?list=true (the LIST operation) so the operator's
// `list` capability on sys/policies/acl applies — a plain GET is a read.
func (c *Client) ListPolicies(ctx context.Context) ([]string, error) {
	resp, err := c.Do(ctx, &Request{
		Method: http.MethodGet,
		Path:   "sys/policies/acl",
		Query:  url.Values{"list": []string{"true"}},
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode sys/policies/acl: %w", err)
	}
	return raw.Data.Keys, nil
}
