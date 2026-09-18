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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// TransitKey is the modelled subset of GET /v1/{mount}/keys/{name}.
type TransitKey struct {
	Name                 string
	Type                 string
	Derived              bool
	Exportable           bool
	AllowPlaintextBackup bool
	DeletionAllowed      bool
	AutoRotatePeriod     int
	LatestVersion        int
}

// CreateTransitKeyRequest carries the creation-only parameters.
type CreateTransitKeyRequest struct {
	Type                 string `json:"type,omitempty"`
	Derived              bool   `json:"derived"`
	Exportable           bool   `json:"exportable"`
	AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
	AutoRotatePeriodSecs int    `json:"auto_rotate_period"`
}

// TransitKeyConfig is the updatable part of a key. Exportable and
// AllowPlaintextBackup are one-way: Vault refuses to turn them back off.
type TransitKeyConfig struct {
	DeletionAllowed      bool `json:"deletion_allowed"`
	Exportable           bool `json:"exportable"`
	AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
	AutoRotatePeriodSecs int  `json:"auto_rotate_period"`
}

func transitKeyPath(mount, name string) (string, error) {
	m := strings.Trim(mount, "/")
	n := strings.Trim(name, "/")
	if m == "" || n == "" {
		return "", fmt.Errorf("transit mount or key name is empty")
	}
	return m + "/keys/" + n, nil
}

// ReadTransitKey returns the live key; a missing one is a NotFound error.
func (c *Client) ReadTransitKey(ctx context.Context, mount, name string) (*TransitKey, error) {
	p, err := transitKeyPath(mount, name)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, &Request{
		Method: http.MethodGet,
		Path:   p,
	})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Data struct {
			Name                 string      `json:"name"`
			Type                 string      `json:"type"`
			Derived              bool        `json:"derived"`
			Exportable           bool        `json:"exportable"`
			AllowPlaintextBackup bool        `json:"allow_plaintext_backup"`
			DeletionAllowed      bool        `json:"deletion_allowed"`
			AutoRotatePeriod     json.Number `json:"auto_rotate_period"`
			LatestVersion        json.Number `json:"latest_version"`
		} `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", p, err)
	}
	key := &TransitKey{
		Name:                 raw.Data.Name,
		Type:                 raw.Data.Type,
		Derived:              raw.Data.Derived,
		Exportable:           raw.Data.Exportable,
		AllowPlaintextBackup: raw.Data.AllowPlaintextBackup,
		DeletionAllowed:      raw.Data.DeletionAllowed,
	}
	if raw.Data.AutoRotatePeriod != "" {
		v, convErr := raw.Data.AutoRotatePeriod.Int64()
		if convErr != nil {
			return nil, fmt.Errorf("decode %s auto_rotate_period: %w", p, convErr)
		}
		key.AutoRotatePeriod = int(v)
	}
	// KMS consumers key on latest_version; without it we are not talking to Transit.
	if raw.Data.LatestVersion == "" {
		return nil, fmt.Errorf("%s: response has no latest_version", p)
	}
	v, convErr := raw.Data.LatestVersion.Int64()
	if convErr != nil {
		return nil, fmt.Errorf("decode %s latest_version: %w", p, convErr)
	}
	key.LatestVersion = int(v)
	if key.Name == "" {
		key.Name = strings.Trim(name, "/")
	}
	return key, nil
}

// CreateTransitKey creates a key; Vault is idempotent, callers still read first.
func (c *Client) CreateTransitKey(ctx context.Context, mount, name string, req CreateTransitKeyRequest) error {
	p, err := transitKeyPath(mount, name)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   p,
		Body:   req,
	})
	return err
}

// UpdateTransitKeyConfig writes the mutable half of a key.
func (c *Client) UpdateTransitKeyConfig(ctx context.Context, mount, name string, cfg TransitKeyConfig) error {
	p, err := transitKeyPath(mount, name)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   p + "/config",
		Body:   cfg,
	})
	return err
}
