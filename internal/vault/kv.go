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

// kvPath validates and builds a KV-v2 path {mount}/{kind}/{path}, where kind is
// "data" (values) or "metadata".
func kvPath(kind, mount, path string) (string, error) {
	mount, path = strings.Trim(mount, "/"), strings.Trim(path, "/")
	if mount == "" || path == "" {
		return "", fmt.Errorf("vault: mount and path are required")
	}
	return mount + "/" + kind + "/" + path, nil
}

// ReadKV reads a KV-v2 secret. A missing secret returns (nil, false, nil); the
// returned map is the inner data.data payload (the actual key/value pairs).
func (c *Client) ReadKV(ctx context.Context, mount, path string) (map[string]any, bool, error) {
	data, _, found, err := c.readKV(ctx, mount, path)
	return data, found, err
}

// ReadKVVersion returns version zero for a missing secret.
func (c *Client) ReadKVVersion(ctx context.Context, mount, path string) (map[string]any, int, error) {
	data, version, found, err := c.readKV(ctx, mount, path)
	if found && (version <= 0 || data == nil) {
		return nil, 0, fmt.Errorf("invalid KV state returned by Vault")
	}
	return data, version, err
}

func (c *Client) readKV(ctx context.Context, mount, path string) (map[string]any, int, bool, error) {
	p, err := kvPath("data", mount, path)
	if err != nil {
		return nil, 0, false, err
	}
	resp, err := c.Do(ctx, &Request{Method: http.MethodGet, Path: p})
	if err != nil {
		if IsNotFound(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	var raw struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := resp.Decode(&raw); err != nil {
		return nil, 0, false, fmt.Errorf("decode %s: %w", p, err)
	}
	return raw.Data.Data, raw.Data.Metadata.Version, true, nil
}

func (c *Client) WriteKVCAS(ctx context.Context, mount, path string, data map[string]any, version int) error {
	p, err := kvPath("data", mount, path)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   p,
		Body:   map[string]any{"data": data, "options": map[string]int{"cas": version}},
	})
	return err
}

// WriteKV writes a KV-v2 secret, creating a new version. data is wrapped in the
// required {"data": ...} envelope.
func (c *Client) WriteKV(ctx context.Context, mount, path string, data map[string]any) error {
	if len(data) == 0 {
		return fmt.Errorf("vault WriteKV: empty data")
	}
	p, err := kvPath("data", mount, path)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   p,
		Body:   map[string]any{"data": data},
	})
	return err
}

// KVMetadataExists reports whether a KV-v2 secret exists at path (any version).
func (c *Client) KVMetadataExists(ctx context.Context, mount, path string) (bool, error) {
	p, err := kvPath("metadata", mount, path)
	if err != nil {
		return false, err
	}
	_, err = c.Do(ctx, &Request{Method: http.MethodGet, Path: p})
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteKVMetadata removes a KV-v2 secret and all its versions (deletionPolicy
// Purge). NotFound is treated as success.
func (c *Client) DeleteKVMetadata(ctx context.Context, mount, path string) error {
	p, err := kvPath("metadata", mount, path)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{Method: http.MethodDelete, Path: p})
	if IsNotFound(err) {
		return nil
	}
	return err
}
