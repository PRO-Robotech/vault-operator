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
	"errors"
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
	data, _, ok, err := c.ReadKVVersioned(ctx, mount, path)
	return data, ok, err
}

// kvDataResponse is the body of a KV-v2 data read. Vault sends the same shape
// with 404 for a leaf whose current version is deleted or destroyed: data is
// null, metadata.version is still the current version.
type kvDataResponse struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// ReadKVVersioned is ReadKV plus the current version, for a following
// WriteKVCAS. A leaf without data has ok=false and version 0 only when it has
// no metadata either: after `vault kv delete` or `kv destroy` the current
// version stays, and a check-and-set write must name it.
func (c *Client) ReadKVVersioned(ctx context.Context, mount, path string) (map[string]any, int, bool, error) {
	p, err := kvPath("data", mount, path)
	if err != nil {
		return nil, 0, false, err
	}
	resp, err := c.Do(ctx, &Request{Method: http.MethodGet, Path: p})
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
			return nil, 0, false, err
		}
		// A body that is not this shape (`{"errors":[]}` of a leaf without
		// metadata, or none) reads as version 0: a wrong 0 costs one CAS
		// rejection, never an overwrite.
		var raw kvDataResponse
		_ = json.Unmarshal(apiErr.Body, &raw)
		return nil, raw.Data.Metadata.Version, false, nil
	}
	var raw kvDataResponse
	if err := resp.Decode(&raw); err != nil {
		return nil, 0, false, fmt.Errorf("decode %s: %w", p, err)
	}
	return raw.Data.Data, raw.Data.Metadata.Version, true, nil
}

// WriteKVCAS writes a KV-v2 secret only if its current version is cas (0: the
// leaf must not exist). A concurrent writer makes it fail with an error for
// which IsCASMismatch is true; re-read and retry.
func (c *Client) WriteKVCAS(ctx context.Context, mount, path string, data map[string]any, cas int) error {
	if len(data) == 0 {
		return fmt.Errorf("vault WriteKVCAS: empty data")
	}
	p, err := kvPath("data", mount, path)
	if err != nil {
		return err
	}
	_, err = c.Do(ctx, &Request{
		Method: http.MethodPost,
		Path:   p,
		Body:   map[string]any{"data": data, "options": map[string]any{"cas": cas}},
	})
	return err
}

// IsCASMismatch reports a KV-v2 check-and-set rejection.
func IsCASMismatch(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return false
	}
	for _, e := range apiErr.Errors {
		if strings.Contains(e, "check-and-set parameter did not match") {
			return true
		}
	}
	return false
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
