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
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestClient_WriteKV_BodyShape(t *testing.T) {
	fv := newFakeVault(t)
	var seenPath string
	var seenData map[string]any
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/secret/data/") {
			seenPath = strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			b, _ := io.ReadAll(r.Body)
			var body struct {
				Data map[string]any `json:"data"`
			}
			_ = json.Unmarshal(b, &body)
			seenData = body.Data
			w.WriteHeader(http.StatusOK)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	err := c.WriteKV(context.Background(), "secret", "clusters/ec8a00/argocd", map[string]any{
		"admin.password": "p4ss",
	})
	if err != nil {
		t.Fatalf("WriteKV: %v", err)
	}
	if seenPath != "clusters/ec8a00/argocd" {
		t.Fatalf("path = %q", seenPath)
	}
	if seenData["admin.password"] != "p4ss" {
		t.Fatalf("data = %v", seenData)
	}
}

func TestClient_WriteKV_EmptyDataFails(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.WriteKV(context.Background(), "secret", "x/y", nil); err == nil {
		t.Fatalf("expected error for empty data")
	}
}

func TestClient_ReadKV_RoundTrip(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/system/dex" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     map[string]any{"staticClient": "abc123"},
					"metadata": map[string]any{"version": 4},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	data, ok, err := c.ReadKV(context.Background(), "secret", "system/dex")
	if err != nil {
		t.Fatalf("ReadKV: %v", err)
	}
	if !ok {
		t.Fatalf("expected exists=true")
	}
	if data["staticClient"] != "abc123" {
		t.Fatalf("data = %v", data)
	}
}

func TestClient_ReadKV_NotFound(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	data, ok, err := c.ReadKV(context.Background(), "secret", "system/missing")
	if err != nil {
		t.Fatalf("ReadKV 404 should not error, got %v", err)
	}
	if ok || data != nil {
		t.Fatalf("expected (nil,false), got (%v,%v)", data, ok)
	}
}

func TestClient_KVMetadataExists(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/secret/metadata/clusters/ec8a00/argocd" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	exists, err := c.KVMetadataExists(context.Background(), "secret", "clusters/ec8a00/argocd")
	if err != nil {
		t.Fatalf("KVMetadataExists: %v", err)
	}
	if !exists {
		t.Fatalf("expected exists=true")
	}
	missing, err := c.KVMetadataExists(context.Background(), "secret", "clusters/ec8a00/nope")
	if err != nil {
		t.Fatalf("KVMetadataExists missing: %v", err)
	}
	if missing {
		t.Fatalf("expected exists=false for 404")
	}
}

func TestClient_DeleteKVMetadata_NotFoundIsOK(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.DeleteKVMetadata(context.Background(), "secret", "clusters/ec8a00/gone"); err != nil {
		t.Fatalf("DeleteKVMetadata should swallow 404, got %v", err)
	}
}

func TestClient_ReadKVVersioned_ReturnsTheCurrentVersion(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/clusters/x/s3" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"accessKey":"AK"},"metadata":{"version":7}}}`))
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	data, version, ok, err := c.ReadKVVersioned(context.Background(), "secret", "clusters/x/s3")
	if err != nil || !ok {
		t.Fatalf("ReadKVVersioned: ok=%v err=%v", ok, err)
	}
	if version != 7 || data["accessKey"] != "AK" {
		t.Fatalf("version=%d data=%v", version, data)
	}
	// Twin: an absent leaf is version 0, not an error.
	_, version, ok, err = c.ReadKVVersioned(context.Background(), "secret", "clusters/absent")
	if err != nil || ok || version != 0 {
		t.Fatalf("absent: version=%d ok=%v err=%v", version, ok, err)
	}
}

func TestClient_WriteKVCAS_SendsCASAndClassifiesAMismatch(t *testing.T) {
	fv := newFakeVault(t)
	var seen map[string]any
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/secret/data/") {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &seen)
			opts, _ := seen["options"].(map[string]any)
			if cas, _ := opts["cas"].(float64); cas != 3 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["check-and-set parameter did not match the current version"]}`))
				return true
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"version":4}}`))
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.WriteKVCAS(context.Background(), "secret", "x/y", map[string]any{"k": "v"}, 3); err != nil {
		t.Fatalf("WriteKVCAS: %v", err)
	}
	if d, _ := seen["data"].(map[string]any); d["k"] != "v" {
		t.Fatalf("body data = %v", seen["data"])
	}
	err := c.WriteKVCAS(context.Background(), "secret", "x/y", map[string]any{"k": "v"}, 2)
	if !IsCASMismatch(err) {
		t.Fatalf("stale cas: err=%v, want IsCASMismatch", err)
	}
	// Twin: a different 400 is not a CAS mismatch.
	if IsCASMismatch(&APIError{StatusCode: http.StatusBadRequest, Errors: []string{"invalid path"}}) {
		t.Fatalf("plain 400 classified as CAS mismatch")
	}
}
