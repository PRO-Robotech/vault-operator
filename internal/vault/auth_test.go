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

func TestClient_EnableAuthMethod(t *testing.T) {
	fv := newFakeVault(t)
	var seenPath, seenType string
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/sys/auth/") {
			seenPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			var body map[string]string
			_ = json.Unmarshal(b, &body)
			seenType = body["type"]
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.EnableAuthMethod(context.Background(), "kubernetes-ec8a00", EnableAuthRequest{Type: "kubernetes", Description: "per-cluster"}); err != nil {
		t.Fatalf("EnableAuthMethod: %v", err)
	}
	if seenPath != "/v1/sys/auth/kubernetes-ec8a00" {
		t.Fatalf("unexpected path %q", seenPath)
	}
	if seenType != "kubernetes" {
		t.Fatalf("expected type=kubernetes, got %q", seenType)
	}
}

func TestClient_EnableAuthMethod_AlreadyExists(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/sys/auth/") {
			http.Error(w, `{"errors":["path is already in use at kubernetes-ec8a00/"]}`, http.StatusBadRequest)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	err := c.EnableAuthMethod(context.Background(), "kubernetes-ec8a00", EnableAuthRequest{Type: "kubernetes"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !IsBadRequest(err) {
		t.Fatalf("expected BadRequest, got %v", err)
	}
}

func TestClient_DisableAuthMethod_NotFoundIsOK(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/sys/auth/") {
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.DisableAuthMethod(context.Background(), "kubernetes-ec8a00"); err != nil {
		t.Fatalf("DisableAuthMethod should ignore 404, got %v", err)
	}
}

func TestClient_WriteKubernetesAuthConfig(t *testing.T) {
	fv := newFakeVault(t)
	var receivedBody KubernetesAuthConfig
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/auth/kubernetes-ec8a00/config" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &receivedBody)
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	cfg := KubernetesAuthConfig{
		KubernetesHost:    "https://kube.example",
		TokenReviewerJWT:  "reviewer-jwt",
		KubernetesCACert:  "ca-bundle",
		Issuer:            "https://issuer",
		DisableLocalCAJWT: true,
	}
	if err := c.WriteKubernetesAuthConfig(context.Background(), "kubernetes-ec8a00", cfg); err != nil {
		t.Fatalf("WriteKubernetesAuthConfig: %v", err)
	}
	if receivedBody.KubernetesHost != "https://kube.example" {
		t.Fatalf("unexpected host %q", receivedBody.KubernetesHost)
	}
	if receivedBody.TokenReviewerJWT != "reviewer-jwt" {
		t.Fatalf("unexpected jwt %q", receivedBody.TokenReviewerJWT)
	}
	if !receivedBody.DisableLocalCAJWT {
		t.Fatalf("expected disable_local_ca_jwt=true")
	}
}

func TestClient_ListAuthMounts_DataKey(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/auth" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"kubernetes-mgmt/":   map[string]any{"type": "kubernetes", "accessor": "auth_k8s_mgmt"},
					"kubernetes-ec8a00/": map[string]any{"type": "kubernetes", "accessor": "auth_k8s_ec8a00"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	mounts, err := c.ListAuthMounts(context.Background())
	if err != nil {
		t.Fatalf("ListAuthMounts: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts["kubernetes-ec8a00/"].Accessor != "auth_k8s_ec8a00" {
		t.Fatalf("unexpected accessor %q", mounts["kubernetes-ec8a00/"].Accessor)
	}
}

func TestClient_GetAuthMountAccessor(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/auth" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"kubernetes-ec8a00/": map[string]any{"type": "kubernetes", "accessor": "auth_k8s_abc"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	acc, err := c.GetAuthMountAccessor(context.Background(), "kubernetes-ec8a00")
	if err != nil {
		t.Fatalf("GetAuthMountAccessor: %v", err)
	}
	if acc != "auth_k8s_abc" {
		t.Fatalf("unexpected accessor %q", acc)
	}
	// Missing mount.
	_, err = c.GetAuthMountAccessor(context.Background(), "kubernetes-missing")
	if err == nil {
		t.Fatalf("expected error for missing mount")
	}
}

func TestClient_SharedMountExists(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/mounts" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"secret/": map[string]any{"type": "kv-v2"},
					"sys/":    map[string]any{"type": "system"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	ok, err := c.SharedMountExists(context.Background(), "secret")
	if err != nil {
		t.Fatalf("SharedMountExists: %v", err)
	}
	if !ok {
		t.Fatalf("expected secret mount to exist")
	}
	ok, _ = c.SharedMountExists(context.Background(), "nonexistent")
	if ok {
		t.Fatalf("expected nonexistent mount = false")
	}
	// sys/ is not a KV mount, so should report false.
	ok, _ = c.SharedMountExists(context.Background(), "sys")
	if ok {
		t.Fatalf("sys is not a kv mount")
	}
}
