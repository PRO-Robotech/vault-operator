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
	"reflect"
	"strings"
	"testing"
)

func TestClient_PutKubernetesRole(t *testing.T) {
	fv := newFakeVault(t)
	var receivedPath string
	var received KubernetesRole
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/kubernetes-ec8a00/role/") {
			receivedPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &received)
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	role := KubernetesRole{
		BoundServiceAccountNames:      []string{"vmauth"},
		BoundServiceAccountNamespaces: []string{"monitoring"},
		TokenPolicies:                 []string{"ec8a00-vmauth-reader"},
		TokenTTLSeconds:               3600,
		TokenMaxTTLSeconds:            86400,
	}
	if err := c.PutKubernetesRole(context.Background(), "kubernetes-ec8a00", "vmauth-reader", role); err != nil {
		t.Fatalf("PutKubernetesRole: %v", err)
	}
	if receivedPath != "/v1/auth/kubernetes-ec8a00/role/vmauth-reader" {
		t.Fatalf("unexpected path %q", receivedPath)
	}
	if !reflect.DeepEqual(received.BoundServiceAccountNames, []string{"vmauth"}) {
		t.Fatalf("unexpected names %v", received.BoundServiceAccountNames)
	}
	if received.TokenTTLSeconds != 3600 {
		t.Fatalf("ttl=%d, want 3600", received.TokenTTLSeconds)
	}
}

func TestClient_PutKubernetesRole_Validation(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	missing := KubernetesRole{TokenPolicies: []string{"p"}}
	if err := c.PutKubernetesRole(context.Background(), "m", "r", missing); err == nil {
		t.Fatalf("expected error when bound SA empty")
	}

	noPolicy := KubernetesRole{
		BoundServiceAccountNames:      []string{"vmauth"},
		BoundServiceAccountNamespaces: []string{"monitoring"},
	}
	if err := c.PutKubernetesRole(context.Background(), "m", "r", noPolicy); err == nil {
		t.Fatalf("expected error when no policies")
	}
}

func TestClient_DeleteKubernetesRole_NotFoundIsOK(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.DeleteKubernetesRole(context.Background(), "kubernetes-ec8a00", "missing"); err != nil {
		t.Fatalf("DeleteKubernetesRole should swallow 404, got %v", err)
	}
}

func TestClient_ListKubernetesRoles(t *testing.T) {
	fv := newFakeVault(t)
	var seenQuery string
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/auth/kubernetes-ec8a00/role" {
			seenQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"keys": []string{"vmauth-reader", "argocd-reader"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	got, err := c.ListKubernetesRoles(context.Background(), "kubernetes-ec8a00")
	if err != nil {
		t.Fatalf("ListKubernetesRoles: %v", err)
	}
	if !strings.Contains(seenQuery, "list=true") {
		t.Fatalf("expected list=true in query, got %q", seenQuery)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(got))
	}
}

func TestClient_ListKubernetesRoles_EmptyIs404(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/auth/kubernetes-ec8a00/role" {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	got, err := c.ListKubernetesRoles(context.Background(), "kubernetes-ec8a00")
	if err != nil {
		t.Fatalf("expected nil error on empty role list (404), got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty list, got %v", got)
	}
}
