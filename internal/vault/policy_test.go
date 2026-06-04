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
	"sort"
	"strings"
	"testing"
)

func TestClient_PutPolicy_BodyShape(t *testing.T) {
	fv := newFakeVault(t)
	var seenName, seenHCL string
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/") {
			seenName = strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
			b, _ := io.ReadAll(r.Body)
			var body map[string]string
			_ = json.Unmarshal(b, &body)
			seenHCL = body["policy"]
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	hcl := `path "secret/data/clusters/ec8a00/*" { capabilities = ["read"] }`
	if err := c.PutPolicy(context.Background(), "ec8a00-vmauth-reader", hcl); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	if seenName != "ec8a00-vmauth-reader" {
		t.Fatalf("unexpected name %q", seenName)
	}
	if seenHCL != hcl {
		t.Fatalf("unexpected HCL %q", seenHCL)
	}
}

func TestClient_PutPolicy_EmptyHCLFails(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.PutPolicy(context.Background(), "x", ""); err == nil {
		t.Fatalf("expected error for empty HCL")
	}
}

func TestClient_DeletePolicy_NotFoundIsOK(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/") {
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.DeletePolicy(context.Background(), "ec8a00-x"); err != nil {
		t.Fatalf("DeletePolicy should swallow 404, got %v", err)
	}
}

func TestClient_ListPolicies(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/policies/acl" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"keys": []string{"default", "ec8a00-vmauth-reader", "ec8a00-argocd-reader"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	got, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	sort.Strings(got)
	want := []string{"default", "ec8a00-argocd-reader", "ec8a00-vmauth-reader"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("policy[%d]=%q, want %q", i, got[i], w)
		}
	}
}
