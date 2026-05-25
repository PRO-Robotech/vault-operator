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
	"net/http"
	"testing"
)

func TestClient_SealStatus_Unsealed(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	ss, err := c.SealStatus(context.Background())
	if err != nil {
		t.Fatalf("SealStatus: %v", err)
	}
	if ss.Sealed {
		t.Fatalf("expected unsealed")
	}
	if !ss.Initialized {
		t.Fatalf("expected initialized")
	}
	if ss.Version != "1.17.6" {
		t.Fatalf("unexpected version %q", ss.Version)
	}
	// SealStatus must not trigger login (it's AuthOptional).
	if fv.loginCalls.Load() != 0 {
		t.Fatalf("SealStatus should not require login, got %d login calls", fv.loginCalls.Load())
	}
}

func TestClient_SealStatus_Sealed(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathSealStatus {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sealed":      true,
				"initialized": true,
				"version":     "1.17.6",
				"t":           3,
				"n":           5,
				"progress":    1,
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	ss, err := c.SealStatus(context.Background())
	if err != nil {
		t.Fatalf("SealStatus: %v", err)
	}
	if !ss.Sealed {
		t.Fatalf("expected sealed=true")
	}
	if ss.Progress != 1 {
		t.Fatalf("expected progress=1, got %d", ss.Progress)
	}
}

func TestClient_SealStatus_Uninitialized(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathSealStatus {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sealed":      true,
				"initialized": false,
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	ss, err := c.SealStatus(context.Background())
	if err != nil {
		t.Fatalf("SealStatus: %v", err)
	}
	if ss.Initialized {
		t.Fatalf("expected initialized=false")
	}
}
