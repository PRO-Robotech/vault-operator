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
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Auth-method endpoints.
		{"/v1/auth/kubernetes-mgmt/login", "auth_login"},
		{"auth/kubernetes-ec8a00/login", "auth_login"},
		{"/v1/auth/kubernetes-ec8a00/config", "auth_config"},
		{"/v1/auth/kubernetes-ec8a00/role", "auth_role_list"},
		{"/v1/auth/kubernetes-ec8a00/role/vmauth-reader", "auth_role"},

		// Token self-management.
		{"/v1/auth/token/renew-self", "auth_token_renew"},
		{"/v1/auth/token/lookup-self", "auth_token_lookup"},

		// sys endpoints.
		{"/v1/sys/seal-status", "sys_seal_status"},
		{"/v1/sys/mounts", "sys_mounts"},
		{"/v1/sys/auth", "sys_auth_list"},
		{"/v1/sys/auth/kubernetes-ec8a00", "sys_auth"},
		{"/v1/sys/auth/kubernetes-ec8a00/tune", "sys_auth_tune"},
		{"/v1/sys/policies/acl", "sys_policies_acl_list"},
		{"/v1/sys/policies/acl/ec8a00-vmauth-reader", "sys_policies_acl"},

		// Unknown / other.
		{"/v1/secret/data/clusters/ec8a00/x", PathOther},
		{"", PathOther},
		{"/v1/", PathOther},
		{"/v1/sys/unknown-endpoint", PathOther},
		{"/v1/auth/token/unknown", PathOther},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizePath(tc.in); got != tc.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestResultFromStatusCode(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{200, ResultSuccess},
		{204, ResultSuccess},
		{301, ResultTransportErr}, // 3xx unmapped → treat as transport oddity
		{400, ResultClientError},
		{403, ResultClientError},
		{404, ResultClientError},
		{499, ResultClientError},
		{500, ResultServerError},
		{503, ResultServerError},
		{0, ResultTransportErr},
	}
	for _, tc := range cases {
		if got := resultFromStatusCode(tc.code); got != tc.want {
			t.Errorf("resultFromStatusCode(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestCodeLabel(t *testing.T) {
	cases := map[int]string{
		200: "2xx",
		301: "3xx",
		401: "401",
		403: "403",
		404: "404",
		400: "4xx",
		500: "5xx",
		503: "5xx",
		0:   "unknown",
	}
	for code, want := range cases {
		if got := codeLabel(code); got != want {
			t.Errorf("codeLabel(%d) = %q, want %q", code, got, want)
		}
	}
}

// TestLoginSuccessIncrementsMetric drives a real Login through httptest and
// confirms that ClientTokenRenewalTotal{login_success} ticks.
func TestLoginSuccessIncrementsMetric(t *testing.T) {
	before := testutil.ToFloat64(ClientTokenRenewalTotal.WithLabelValues(ResultLoginSuccess))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "ct",
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		Address:   server.URL,
		AuthPath:  "kubernetes-mgmt",
		Role:      "vault-operator",
		JWTSource: staticJWT("jwt"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	after := testutil.ToFloat64(ClientTokenRenewalTotal.WithLabelValues(ResultLoginSuccess))
	if after-before != 1 {
		t.Errorf("login_success delta = %v, want 1", after-before)
	}
}

// TestLoginFailureIncrementsMetric verifies the failure path counts.
func TestLoginFailureIncrementsMetric(t *testing.T) {
	before := testutil.ToFloat64(ClientTokenRenewalTotal.WithLabelValues(ResultLoginFailed))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	c, _ := New(Config{
		Address:   server.URL,
		AuthPath:  "kubernetes-mgmt",
		Role:      "vault-operator",
		JWTSource: staticJWT("jwt"),
	})
	if err := c.Login(context.Background()); err == nil {
		t.Fatal("expected Login to fail")
	}

	after := testutil.ToFloat64(ClientTokenRenewalTotal.WithLabelValues(ResultLoginFailed))
	if after-before != 1 {
		t.Errorf("login_failed delta = %v, want 1", after-before)
	}
}

// TestDoRawRecordsAPIResponses ensures every Vault HTTP response is reflected
// in vault_api_responses_total.
func TestDoRawRecordsAPIResponses(t *testing.T) {
	beforeForbidden := testutil.ToFloat64(APIResponsesTotal.WithLabelValues(http.MethodGet, "sys_mounts", "403"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	c, _ := New(Config{
		Address:   server.URL,
		AuthPath:  "kubernetes-mgmt",
		Role:      "vault-operator",
		JWTSource: staticJWT("jwt"),
	})
	// We need a token to call SharedMountExists; cheat by stuffing one.
	c.mu.Lock()
	c.token = "fake"
	c.mu.Unlock()

	_, _ = c.SharedMountExists(context.Background(), "secret")

	after := testutil.ToFloat64(APIResponsesTotal.WithLabelValues(http.MethodGet, "sys_mounts", "403"))
	if after-beforeForbidden != 1 {
		t.Errorf("403 delta = %v, want 1", after-beforeForbidden)
	}
}

// staticJWT is a JWTSource that returns a fixed string. Reused by metrics tests
// without needing to mock the projected token mount.
type staticJWT string

func (s staticJWT) JWT() (string, error) { return string(s), nil }
