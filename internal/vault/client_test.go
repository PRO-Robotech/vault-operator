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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Test-only constants to satisfy goconst.
const (
	pathSealStatus = "/v1/sys/seal-status"
	pathHealth     = "/v1/sys/health"
)

// fakeVault is a minimal HTTP server mimicking the subset of Vault endpoints
// used by the operator. It records call counts so tests can assert ordering.
type fakeVault struct {
	*httptest.Server

	loginCalls   atomic.Int32
	renewCalls   atomic.Int32
	leaseSeconds int
	renewable    bool

	// override is invoked first; if it writes a status, the default handler is skipped.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	fv := &fakeVault{
		leaseSeconds: 3600,
		renewable:    true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if fv.override != nil && fv.override(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/login"):
			fv.loginCalls.Add(1)
			writeAuth(w, "vault-token-issued", fv.leaseSeconds, fv.renewable)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/renew-self":
			fv.renewCalls.Add(1)
			writeAuth(w, "", fv.leaseSeconds, fv.renewable)
		case r.Method == http.MethodGet && r.URL.Path == pathSealStatus:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sealed":      false,
				"initialized": true,
				"version":     "1.17.6",
				"t":           3,
				"n":           5,
				"progress":    0,
			})
		default:
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		}
	})
	fv.Server = httptest.NewServer(mux)
	t.Cleanup(fv.Close)
	return fv
}

func writeAuth(w http.ResponseWriter, token string, lease int, renewable bool) {
	auth := map[string]any{
		"lease_duration": lease,
		"renewable":      renewable,
	}
	if token != "" {
		auth["client_token"] = token
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": auth})
}

func newTestClient(t *testing.T, fv *fakeVault) *Client {
	t.Helper()
	c, err := New(Config{
		Address:            fv.URL,
		AuthPath:           "kubernetes-mgmt",
		Role:               "vault-operator",
		JWTSource:          StaticJWTSource("sa-jwt"),
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestClient_New_RequiresFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing address", Config{AuthPath: "k", Role: "r", JWTSource: StaticJWTSource("j")}},
		{"missing auth path", Config{Address: "https://v", Role: "r", JWTSource: StaticJWTSource("j")}},
		{"missing role", Config{Address: "https://v", AuthPath: "k", JWTSource: StaticJWTSource("j")}},
		{"missing jwt source", Config{Address: "https://v", AuthPath: "k", Role: "r"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestClient_Login_Success(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.Token() != "vault-token-issued" {
		t.Fatalf("Token=%q, want vault-token-issued", c.Token())
	}
	if fv.loginCalls.Load() != 1 {
		t.Fatalf("expected 1 login call, got %d", fv.loginCalls.Load())
	}
}

func TestClient_Login_PropagatesAPIError(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/login") {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	err := c.Login(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !IsForbidden(err) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestClient_Do_LazyLoginAndCallsBackend(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/mounts" {
			if r.Header.Get("X-Vault-Token") != "vault-token-issued" {
				http.Error(w, `{"errors":["missing token"]}`, http.StatusForbidden)
				return true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"secret/": map[string]any{"type": "kv"},
				},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)

	resp, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/mounts"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp == nil || len(resp.Body) == 0 {
		t.Fatalf("expected body")
	}
	if fv.loginCalls.Load() != 1 {
		t.Fatalf("expected lazy login, got %d login calls", fv.loginCalls.Load())
	}
}

func TestClient_Do_RenewsAt60Percent(t *testing.T) {
	fv := newFakeVault(t)
	fv.leaseSeconds = 100
	c := newTestClient(t, fv)

	now := time.Now()
	c.now = func() time.Time { return now }

	// Initial login at t=0.
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if fv.renewCalls.Load() != 0 {
		t.Fatalf("expected 0 renew calls initially")
	}

	// At 30s remaining (70% elapsed → 30% remaining, below 60% threshold), Do should renew.
	now = now.Add(70 * time.Second)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathHealth {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return true
		}
		return false
	}
	_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if fv.renewCalls.Load() != 1 {
		t.Fatalf("expected 1 renew call, got %d", fv.renewCalls.Load())
	}
}

func TestClient_Do_ReLoginsWhenExpired(t *testing.T) {
	fv := newFakeVault(t)
	fv.leaseSeconds = 10
	c := newTestClient(t, fv)

	now := time.Now()
	c.now = func() time.Time { return now }

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	beforeRenew := fv.renewCalls.Load()
	beforeLogin := fv.loginCalls.Load()

	// Advance past expiry.
	now = now.Add(time.Hour)

	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathHealth {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return true
		}
		return false
	}
	_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if fv.loginCalls.Load() <= beforeLogin {
		t.Fatalf("expected new login on expired token, before=%d after=%d", beforeLogin, fv.loginCalls.Load())
	}
	// renew-self should NOT be called for an expired token; we go straight to re-login.
	if fv.renewCalls.Load() != beforeRenew {
		t.Fatalf("did not expect renew on expired token: before=%d after=%d", beforeRenew, fv.renewCalls.Load())
	}
}

func TestClient_Do_4xxDoesNotTripBreaker(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/v1/sys/policies/acl/missing" {
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)

	for i := 0; i < 10; i++ {
		_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/policies/acl/missing"})
		if !IsNotFound(err) {
			t.Fatalf("expected NotFound, got %v", err)
		}
	}
	if c.Breaker().State() != "closed" {
		t.Fatalf("breaker should stay closed on 404, got %s", c.Breaker().State())
	}
}

func TestClient_Do_5xxTripsBreaker(t *testing.T) {
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathHealth {
			http.Error(w, `{"errors":["internal"]}`, http.StatusInternalServerError)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)

	// Login succeeds first.
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	for i := 0; i < DefaultBreakerFailureThreshold; i++ {
		_, _ = c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	}
	if c.Breaker().State() != "open" {
		t.Fatalf("breaker should trip after %d 5xx, got %s", DefaultBreakerFailureThreshold, c.Breaker().State())
	}
	// Next call short-circuits with ErrCircuitOpen wrapped around the last underlying error.
	_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

// tripBreaker logs in and drives the breaker open via 5xx on sys/health.
func tripBreaker(t *testing.T) *Client {
	t.Helper()
	fv := newFakeVault(t)
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == pathHealth {
			http.Error(w, `{"errors":["boom"]}`, http.StatusInternalServerError)
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	for i := 0; i < DefaultBreakerFailureThreshold; i++ {
		_, _ = c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	}
	if c.Breaker().State() != StateOpen {
		t.Fatalf("expected breaker open, got %s", c.Breaker().State())
	}
	return c
}

// P2: AuthOptional probes bypass the breaker and don't reset it.
func TestClient_Do_AuthOptionalBypassesOpenBreaker(t *testing.T) {
	c := tripBreaker(t)

	// seal-status (AuthOptional) still reaches Vault despite the open breaker.
	ss, err := c.SealStatus(context.Background())
	if err != nil {
		t.Fatalf("seal-status should bypass the open breaker, got %v", err)
	}
	if ss == nil || ss.Sealed {
		t.Fatalf("unexpected seal status: %+v", ss)
	}

	// A successful probe must not silently close the breaker guarding auth calls.
	if c.Breaker().State() != StateOpen {
		t.Fatalf("AuthOptional success must not close the breaker, got %s", c.Breaker().State())
	}

	// Authenticated calls remain short-circuited with the typed error.
	_, err = c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	var co *CircuitOpenError
	if !errors.As(err, &co) {
		t.Fatalf("expected *CircuitOpenError, got %v", err)
	}
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("CircuitOpenError must satisfy errors.Is(ErrCircuitOpen)")
	}
}

// P1: short-circuit error carries LastErr + RetryAfter and says no request sent.
func TestClient_Do_CircuitOpenErrorCarriesContext(t *testing.T) {
	c := tripBreaker(t)

	_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	var co *CircuitOpenError
	if !errors.As(err, &co) {
		t.Fatalf("expected *CircuitOpenError, got %v", err)
	}
	if co.LastErr == nil {
		t.Fatalf("CircuitOpenError.LastErr should carry the tripping error")
	}
	if co.RetryAfter <= 0 || co.RetryAfter > DefaultBreakerOpenWindow {
		t.Fatalf("RetryAfter should be within (0, window], got %s", co.RetryAfter)
	}
	if !strings.Contains(err.Error(), "no request sent") {
		t.Fatalf("error should state no request was sent, got %q", err.Error())
	}
}

// P3: a marshal error must not consume the half-open probe slot.
func TestClient_Do_MarshalErrorDoesNotConsumeProbe(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.Breaker().now = func() time.Time { return now }
	for i := 0; i < DefaultBreakerFailureThreshold; i++ {
		c.Breaker().Allow()
		c.Breaker().OnFailure(errors.New("boom"))
	}
	if c.Breaker().State() != StateOpen {
		t.Fatalf("expected breaker open, got %s", c.Breaker().State())
	}

	// Advance past the window so the next Allow() *would* admit the probe.
	now = now.Add(DefaultBreakerOpenWindow + time.Second)

	_, err := c.Do(context.Background(), &Request{
		Method: http.MethodPost,
		Path:   "sys/policies/acl/x",
		Body:   make(chan int), // channels are not JSON-marshalable
	})
	if err == nil || !strings.Contains(err.Error(), "marshal request body") {
		t.Fatalf("expected marshal error, got %v", err)
	}

	// Breaker must still be open — the marshal error didn't consume the probe slot.
	if c.Breaker().State() != StateOpen {
		t.Fatalf("breaker must stay open after a marshal error, got %s", c.Breaker().State())
	}
	if !c.Breaker().Allow() {
		t.Fatalf("half-open probe should still be available after a marshal error")
	}
}

func TestClient_ClearToken(t *testing.T) {
	fv := newFakeVault(t)
	c := newTestClient(t, fv)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.Token() == "" {
		t.Fatalf("expected token after login")
	}
	c.ClearToken()
	if c.Token() != "" {
		t.Fatalf("expected empty token after Clear")
	}
}

func TestClient_Request_QueryString(t *testing.T) {
	fv := newFakeVault(t)
	var seen string
	fv.override = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/v1/auth/k/role") {
			seen = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"keys": []string{"r1", "r2"}},
			})
			return true
		}
		return false
	}
	c := newTestClient(t, fv)
	resp, err := c.Do(context.Background(), &Request{
		Method: http.MethodGet,
		Path:   "auth/k/role",
		Query:  map[string][]string{"list": {"true"}},
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !strings.Contains(seen, "list=true") {
		t.Fatalf("expected list=true in query, got %q", seen)
	}
	body, _ := io.ReadAll(strings.NewReader(string(resp.Body)))
	if !strings.Contains(string(body), "r1") {
		t.Fatalf("expected r1 in body, got %s", string(resp.Body))
	}
}
