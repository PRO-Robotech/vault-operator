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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	firstToken     = "tok-1"
	pathLookupSelf = "/v1/auth/token/lookup-self"
	pathRevokeSelf = "/v1/auth/token/revoke-self"
	pathPolicyP    = "/v1/sys/policies/acl/p"
)

// tokenVault issues tok-1, tok-2, … one per login and answers the endpoints
// the token lifecycle uses. dead holds tokens Vault no longer accepts.
type tokenVault struct {
	*httptest.Server

	logins    atomic.Int32
	arrived   atomic.Int32
	renewable bool
	lease     int
	// hold, when set, keeps every login waiting until it is closed.
	hold chan struct{}
	// holdFirst, when set, keeps only the first login waiting until it is
	// closed.
	holdFirst chan struct{}
	// loginStatus, when set, is the status every login answers with.
	loginStatus int
	// denyLookupSelf: the policy of a live token does not allow lookup-self.
	denyLookupSelf bool

	mu      sync.Mutex
	dead    map[string]bool
	revoked []string
	// denied is a path the policy of a live token does not allow.
	denied string
}

// newTokenVault applies configure before the server starts, so handlers read
// the settings without a lock.
func newTokenVault(t *testing.T, configure func(tv *tokenVault)) *tokenVault {
	t.Helper()
	tv := &tokenVault{renewable: true, lease: 3600, dead: map[string]bool{}}
	if configure != nil {
		configure(tv)
	}
	tv.Server = httptest.NewServer(http.HandlerFunc(tv.serve))
	t.Cleanup(tv.Close)
	return tv
}

func (tv *tokenVault) serve(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Vault-Token")
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/login") {
		first := tv.arrived.Add(1) == 1
		if tv.hold != nil {
			<-tv.hold
		}
		if first && tv.holdFirst != nil {
			<-tv.holdFirst
		}
		if tv.loginStatus != 0 {
			http.Error(w, `{"errors":["internal error"]}`, tv.loginStatus)
			return
		}
		n := tv.logins.Add(1)
		writeAuth(w, fmt.Sprintf("tok-%d", n), tv.lease, tv.renewable)
		return
	}
	tv.mu.Lock()
	dead := tv.dead[tok]
	tv.mu.Unlock()
	if dead {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case pathLookupSelf:
		if tv.denyLookupSelf {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ttl":3600}}`))
	case pathRevokeSelf:
		tv.mu.Lock()
		tv.revoked = append(tv.revoked, tok)
		tv.dead[tok] = true
		tv.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case tv.denied:
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	case pathPolicyP, pathHealth:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
	}
}

func (tv *tokenVault) kill(tok string) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.dead[tok] = true
}

func (tv *tokenVault) revokedTokens() []string {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	return append([]string(nil), tv.revoked...)
}

func tokenClient(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := New(Config{Address: addr, AuthPath: "kubernetes-mgmt", Role: "vault-operator",
		JWTSource: StaticJWTSource("sa-jwt"), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// Callers that find no token at the same moment share one login: a login per
// caller is a token per caller, and Vault keeps every one until its TTL ends.
func TestClient_ConcurrentCallersShareOneLogin(t *testing.T) {
	hold := make(chan struct{})
	tv := newTokenVault(t, func(tv *tokenVault) { tv.hold = hold })
	c := tokenClient(t, tv.URL)

	const callers = 50
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.PutPolicy(context.Background(), "p", `path "secret/data/x" { capabilities = ["read"] }`)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for tv.arrived.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Every caller has had the time to reach the token check while the first
	// login is held.
	time.Sleep(200 * time.Millisecond)
	close(hold)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("PutPolicy: %v", err)
		}
	}
	if n := tv.logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1 for %d concurrent callers", n, callers)
	}
}

// A token Vault stopped accepting is replaced once and the request is sent
// again with the new one.
func TestClient_RejectedTokenIsReplacedAndTheCallRetriedOnce(t *testing.T) {
	tv := newTokenVault(t, nil)
	c := tokenClient(t, tv.URL)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	tv.kill(firstToken)

	if err := c.PutPolicy(context.Background(), "p", `path "secret/data/x" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("PutPolicy with a revoked token: %v", err)
	}
	if n := tv.logins.Load(); n != 2 {
		t.Fatalf("logins = %d, want 2 (the first and one replacement)", n)
	}
	if got := c.Token(); got != "tok-2" {
		t.Fatalf("token = %q, want tok-2", got)
	}
}

// Twin: a 403 the live token earns by its policy is the caller's answer. The
// token stays and no login follows.
func TestClient_DenialOfALiveTokenKeepsTheToken(t *testing.T) {
	tv := newTokenVault(t, func(tv *tokenVault) { tv.denied = pathPolicyP })
	c := tokenClient(t, tv.URL)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err := c.PutPolicy(context.Background(), "p", `path "secret/data/x" { capabilities = ["read"] }`)
	if !IsForbidden(err) {
		t.Fatalf("PutPolicy = %v, want 403", err)
	}
	if n := tv.logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1: a capability denial is not a dead token", n)
	}
	if got := c.Token(); got != firstToken {
		t.Fatalf("token = %q, want tok-1", got)
	}
}

// A live token whose policy does not allow lookup-self looks dead after any
// 403. The client drops it, and a dropped token Vault still holds must be
// revoked, or every such 403 leaves one more token behind until its TTL ends.
func TestClient_ATokenDroppedAfterA403IsRevoked(t *testing.T) {
	tv := newTokenVault(t, func(tv *tokenVault) { tv.denied, tv.denyLookupSelf = pathPolicyP, true })
	c := tokenClient(t, tv.URL)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	err := c.PutPolicy(context.Background(), "p", `path "secret/data/x" { capabilities = ["read"] }`)
	if !IsForbidden(err) {
		t.Fatalf("PutPolicy = %v, want 403", err)
	}
	if got := tv.revokedTokens(); len(got) != 1 || got[0] != firstToken {
		t.Fatalf("revoked = %v, want [tok-1]: the dropped token stays in Vault", got)
	}
}

// heldLogin starts a refresh whose login Vault holds and returns once the
// login has reached Vault.
func heldLogin(t *testing.T, tv *tokenVault, call func()) {
	t.Helper()
	go call()
	deadline := time.Now().Add(5 * time.Second)
	for tv.arrived.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if tv.arrived.Load() == 0 {
		t.Fatal("the first login never reached Vault")
	}
}

// waiters starts n callers that need a token while the first refresh is held
// and returns their results once the refresh is released by release.
func waiters(c *Client, n int, release func()) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.EnsureLoggedIn(context.Background())
		}()
	}
	// Every waiter has had the time to queue behind the held refresh.
	time.Sleep(200 * time.Millisecond)
	release()
	wg.Wait()
	return errs
}

// The caller that refreshes may be cancelled (its reconcile timed out, the
// process stops). Its cancellation says nothing about Vault: the callers that
// waited for it refresh with their own context, and the breaker counts
// nothing. Four waiters and the cancelled caller are the breaker's threshold.
func TestClient_ACancelledRefreshIsNotPassedToItsWaiters(t *testing.T) {
	hold := make(chan struct{})
	tv := newTokenVault(t, func(tv *tokenVault) { tv.holdFirst = hold })
	t.Cleanup(func() { close(hold) })
	c := tokenClient(t, tv.URL)

	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	heldLogin(t, tv, func() { leaderErr <- c.EnsureLoggedIn(leaderCtx) })
	errs := waiters(c, DefaultBreakerFailureThreshold-1, cancel)

	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v, want context.Canceled", err)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("waiter %d: %v, want a token: the cancellation of another caller was passed on", i, err)
		}
	}
	if st := c.Breaker().State(); st != StateClosed {
		t.Fatalf("breaker = %s, want closed: a cancellation was counted as a Vault failure", st)
	}
}

// One refresh is one outcome: a login Vault fails while others wait for it is
// one failure for the breaker, however many callers it answers.
func TestClient_ASharedRefreshFailureCountsOnce(t *testing.T) {
	hold := make(chan struct{})
	tv := newTokenVault(t, func(tv *tokenVault) { tv.holdFirst, tv.loginStatus = hold, http.StatusInternalServerError })
	c := tokenClient(t, tv.URL)

	leaderErr := make(chan error, 1)
	heldLogin(t, tv, func() { leaderErr <- c.EnsureLoggedIn(context.Background()) })
	errs := waiters(c, DefaultBreakerFailureThreshold-1, func() { close(hold) })

	if err := <-leaderErr; err == nil {
		t.Fatal("the refreshing caller got no error from a failed login")
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("waiter %d: nil, want the outcome of the refresh it waited for", i)
		}
	}
	if n := tv.arrived.Load(); n != 1 {
		t.Fatalf("logins sent = %d, want 1: waiters repeated a failed refresh", n)
	}
	if st := c.Breaker().State(); st != StateClosed {
		t.Fatalf("breaker = %s, want closed: one failed login was counted %d times", st, DefaultBreakerFailureThreshold)
	}
}

// Twin: failures of separate refreshes still count one each and open the
// breaker at its threshold.
func TestClient_SeparateRefreshFailuresOpenTheBreaker(t *testing.T) {
	tv := newTokenVault(t, func(tv *tokenVault) { tv.loginStatus = http.StatusInternalServerError })
	c := tokenClient(t, tv.URL)
	for range DefaultBreakerFailureThreshold {
		if err := c.EnsureLoggedIn(context.Background()); err == nil {
			t.Fatal("EnsureLoggedIn: nil, want the login failure")
		}
	}
	if st := c.Breaker().State(); st != StateOpen {
		t.Fatalf("breaker = %s, want open after %d failed logins", st, DefaultBreakerFailureThreshold)
	}
}

// A token that cannot be renewed is replaced by a login, and the replaced
// token, still valid, is revoked rather than left to its TTL.
func TestClient_ReloginRevokesTheTokenItReplaces(t *testing.T) {
	tv := newTokenVault(t, func(tv *tokenVault) { tv.renewable, tv.lease = false, 100 })
	c := tokenClient(t, tv.URL)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	now = now.Add(70 * time.Second) // 30% of the TTL left: past the renew threshold
	if _, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if n := tv.logins.Load(); n != 2 {
		t.Fatalf("logins = %d, want 2", n)
	}
	if got := tv.revokedTokens(); len(got) != 1 || got[0] != firstToken {
		t.Fatalf("revoked = %v, want [tok-1]", got)
	}
}

// Parallel calls share a bounded pool of connections to Vault.
func TestClient_ParallelCallsStayWithinTheConnectionCap(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			writeAuth(w, "tok", 3600, true)
			return
		}
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	c := tokenClient(t, srv.URL)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
		}()
	}
	wg.Wait()
	if n := conns.Load(); n > 6 {
		t.Fatalf("connections = %d for 100 parallel calls, want at most 6", n)
	}
}

// A Vault answer larger than the client accepts is refused, not buffered.
func TestClient_RefusesAnOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			writeAuth(w, "tok", 3600, true)
			return
		}
		_, _ = w.Write([]byte(`{"data":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", 9<<20)))
		_, _ = w.Write([]byte(`"}`))
	}))
	t.Cleanup(srv.Close)
	c := tokenClient(t, srv.URL)

	_, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"})
	if err == nil {
		t.Fatal("a 9 MiB answer was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want a size refusal", err)
	}
}

// Repeated EnsureLoggedIn on a fresh token costs no request: 200 passes, one
// login.
func TestClient_EnsureLoggedInReusesTheToken(t *testing.T) {
	tv := newTokenVault(t, nil)
	c := tokenClient(t, tv.URL)
	for range 200 {
		if err := c.EnsureLoggedIn(context.Background()); err != nil {
			t.Fatalf("EnsureLoggedIn: %v", err)
		}
	}
	if n := tv.logins.Load(); n != 1 {
		t.Fatalf("logins = %d for 200 passes, want 1", n)
	}
}

// An open breaker answers EnsureLoggedIn without a request to Vault.
func TestClient_EnsureLoggedInWithAnOpenBreakerSendsNothing(t *testing.T) {
	c := tripBreaker(t)
	c.ClearToken()
	before := c.Breaker().State()
	err := c.EnsureLoggedIn(context.Background())
	var co *CircuitOpenError
	if !errors.As(err, &co) {
		t.Fatalf("EnsureLoggedIn = %v, want a CircuitOpenError", err)
	}
	if c.Token() != "" {
		t.Fatal("a token was obtained through an open breaker")
	}
	if got := c.Breaker().State(); got != before {
		t.Fatalf("breaker state %s → %s", before, got)
	}
}

// Revoke gives the token back and forgets it.
func TestClient_RevokeGivesTheTokenBack(t *testing.T) {
	tv := newTokenVault(t, nil)
	c := tokenClient(t, tv.URL)
	if err := c.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	c.Revoke(context.Background())
	if got := tv.revokedTokens(); len(got) != 1 || got[0] != firstToken {
		t.Fatalf("revoked = %v, want [tok-1]", got)
	}
	if c.Token() != "" {
		t.Fatal("the revoked token is still cached")
	}
}

// The request limit spaces calls out: with 10 req/s and a burst of 1, 11
// calls take at least a second.
func TestClient_RateLimitSpacesCalls(t *testing.T) {
	tv := newTokenVault(t, nil)
	c, err := New(Config{Address: tv.URL, AuthPath: "kubernetes-mgmt", Role: "vault-operator",
		JWTSource: StaticJWTSource("sa-jwt"), QPS: 10, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	for range 11 {
		if _, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Fatalf("11 calls at 10/s took %s, want about 1s", d)
	}
}

// Twin: a negative QPS lifts the limit.
func TestClient_NegativeQPSDisablesTheLimit(t *testing.T) {
	tv := newTokenVault(t, nil)
	c, err := New(Config{Address: tv.URL, AuthPath: "kubernetes-mgmt", Role: "vault-operator",
		JWTSource: StaticJWTSource("sa-jwt"), QPS: -1, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	for range 11 {
		if _, err := c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/health"}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Fatalf("11 unlimited calls took %s", d)
	}
}

// A replacement client keeps the token it adopts.
func TestClient_AdoptTokenKeepsTheLogin(t *testing.T) {
	tv := newTokenVault(t, nil)
	old := tokenClient(t, tv.URL)
	if err := old.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	fresh := tokenClient(t, tv.URL)
	fresh.AdoptToken(old)
	if err := fresh.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	if n := tv.logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1", n)
	}
}
