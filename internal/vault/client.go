/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vault is an HTTP client for HashiCorp Vault tailored to
// vault-operator: Kubernetes-auth login with the operator SA JWT, one token
// per client shared by every caller (proactive renew at 60% TTL, revoke of a
// replaced token), a circuit breaker, a request rate limit, and sealed or
// uninitialized detection without login. We use net/http directly rather
// than the upstream vault/api SDK to keep retry, breaker, and renew behaviour
// under our control.
package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// renewThreshold is the fraction of remaining TTL below which the client
// proactively renews its token.
const renewThreshold = 0.60

// Defaults of Config. The rate and the connection cap sit above what the
// default worker counts can issue (four VaultClaim workers and a VaultConfig
// probe), so a default deployment is never throttled by them.
const (
	defaultHTTPTimeout      = 10 * time.Second
	DefaultQPS              = 100
	DefaultBurst            = 200
	DefaultMaxConnsPerHost  = 6
	DefaultMaxResponseBytes = 8 << 20
)

// revokeTimeout bounds the best-effort revoke of a replaced token.
const revokeTimeout = 5 * time.Second

type Config struct {
	Address  string
	AuthPath string
	Role     string

	JWTSource JWTSource

	// Name labels the client's metrics, normally the VaultConfig name.
	Name string

	// CABundle is PEM-encoded; empty means system CAs.
	CABundle   []byte
	ServerName string

	// InsecureSkipVerify is tests-only.
	InsecureSkipVerify bool

	// Timeout defaults to defaultHTTPTimeout when zero.
	Timeout time.Duration

	// QPS caps requests per second to Vault: 0 means DefaultQPS, a negative
	// value disables the limit. Burst 0 means DefaultBurst.
	QPS   float64
	Burst int

	// MaxConnsPerHost caps connections to Vault; 0 means DefaultMaxConnsPerHost.
	MaxConnsPerHost int

	// MaxResponseBytes caps the body of one Vault answer; 0 means
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64

	// Breaker defaults to NewCircuitBreaker(0,0) when nil.
	Breaker *CircuitBreaker

	// Now is an injectable clock for tests; defaults to time.Now.
	Now func() time.Time
}

// Client wraps Vault HTTP calls. Authenticated methods enforce the breaker,
// ensure a valid token (login/renew/re-login), and trip the breaker on 5xx
// or transport errors only — 4xx are caller bugs and do not count.
//
// The token is the client's, not the caller's: every caller uses the cached
// one, and when it must be refreshed exactly one caller talks to Vault while
// the others wait for its outcome.
type Client struct {
	addr     string
	authPath string
	role     string
	jwtSrc   JWTSource
	name     string

	httpClient  *http.Client
	breaker     *CircuitBreaker
	limiter     *rate.Limiter
	maxResponse int64
	now         func() time.Time

	// loginMu serialises refreshes: login, renew-self, revoke.
	loginMu sync.Mutex

	mu          sync.RWMutex
	token       string
	tokenTTL    time.Duration
	tokenIssued time.Time
	tokenRenew  bool
	// refreshes counts finished refresh attempts; refreshErr is the outcome of
	// the last one. A caller that waited for loginMu while another refreshed
	// takes that outcome instead of repeating it.
	refreshes  uint64
	refreshErr error

	// authMountReadDenied: GET sys/auth/<mount> answered 403 once; the
	// operator policy lacks the read, and ReadAuthMount uses the listing.
	authMountReadDenied atomic.Bool
}

// New constructs a Client without logging in; callers invoke EnsureLoggedIn
// or rely on lazy auth via Do.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: Address is required")
	}
	if cfg.AuthPath == "" {
		return nil, fmt.Errorf("vault: AuthPath is required")
	}
	if cfg.Role == "" {
		return nil, fmt.Errorf("vault: Role is required")
	}
	if cfg.JWTSource == nil {
		return nil, fmt.Errorf("vault: JWTSource is required")
	}

	if _, err := url.Parse(cfg.Address); err != nil {
		return nil, fmt.Errorf("vault: invalid Address %q: %w", cfg.Address, err)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // gated by config, tests only
		ServerName:         cfg.ServerName,
	}
	if len(cfg.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CABundle) {
			return nil, fmt.Errorf("vault: CABundle does not contain valid PEM certificates")
		}
		if err := checkCABundleExpiry(cfg.CABundle, now()); err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	conns := cfg.MaxConnsPerHost
	if conns <= 0 {
		conns = DefaultMaxConnsPerHost
	}
	maxResponse := cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseBytes
	}

	breaker := cfg.Breaker
	if breaker == nil {
		breaker = NewCircuitBreaker(0, 0)
	}
	name := cfg.Name
	if name == "" {
		name = defaultClientName
	}
	breaker.setMetricName(name)

	return &Client{
		addr:     strings.TrimRight(cfg.Address, "/"),
		authPath: strings.Trim(cfg.AuthPath, "/"),
		role:     cfg.Role,
		jwtSrc:   cfg.JWTSource,
		name:     name,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				Proxy:               http.ProxyFromEnvironment,
				MaxConnsPerHost:     conns,
				MaxIdleConnsPerHost: conns,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: timeout,
			},
		},
		breaker:     breaker,
		limiter:     newLimiter(cfg.QPS, cfg.Burst),
		maxResponse: maxResponse,
		now:         now,
	}, nil
}

// newLimiter returns nil (no limit) for a negative qps.
func newLimiter(qps float64, burst int) *rate.Limiter {
	if qps < 0 {
		return nil
	}
	if qps == 0 {
		qps = DefaultQPS
	}
	if burst <= 0 {
		burst = DefaultBurst
	}
	return rate.NewLimiter(rate.Limit(qps), burst)
}

func (c *Client) Address() string          { return c.addr }
func (c *Client) AuthPath() string         { return c.authPath }
func (c *Client) Breaker() *CircuitBreaker { return c.breaker }

// Name is the metric label of the client.
func (c *Client) Name() string { return c.name }

func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

func (c *Client) TokenExpiry() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.token == "" {
		return time.Time{}
	}
	return c.tokenIssued.Add(c.tokenTTL)
}

// ClearToken forces a re-login on the next call. The token is dropped, not
// revoked: it is cleared when Vault no longer accepts it.
func (c *Client) ClearToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTokenLocked(tokenState{})
}

// tokenState is the cached token as one value.
type tokenState struct {
	token     string
	ttl       time.Duration
	issued    time.Time
	renewable bool
}

func (c *Client) state() tokenState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return tokenState{token: c.token, ttl: c.tokenTTL, issued: c.tokenIssued, renewable: c.tokenRenew}
}

func (c *Client) setTokenLocked(s tokenState) {
	c.token, c.tokenTTL, c.tokenIssued, c.tokenRenew = s.token, s.ttl, s.issued, s.renewable
}

// fresh: the token can be used without a call to Vault. A token without a
// TTL never expires.
func (s tokenState) fresh(now time.Time) bool {
	if s.token == "" {
		return false
	}
	if s.ttl <= 0 {
		return true
	}
	return s.issued.Add(s.ttl).Sub(now) >= time.Duration(float64(s.ttl)*renewThreshold)
}

// live: Vault still holds the token, so replacing it leaves it behind.
func (s tokenState) live(now time.Time) bool {
	return s.token != "" && (s.ttl <= 0 || s.issued.Add(s.ttl).After(now))
}

// AdoptToken takes over the token of another client of the same Vault and
// role: a client rebuilt for a new CA bundle keeps the token instead of
// logging in again.
func (c *Client) AdoptToken(from *Client) {
	s := from.state()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTokenLocked(s)
}

type loginResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// Login exchanges the SA JWT for a new Vault client_token, whatever the
// cached one. A cached token Vault still holds is revoked. Callers that only
// need a usable token call EnsureLoggedIn.
func (c *Client) Login(ctx context.Context) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	return c.loginLocked(ctx)
}

// loginLocked runs with loginMu held.
func (c *Client) loginLocked(ctx context.Context) error {
	old := c.state()
	if err := c.login(ctx); err != nil {
		ClientTokenRenewalTotal.WithLabelValues(ResultLoginFailed).Inc()
		return err
	}
	ClientTokenRenewalTotal.WithLabelValues(ResultLoginSuccess).Inc()
	if old.live(c.now()) && old.token != c.Token() {
		c.revoke(ctx, old.token)
	}
	return nil
}

func (c *Client) login(ctx context.Context) error {
	jwt, err := c.jwtSrc.JWT()
	if err != nil {
		return fmt.Errorf("read SA JWT: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"role": c.role,
		"jwt":  jwt,
	})
	if err != nil {
		return fmt.Errorf("marshal login body: %w", err)
	}

	path := "/v1/auth/" + c.authPath + "/login"
	resp, err := c.doRaw(ctx, http.MethodPost, path, body, "")
	if err != nil {
		return fmt.Errorf("vault login: %w", err)
	}

	var lr loginResponse
	if err := json.Unmarshal(resp, &lr); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	if lr.Auth == nil || lr.Auth.ClientToken == "" {
		return fmt.Errorf("vault login: response missing auth.client_token")
	}

	c.mu.Lock()
	c.setTokenLocked(tokenState{
		token:     lr.Auth.ClientToken,
		ttl:       time.Duration(lr.Auth.LeaseDuration) * time.Second,
		issued:    c.now(),
		renewable: lr.Auth.Renewable,
	})
	c.mu.Unlock()
	return nil
}

// revoke is best effort: a token that cannot be revoked expires with its
// TTL, and the caller's work does not depend on it.
func (c *Client) revoke(ctx context.Context, token string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	if _, err := c.doRaw(ctx, http.MethodPost, "/v1/auth/token/revoke-self", nil, token); err != nil {
		ClientTokenRenewalTotal.WithLabelValues(ResultRevokeFailed).Inc()
		return
	}
	ClientTokenRenewalTotal.WithLabelValues(ResultRevokeSuccess).Inc()
}

// Revoke revokes the cached token and forgets it. Run at shutdown, after the
// last caller is done: a later call logs in again.
func (c *Client) Revoke(ctx context.Context) {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	s := c.state()
	if !s.live(c.now()) {
		return
	}
	c.mu.Lock()
	c.setTokenLocked(tokenState{})
	c.mu.Unlock()
	c.revoke(ctx, s.token)
}

func (c *Client) renewSelf(ctx context.Context, token string) error {
	if err := c.doRenewSelf(ctx, token); err != nil {
		ClientTokenRenewalTotal.WithLabelValues(ResultRenewFailed).Inc()
		return err
	}
	ClientTokenRenewalTotal.WithLabelValues(ResultRenewSuccess).Inc()
	return nil
}

func (c *Client) doRenewSelf(ctx context.Context, token string) error {
	resp, err := c.doRaw(ctx, http.MethodPost, "/v1/auth/token/renew-self", nil, token)
	if err != nil {
		return fmt.Errorf("vault renew-self: %w", err)
	}

	var lr loginResponse
	if err := json.Unmarshal(resp, &lr); err != nil {
		return fmt.Errorf("decode renew-self response: %w", err)
	}
	if lr.Auth == nil {
		return fmt.Errorf("vault renew-self: response missing auth")
	}

	c.mu.Lock()
	// renew-self extends the existing token; no new client_token is returned.
	if c.token == token {
		c.tokenTTL = time.Duration(lr.Auth.LeaseDuration) * time.Second
		c.tokenIssued = c.now()
	}
	c.mu.Unlock()
	return nil
}

// ensureToken returns a token Vault accepts: the cached one while it is
// fresh, otherwise the outcome of one refresh shared by every caller that
// needed it at the same time.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	s := tokenState{token: c.token, ttl: c.tokenTTL, issued: c.tokenIssued, renewable: c.tokenRenew}
	seen := c.refreshes
	c.mu.RUnlock()
	if s.fresh(c.now()) {
		return s.token, nil
	}

	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	c.mu.RLock()
	s = tokenState{token: c.token, ttl: c.tokenTTL, issued: c.tokenIssued, renewable: c.tokenRenew}
	done, lastErr := c.refreshes, c.refreshErr
	c.mu.RUnlock()
	if s.fresh(c.now()) {
		return s.token, nil
	}
	if done != seen && lastErr != nil {
		// Another caller refreshed while this one waited and failed: the same
		// call now would fail the same way.
		return "", lastErr
	}

	err := c.refreshLocked(ctx, s)
	c.mu.Lock()
	c.refreshes++
	c.refreshErr = err
	tok := c.token
	c.mu.Unlock()
	if err != nil {
		return "", err
	}
	return tok, nil
}

// refreshLocked renews a live renewable token and replaces any other; it runs
// with loginMu held.
func (c *Client) refreshLocked(ctx context.Context, s tokenState) error {
	if s.live(c.now()) && s.renewable {
		if err := c.renewSelf(ctx, s.token); err == nil {
			return nil
		}
	}
	return c.loginLocked(ctx)
}

// forget drops token if it is still the cached one.
func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.setTokenLocked(tokenState{})
	}
}

// tokenDead asks Vault whether it still accepts token. Only a 403 on
// lookup-self, which the default policy allows, means it does not.
func (c *Client) tokenDead(ctx context.Context, token string) bool {
	_, err := c.doRaw(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, token)
	return IsForbidden(err)
}

// EnsureLoggedIn makes sure the client holds a token: a fresh cached token
// costs no request, an open breaker short-circuits without one, and otherwise
// one refresh is made for all callers.
func (c *Client) EnsureLoggedIn(ctx context.Context) error {
	if err := c.circuitOpen(); err != nil {
		return err
	}
	if c.state().fresh(c.now()) {
		return nil
	}
	if err := c.wait(ctx); err != nil {
		return err
	}
	if !c.breaker.Allow() {
		return c.circuitOpenError()
	}
	if _, err := c.ensureToken(ctx); err != nil {
		c.breaker.OnFailure(err)
		return err
	}
	c.breaker.OnSuccess()
	return nil
}

// LookupSelf asks Vault about the cached token; a token Vault dropped is
// replaced once on the way, like for any other call.
func (c *Client) LookupSelf(ctx context.Context) error {
	_, err := c.Do(ctx, &Request{Method: http.MethodGet, Path: "auth/token/lookup-self"})
	return err
}

// circuitOpen returns the short-circuit error while the breaker is open and
// its window has not elapsed.
func (c *Client) circuitOpen() error {
	if c.breaker.RetryAfter() > 0 {
		return c.circuitOpenError()
	}
	return nil
}

func (c *Client) circuitOpenError() error {
	return &CircuitOpenError{
		LastErr:    c.breaker.LastError(),
		RetryAfter: c.breaker.RetryAfter(),
	}
}

// wait takes a request slot from the rate limiter.
func (c *Client) wait(ctx context.Context) error {
	if c.limiter == nil {
		return nil
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("vault rate limit: %w", err)
	}
	return nil
}

// Request describes a Vault HTTP call. Path must NOT include /v1.
type Request struct {
	Method string
	Path   string
	Body   any
	// AuthOptional skips ensureToken (used by SealStatus and health).
	AuthOptional bool
	Query        url.Values
}

type Response struct {
	StatusCode int
	Body       []byte
}

func (r *Response) Decode(v any) error {
	if len(r.Body) == 0 {
		return nil
	}
	return json.Unmarshal(r.Body, v)
}

// Do issues a Vault request through the rate limit and the circuit breaker:
// 4xx propagates without tripping, 5xx and transport errors trip it.
// AuthOptional probes bypass the breaker. A 403 for a token Vault no longer
// accepts replaces the token and sends the request once more.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	// Marshal before the breaker so a marshal error can't consume the probe slot.
	var body []byte
	if req.Body != nil {
		b, err := json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		body = b
	}
	// The limiter is taken before the breaker: a caller cancelled while it
	// waits must not hold the half-open probe.
	if err := c.wait(ctx); err != nil {
		return nil, err
	}

	if req.AuthOptional { // reachability probes stay callable; never trip the breaker
		return c.send(ctx, req, body, "")
	}

	if !c.breaker.Allow() {
		return nil, c.circuitOpenError()
	}

	token, err := c.ensureToken(ctx)
	if err != nil {
		c.breaker.OnFailure(err)
		return nil, err
	}

	resp, err := c.send(ctx, req, body, token)
	if IsForbidden(err) && c.tokenDead(ctx, token) {
		c.forget(token)
		if token, err = c.ensureToken(ctx); err == nil {
			resp, err = c.send(ctx, req, body, token)
		}
	}
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
			// 4xx is success from the breaker's POV — Vault is reachable.
			c.breaker.OnSuccess()
		} else {
			c.breaker.OnFailure(err)
		}
		return nil, err
	}

	c.breaker.OnSuccess()
	return resp, nil
}

// send issues the raw HTTP call with no breaker accounting; callers decide whether the outcome counts.
func (c *Client) send(ctx context.Context, req *Request, body []byte, token string) (*Response, error) {
	path := "/v1/" + strings.TrimLeft(req.Path, "/")
	if len(req.Query) > 0 {
		path += "?" + req.Query.Encode()
	}

	respBody, err := c.doRaw(ctx, req.Method, path, body, token)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: http.StatusOK, Body: respBody}, nil
}

// doRaw is the low-level HTTP send. The path label fed into the metric is
// normalised (see normalizePath) so cardinality stays bounded.
func (c *Client) doRaw(ctx context.Context, method, path string, body []byte, token string) ([]byte, error) {
	pathLabel := normalizePath(path)
	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewReader(body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, c.addr+path, reqBody)
	if err != nil {
		APICallsTotal.WithLabelValues(method, pathLabel, ResultTransportErr).Inc()
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		httpReq.Header.Set("X-Vault-Token", token)
	}

	start := time.Now()
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		APICallsTotal.WithLabelValues(method, pathLabel, ResultTransportErr).Inc()
		APIRequestDuration.WithLabelValues(method, pathLabel, ResultTransportErr).Observe(time.Since(start).Seconds())
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Record the status as soon as we have it, independent of body read.
	result := resultFromStatusCode(httpResp.StatusCode)
	APIResponsesTotal.WithLabelValues(method, pathLabel, codeLabel(httpResp.StatusCode)).Inc()
	APICallsTotal.WithLabelValues(method, pathLabel, result).Inc()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, c.maxResponse+1))
	APIRequestDuration.WithLabelValues(method, pathLabel, result).Observe(time.Since(start).Seconds())
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(respBody)) > c.maxResponse {
		return nil, fmt.Errorf("vault %s %s: response exceeds %d bytes", method, pathLabel, c.maxResponse)
	}

	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		return respBody, nil
	}

	apiErr := &APIError{
		Method:     method,
		Path:       path,
		StatusCode: httpResp.StatusCode,
		Body:       respBody,
	}
	// Vault encodes errors as {"errors": ["msg1", ...]}.
	var errPayload struct {
		Errors []string `json:"errors"`
	}
	if jerr := json.Unmarshal(respBody, &errPayload); jerr == nil {
		apiErr.Errors = errPayload.Errors
	}
	return nil, apiErr
}
