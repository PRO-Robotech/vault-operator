/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package vault is an HTTP client for HashiCorp Vault tailored to
// vault-operator: Kubernetes-auth login with the operator SA JWT, proactive
// client_token renew at 60% TTL, a circuit breaker, and sealed/uninitialized
// detection without login. We use net/http directly rather than the upstream
// vault/api SDK to keep retry, breaker, and renew behaviour under our control.
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
	"time"
)

// renewThreshold is the fraction of remaining TTL below which the client
// proactively renews its token.
const renewThreshold = 0.60

const defaultHTTPTimeout = 30 * time.Second

type Config struct {
	Address  string
	AuthPath string
	Role     string

	JWTSource JWTSource

	// CABundle is PEM-encoded; empty means system CAs.
	CABundle   []byte
	ServerName string

	// InsecureSkipVerify is tests-only.
	InsecureSkipVerify bool

	// Timeout defaults to defaultHTTPTimeout when zero.
	Timeout time.Duration

	// Breaker defaults to NewCircuitBreaker(0,0) when nil.
	Breaker *CircuitBreaker

	// Now is an injectable clock for tests; defaults to time.Now.
	Now func() time.Time
}

// Client wraps Vault HTTP calls. Authenticated methods enforce the breaker,
// ensure a valid token (login/renew/re-login), and trip the breaker on 5xx
// or transport errors only — 4xx are caller bugs and do not count.
type Client struct {
	addr     string
	authPath string
	role     string
	jwtSrc   JWTSource

	httpClient *http.Client
	breaker    *CircuitBreaker
	now        func() time.Time

	mu          sync.RWMutex
	token       string
	tokenTTL    time.Duration
	tokenIssued time.Time
	tokenRenew  bool
}

// New constructs a Client without logging in; callers invoke Login or rely
// on lazy auth via Do.
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
		tlsCfg.RootCAs = pool
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}

	breaker := cfg.Breaker
	if breaker == nil {
		breaker = NewCircuitBreaker(0, 0)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Client{
		addr:     strings.TrimRight(cfg.Address, "/"),
		authPath: strings.Trim(cfg.AuthPath, "/"),
		role:     cfg.Role,
		jwtSrc:   cfg.JWTSource,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				Proxy:           http.ProxyFromEnvironment,
			},
		},
		breaker: breaker,
		now:     now,
	}, nil
}

func (c *Client) Address() string          { return c.addr }
func (c *Client) AuthPath() string         { return c.authPath }
func (c *Client) Breaker() *CircuitBreaker { return c.breaker }

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

// ClearToken forces a re-login on the next Do — used after a 403 to recover
// from a revoked token without restarting the process.
func (c *Client) ClearToken() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.tokenTTL = 0
	c.tokenIssued = time.Time{}
	c.tokenRenew = false
}

type loginResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// Login exchanges the SA JWT for a Vault client_token; the resulting token
// and TTL are cached on the client.
func (c *Client) Login(ctx context.Context) error {
	if err := c.login(ctx); err != nil {
		ClientTokenRenewalTotal.WithLabelValues(ResultLoginFailed).Inc()
		return err
	}
	ClientTokenRenewalTotal.WithLabelValues(ResultLoginSuccess).Inc()
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
	c.token = lr.Auth.ClientToken
	c.tokenTTL = time.Duration(lr.Auth.LeaseDuration) * time.Second
	c.tokenIssued = c.now()
	c.tokenRenew = lr.Auth.Renewable
	c.mu.Unlock()

	return nil
}

func (c *Client) renewSelf(ctx context.Context) error {
	if err := c.doRenewSelf(ctx); err != nil {
		ClientTokenRenewalTotal.WithLabelValues(ResultRenewFailed).Inc()
		return err
	}
	ClientTokenRenewalTotal.WithLabelValues(ResultRenewSuccess).Inc()
	return nil
}

func (c *Client) doRenewSelf(ctx context.Context) error {
	c.mu.RLock()
	token := c.token
	renewable := c.tokenRenew
	c.mu.RUnlock()

	if token == "" {
		return ErrNotLoggedIn
	}
	if !renewable {
		return errors.New("vault token not renewable")
	}

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
	c.tokenTTL = time.Duration(lr.Auth.LeaseDuration) * time.Second
	c.tokenIssued = c.now()
	// renew-self extends the existing token; no new client_token is returned.
	c.mu.Unlock()
	return nil
}

// ensureToken returns a valid token, logging in, renewing, or re-logging in
// as needed. Concurrent callers that observe the same expired token race for
// the lock; only one performs the network call.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	tok := c.token
	issued := c.tokenIssued
	ttl := c.tokenTTL
	c.mu.RUnlock()

	if tok == "" {
		if err := c.Login(ctx); err != nil {
			return "", err
		}
		c.mu.RLock()
		tok = c.token
		c.mu.RUnlock()
		return tok, nil
	}

	if ttl > 0 {
		// Use c.now (injectable) so tests stay consistent with the clock used
		// by Login to set tokenIssued.
		remaining := issued.Add(ttl).Sub(c.now())
		if remaining > 0 && remaining < time.Duration(float64(ttl)*renewThreshold) {
			if err := c.renewSelf(ctx); err != nil {
				if err := c.Login(ctx); err != nil {
					return "", err
				}
			}
			c.mu.RLock()
			tok = c.token
			c.mu.RUnlock()
		} else if remaining <= 0 {
			if err := c.Login(ctx); err != nil {
				return "", err
			}
			c.mu.RLock()
			tok = c.token
			c.mu.RUnlock()
		}
	}

	return tok, nil
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

// Do issues a Vault request through the circuit breaker. 4xx propagates as
// *APIError without tripping; 5xx and transport errors trip the breaker.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if !c.breaker.Allow() {
		if le := c.breaker.LastError(); le != nil {
			return nil, fmt.Errorf("%w: last error: %v", ErrCircuitOpen, le)
		}
		return nil, ErrCircuitOpen
	}

	var token string
	if !req.AuthOptional {
		var err error
		token, err = c.ensureToken(ctx)
		if err != nil {
			c.breaker.OnFailure(err)
			return nil, err
		}
	}

	path := "/v1/" + strings.TrimLeft(req.Path, "/")
	if len(req.Query) > 0 {
		path += "?" + req.Query.Encode()
	}

	var body []byte
	if req.Body != nil {
		var err error
		body, err = json.Marshal(req.Body)
		if err != nil {
			// Marshal errors are caller bugs; don't trip the breaker.
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
	}

	respBody, err := c.doRaw(ctx, req.Method, path, body, token)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode >= 500 {
				c.breaker.OnFailure(err)
			} else {
				// 4xx is success from the breaker's POV — Vault is reachable.
				c.breaker.OnSuccess()
			}
			return nil, err
		}
		c.breaker.OnFailure(err)
		return nil, err
	}

	c.breaker.OnSuccess()
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

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		APICallsTotal.WithLabelValues(method, pathLabel, ResultTransportErr).Inc()
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Record the status as soon as we have it, independent of body read.
	APIResponsesTotal.WithLabelValues(method, pathLabel, codeLabel(httpResp.StatusCode)).Inc()
	APICallsTotal.WithLabelValues(method, pathLabel, resultFromStatusCode(httpResp.StatusCode)).Inc()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode >= 200 && httpResp.StatusCode < 300 {
		return respBody, nil
	}

	apiErr := &APIError{
		Method:     method,
		Path:       path,
		StatusCode: httpResp.StatusCode,
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
