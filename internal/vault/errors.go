/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// APIError represents a non-2xx HTTP response from Vault. The parsed Errors
// array lets callers branch on specific Vault semantics.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Errors     []string
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("vault %s %s: %d %s", e.Method, e.Path, e.StatusCode, http.StatusText(e.StatusCode))
	}
	return fmt.Sprintf("vault %s %s: %d %s: %v", e.Method, e.Path, e.StatusCode, http.StatusText(e.StatusCode), e.Errors)
}

func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

func IsForbidden(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsBadRequest is used to detect "auth method already exists" responses from
// POST sys/auth.
func IsBadRequest(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusBadRequest
	}
	return false
}

func IsServerError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500
	}
	return false
}

var (
	ErrSealed        = errors.New("vault is sealed")
	ErrUninitialized = errors.New("vault is not initialized")
	ErrCircuitOpen   = errors.New("vault circuit breaker is open")
	ErrNotLoggedIn   = errors.New("vault client is not logged in")
)

// CircuitOpenError is returned when the breaker short-circuits a call before any
// request is sent. LastErr is the stale error that tripped it; RetryAfter is the
// time until the next probe. Unwraps to ErrCircuitOpen.
type CircuitOpenError struct {
	LastErr    error
	RetryAfter time.Duration
}

func (e *CircuitOpenError) Error() string {
	if e.LastErr != nil {
		return fmt.Sprintf("%s (no request sent; next probe in %s): last error: %v",
			ErrCircuitOpen.Error(), e.RetryAfter.Round(time.Second), e.LastErr)
	}
	return fmt.Sprintf("%s (no request sent; next probe in %s)",
		ErrCircuitOpen.Error(), e.RetryAfter.Round(time.Second))
}

func (e *CircuitOpenError) Unwrap() error { return ErrCircuitOpen }

// IsCircuitOpen reports whether err is, or wraps, a breaker short-circuit.
func IsCircuitOpen(err error) bool { return errors.Is(err, ErrCircuitOpen) }
