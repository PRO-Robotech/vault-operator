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
	"testing"
	"time"
)

func TestCircuitBreaker_TripsAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Minute)
	for i := 0; i < 2; i++ {
		if !cb.Allow() {
			t.Fatalf("call %d should be allowed", i)
		}
		cb.OnFailure(nil)
	}
	// Two failures, breaker should still be closed.
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after 2 failures, got %s", cb.State())
	}

	// Third failure trips it.
	if !cb.Allow() {
		t.Fatalf("third call should still be allowed (counting fails)")
	}
	cb.OnFailure(nil)
	if cb.State() != StateOpen {
		t.Fatalf("expected open after 3 failures, got %s", cb.State())
	}
	if cb.Allow() {
		t.Fatalf("Allow() should return false while open")
	}
}

func TestCircuitBreaker_HalfOpenAfterWindow(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cb.now = func() time.Time { return now }

	cb.Allow()
	cb.OnFailure(nil)
	if cb.State() != StateOpen {
		t.Fatalf("expected open, got %s", cb.State())
	}
	if cb.Allow() {
		t.Fatalf("should not allow while open")
	}

	// Advance past window.
	now = now.Add(2 * time.Minute)
	if !cb.Allow() {
		t.Fatalf("should allow half-open probe after window")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected half-open, got %s", cb.State())
	}
	// Second probe is rejected — only one at a time.
	if cb.Allow() {
		t.Fatalf("should not allow second probe in half-open")
	}

	// Success closes.
	cb.OnSuccess()
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after success, got %s", cb.State())
	}
	if !cb.Allow() {
		t.Fatalf("should allow after close")
	}
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cb.now = func() time.Time { return now }

	cb.Allow()
	cb.OnFailure(nil)

	now = now.Add(2 * time.Minute)
	if !cb.Allow() {
		t.Fatalf("should allow half-open probe")
	}
	cb.OnFailure(nil)
	if cb.State() != StateOpen {
		t.Fatalf("expected re-open after half-open failure, got %s", cb.State())
	}
	if cb.Allow() {
		t.Fatalf("should not allow while re-opened")
	}
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Minute)
	for i := 0; i < 2; i++ {
		cb.Allow()
		cb.OnFailure(nil)
	}
	// Reset via success.
	cb.Allow()
	cb.OnSuccess()
	// Now we should be able to fail two more times without tripping.
	for i := 0; i < 2; i++ {
		if !cb.Allow() {
			t.Fatalf("call %d after reset should be allowed", i)
		}
		cb.OnFailure(nil)
	}
	if cb.State() != StateClosed {
		t.Fatalf("expected still closed after 2 failures post-reset, got %s", cb.State())
	}
}

func TestCircuitBreaker_DefaultsApplied(t *testing.T) {
	cb := NewCircuitBreaker(0, 0)
	if cb.failureThreshold != DefaultBreakerFailureThreshold {
		t.Fatalf("expected default threshold %d, got %d", DefaultBreakerFailureThreshold, cb.failureThreshold)
	}
	if cb.openWindow != DefaultBreakerOpenWindow {
		t.Fatalf("expected default window %s, got %s", DefaultBreakerOpenWindow, cb.openWindow)
	}
}

func TestCircuitBreaker_LastError(t *testing.T) {
	cb := NewCircuitBreaker(2, time.Minute)
	if got := cb.LastError(); got != nil {
		t.Fatalf("LastError before any failure should be nil, got %v", got)
	}

	wantErr := errors.New("dial tcp: i/o timeout")
	cb.Allow()
	cb.OnFailure(wantErr)
	if got := cb.LastError(); got != wantErr {
		t.Fatalf("LastError after OnFailure: got %v, want %v", got, wantErr)
	}

	// Newer failure overwrites.
	newer := errors.New("connection refused")
	cb.Allow()
	cb.OnFailure(newer)
	if got := cb.LastError(); got != newer {
		t.Fatalf("LastError should be the most recent: got %v, want %v", got, newer)
	}

	// Success clears it.
	cb.OnSuccess()
	if got := cb.LastError(); got != nil {
		t.Fatalf("LastError after OnSuccess should be nil, got %v", got)
	}
}
