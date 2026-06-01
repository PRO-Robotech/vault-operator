/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"sync"
	"time"
)

type circuitState int

const (
	stateClosed circuitState = iota
	stateOpen
	stateHalfOpen
)

const (
	DefaultBreakerFailureThreshold = 5
	DefaultBreakerOpenWindow       = 2 * time.Minute
)

// CircuitBreaker guards Vault HTTP calls. After failureThreshold consecutive
// failures it trips open and short-circuits all calls with ErrCircuitOpen for
// openWindow. After the window it admits one half-open probe — success closes,
// failure re-opens for another window. Concurrency-safe.
type CircuitBreaker struct {
	failureThreshold int
	openWindow       time.Duration

	now func() time.Time

	mu          sync.Mutex
	state       circuitState
	failures    int
	openedAt    time.Time
	probePinned bool
	lastErr     error
}

// NewCircuitBreaker constructs a breaker. Zero values fall back to
// DefaultBreakerFailureThreshold and DefaultBreakerOpenWindow.
func NewCircuitBreaker(failureThreshold int, openWindow time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = DefaultBreakerFailureThreshold
	}
	if openWindow <= 0 {
		openWindow = DefaultBreakerOpenWindow
	}
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		openWindow:       openWindow,
		now:              time.Now,
	}
}

func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case stateClosed:
		return true
	case stateOpen:
		if b.now().Sub(b.openedAt) >= b.openWindow {
			b.state = stateHalfOpen
			b.probePinned = true
			return true
		}
		return false
	case stateHalfOpen:
		// One probe at a time.
		if b.probePinned {
			return false
		}
		b.probePinned = true
		return true
	}
	return false
}

func (b *CircuitBreaker) OnSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.state = stateClosed
	b.probePinned = false
	b.lastErr = nil
}

func (b *CircuitBreaker) OnFailure(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastErr = err

	switch b.state {
	case stateClosed:
		b.failures++
		if b.failures >= b.failureThreshold {
			b.state = stateOpen
			b.openedAt = b.now()
		}
	case stateHalfOpen:
		b.state = stateOpen
		b.openedAt = b.now()
		b.probePinned = false
	}
}

// LastError returns the error that most recently tripped or hit the breaker.
// Nil before the first OnFailure call. Safe for concurrent use.
func (b *CircuitBreaker) LastError() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

const (
	StateClosed   = "closed"
	StateOpen     = "open"
	StateHalfOpen = "half-open"
	StateUnknown  = "unknown"
)

func (b *CircuitBreaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case stateClosed:
		return StateClosed
	case stateOpen:
		return StateOpen
	case stateHalfOpen:
		return StateHalfOpen
	}
	return StateUnknown
}
