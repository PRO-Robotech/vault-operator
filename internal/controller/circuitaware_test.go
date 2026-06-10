/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

func TestRequeueForCircuit_Clamps(t *testing.T) {
	if got := requeueForCircuit(0); got != 2*time.Second {
		t.Fatalf("zero retry should clamp to the 2s floor, got %s", got)
	}
	if got := requeueForCircuit(45 * time.Second); got != 46*time.Second {
		t.Fatalf("expected retry+1s buffer, got %s", got)
	}
	if got := requeueForCircuit(time.Hour); got != RequeueHealthy {
		t.Fatalf("large retry should clamp to RequeueHealthy, got %s", got)
	}
}

func TestClassifyVaultErr(t *testing.T) {
	// A generic error keeps the caller's fallback reason and the unreachable cadence.
	reason, requeue := classifyVaultErr(errors.New("boom"), "LoginFailed")
	if reason != "LoginFailed" || requeue != RequeueUnreachable {
		t.Fatalf("generic error: got (%s, %s), want (LoginFailed, %s)", reason, requeue, RequeueUnreachable)
	}

	// A wrapped short-circuit flips to CircuitOpen with a probe-aligned requeue.
	co := &vault.CircuitOpenError{LastErr: errors.New("dns"), RetryAfter: 20 * time.Second}
	wrapped := fmt.Errorf("vault login: %w", co)
	reason, requeue = classifyVaultErr(wrapped, "LoginFailed")
	if reason != ReasonCircuitOpen {
		t.Fatalf("circuit error: expected reason %s, got %s", ReasonCircuitOpen, reason)
	}
	if requeue != 21*time.Second {
		t.Fatalf("circuit error: expected aligned requeue 21s, got %s", requeue)
	}
}
