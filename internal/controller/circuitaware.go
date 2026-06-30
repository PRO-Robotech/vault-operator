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
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// ReasonCircuitOpen marks a condition whose Vault call was short-circuited by an
// open breaker (no request sent), as opposed to a fresh failure.
const ReasonCircuitOpen = "CircuitOpen"

// ReasonLoginFailed marks a condition whose Vault login failed.
const ReasonLoginFailed = "LoginFailed"

// classifyVaultErr maps a breaker short-circuit to (ReasonCircuitOpen, probe-aligned
// requeue) and any other error to the fallback reason and unreachable cadence.
func classifyVaultErr(err error, fallbackReason string) (reason string, requeue time.Duration) {
	var co *vault.CircuitOpenError
	if errors.As(err, &co) {
		return ReasonCircuitOpen, requeueForCircuit(co.RetryAfter)
	}
	return fallbackReason, RequeueUnreachable
}

// requeueForCircuit aligns the next reconcile with the breaker's next probe, clamped to [2s, RequeueHealthy].
func requeueForCircuit(retryAfter time.Duration) time.Duration {
	d := retryAfter + time.Second // small buffer so the probe is actually admitted
	if d < 2*time.Second {
		d = 2 * time.Second
	}
	if d > RequeueHealthy {
		d = RequeueHealthy
	}
	return d
}
