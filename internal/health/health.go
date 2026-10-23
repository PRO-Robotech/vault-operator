/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package health holds the operators' probe checks: readiness follows the
// informer cache, liveness follows the reconciles in flight.
package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Watchdog reports a reconcile that has run longer than its stall limit. A
// worker stuck in one call serves no other object, and every external call
// the operators make carries a deadline, so a reconcile that outlives them
// all is stuck for good: the liveness probe fails and the pod is restarted.
// An idle process has nothing in flight and stays healthy.
type Watchdog struct {
	stall time.Duration
	now   func() time.Time

	mu       sync.Mutex
	next     uint64
	inFlight map[uint64]time.Time
}

// NewWatchdog returns a Watchdog with the given stall limit; now is the clock
// (nil means time.Now).
func NewWatchdog(stall time.Duration, now func() time.Time) *Watchdog {
	if now == nil {
		now = time.Now
	}
	return &Watchdog{stall: stall, now: now, inFlight: map[uint64]time.Time{}}
}

// Begin records a reconcile that starts now; the returned func ends it.
func (w *Watchdog) Begin() (end func()) {
	w.mu.Lock()
	id := w.next
	w.next++
	w.inFlight[id] = w.now()
	w.mu.Unlock()
	return func() {
		w.mu.Lock()
		delete(w.inFlight, id)
		w.mu.Unlock()
	}
}

// Check is the liveness check: it fails while a reconcile has been in flight
// for longer than the stall limit.
func (w *Watchdog) Check(_ *http.Request) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	for _, started := range w.inFlight {
		if d := now.Sub(started); d > w.stall {
			return fmt.Errorf("a reconcile has been running for %s, longer than %s", d.Round(time.Second), w.stall)
		}
	}
	return nil
}

// CacheWaiter is the part of a controller-runtime cache CacheSynced reads.
type CacheWaiter interface {
	WaitForCacheSync(ctx context.Context) bool
}

// cacheSyncWait bounds one readiness probe's wait for the cache.
const cacheSyncWait = time.Second

// CacheSynced is the readiness check: the process is ready once its informer
// cache has synced, so a pod is not sent traffic, nor counted available by a
// rollout, while it still lists the cluster.
func CacheSynced(c CacheWaiter) func(*http.Request) error {
	return func(req *http.Request) error {
		ctx, cancel := context.WithTimeout(req.Context(), cacheSyncWait)
		defer cancel()
		if !c.WaitForCacheSync(ctx) {
			return errors.New("the informer cache has not synced")
		}
		return nil
	}
}
