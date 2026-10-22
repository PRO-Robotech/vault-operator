/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package health

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// A reconcile stuck past the limit fails the check; the twin that ended in
// time, and an idle process, pass.
func TestWatchdogFailsOnlyOnAStuckReconcile(t *testing.T) {
	clock := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	w := NewWatchdog(10*time.Minute, clock.Now)
	req := httptest.NewRequest("GET", "/healthz", nil)

	if err := w.Check(req); err != nil {
		t.Fatalf("idle: %v", err)
	}
	done := w.Begin()
	clock.advance(9 * time.Minute)
	if err := w.Check(req); err != nil {
		t.Fatalf("a reconcile within the limit: %v", err)
	}
	done()
	clock.advance(time.Hour)
	if err := w.Check(req); err != nil {
		t.Fatalf("a reconcile that ended long ago: %v", err)
	}

	stuck := w.Begin()
	clock.advance(11 * time.Minute)
	err := w.Check(req)
	if err == nil || !strings.Contains(err.Error(), "longer than 10m0s") {
		t.Fatalf("stuck reconcile: %v, want a stall error", err)
	}
	stuck()
	if err := w.Check(req); err != nil {
		t.Fatalf("after the stuck reconcile ended: %v", err)
	}
}

type waiter bool

func (w waiter) WaitForCacheSync(ctx context.Context) bool {
	if !w {
		<-ctx.Done()
	}
	return bool(w)
}

func TestCacheSyncedFollowsTheCache(t *testing.T) {
	req := httptest.NewRequest("GET", "/readyz", nil)
	if err := CacheSynced(waiter(true))(req); err != nil {
		t.Fatalf("synced cache: %v", err)
	}
	if err := CacheSynced(waiter(false))(req); err == nil {
		t.Fatal("an unsynced cache is reported ready")
	}
}
