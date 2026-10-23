/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cloudmanager

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

// The call limit spaces cloud-manager calls out: 10/s with a burst of 1
// makes 11 lookups take about a second.
func TestClient_CallLimitSpacesCalls(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "abc-b1", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{QPS: 10, Burst: 1, FindByBucket: true})
	start := time.Now()
	for range 11 {
		if _, err := c.FindByBucket(context.Background(), "c1", "abc-b1"); err != nil {
			t.Fatalf("FindByBucket: %v", err)
		}
	}
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Fatalf("11 calls at 10/s took %s, want about 1s", d)
	}
}

// Twin: a negative QPS lifts the limit.
func TestClient_NegativeQPSLiftsTheLimit(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "abc-b1", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{QPS: -1, Burst: 1, FindByBucket: true})
	start := time.Now()
	for range 11 {
		if _, err := c.FindByBucket(context.Background(), "c1", "abc-b1"); err != nil {
			t.Fatalf("FindByBucket: %v", err)
		}
	}
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Fatalf("11 unlimited calls took %s", d)
	}
}

// Every call is observed by method and code.
func TestClient_CallsAreObserved(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "abc-b1", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{FindByBucket: true})
	if _, err := c.FindByBucket(context.Background(), "c1", "abc-b1"); err != nil {
		t.Fatalf("FindByBucket: %v", err)
	}
	if n := testutil.CollectAndCount(requestDuration, "vault_operator_cloudmanager_request_duration_seconds"); n == 0 {
		t.Fatal("no cloud-manager latency was observed")
	}
}
