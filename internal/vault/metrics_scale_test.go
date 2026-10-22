/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The breaker publishes its state under the client's name.
func TestCircuitStateFollowsTheBreaker(t *testing.T) {
	b := NewCircuitBreaker(2, 0)
	b.setMetricName("circuit-test")
	t.Cleanup(func() { ForgetClient("circuit-test") })
	state := func() float64 { return testutil.ToFloat64(CircuitState.WithLabelValues("circuit-test")) }
	if got := state(); got != circuitClosedValue {
		t.Fatalf("state = %v, want closed", got)
	}
	b.Allow()
	b.OnFailure(errors.New("boom"))
	b.Allow()
	b.OnFailure(errors.New("boom"))
	if got := state(); got != circuitOpenValue {
		t.Fatalf("state = %v after the threshold, want open", got)
	}
	b.OnSuccess()
	if got := state(); got != circuitClosedValue {
		t.Fatalf("state = %v after a success, want closed", got)
	}
	ForgetClient("circuit-test")
	if CircuitState.DeleteLabelValues("circuit-test") {
		t.Fatal("the series of a forgotten client is still there")
	}
}

// Every call is observed in the latency histogram under the bounded path
// bucket, whatever the mount or role name.
func TestRequestDurationIsObservedPerBucket(t *testing.T) {
	tv := newTokenVault(t, nil)
	c := tokenClient(t, tv.URL)
	before := testutil.CollectAndCount(APIRequestDuration)
	for _, name := range []string{"a", "b", "c"} {
		_, _ = c.Do(context.Background(), &Request{Method: http.MethodGet, Path: "sys/policies/acl/" + name})
	}
	after := testutil.CollectAndCount(APIRequestDuration)
	// Three policy names, one series: the path label is the bucket.
	if after-before > 2 {
		t.Fatalf("series grew by %d for three names (login + policy bucket at most)", after-before)
	}
	if after == 0 {
		t.Fatal("no latency was observed")
	}
}
