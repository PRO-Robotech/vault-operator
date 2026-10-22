/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/PRO-Robotech/vault-operator/internal/health"
)

type fixedResult time.Duration

func (f fixedResult) Reconcile(context.Context, reconcile.Request) (reconcile.Result, error) {
	return reconcile.Result{RequeueAfter: time.Duration(f)}, nil
}

// Jitter stretches every requeue within [d, d·(1+f)] and spreads them.
func TestRuntimeJitterSpreadsRequeues(t *testing.T) {
	const d = 10 * time.Minute
	r := Runtime{RequeueJitter: 0.15}.wrap(fixedResult(d))
	seen := map[time.Duration]bool{}
	for range 50 {
		res, err := r.Reconcile(context.Background(), reconcile.Request{})
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if res.RequeueAfter < d || res.RequeueAfter > d+d*15/100 {
			t.Fatalf("RequeueAfter = %s outside [%s, %s]", res.RequeueAfter, d, d+d*15/100)
		}
		seen[res.RequeueAfter] = true
	}
	if len(seen) < 2 {
		t.Fatal("50 requeues share one interval")
	}
}

// Twin: the zero Runtime leaves results alone.
func TestZeroRuntimeChangesNothing(t *testing.T) {
	inner := fixedResult(time.Minute)
	if got := (Runtime{}).wrap(inner); got != reconcile.Reconciler(inner) {
		t.Fatal("the zero Runtime wrapped the reconciler")
	}
	opts := Runtime{}.controllerOptions(4)
	if opts.MaxConcurrentReconciles != 4 || opts.UsePriorityQueue != nil || opts.ReconciliationTimeout != 0 {
		t.Fatalf("options = %+v", opts)
	}
	opts = Runtime{PriorityQueue: true, ReconcileTimeout: time.Minute}.controllerOptions(2)
	if opts.UsePriorityQueue == nil || !*opts.UsePriorityQueue || opts.ReconciliationTimeout != time.Minute {
		t.Fatalf("options = %+v", opts)
	}
}

// The watchdog sees a reconcile in flight through the wrapper.
func TestRuntimeTracksReconcilesInFlight(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := health.NewWatchdog(time.Minute, func() time.Time { return now })
	stuck := make(chan struct{})
	entered := make(chan struct{})
	r := Runtime{Progress: w}.wrap(reconcile.Func(func(context.Context, reconcile.Request) (reconcile.Result, error) {
		close(entered)
		<-stuck
		return reconcile.Result{}, nil
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Reconcile(context.Background(), reconcile.Request{})
	}()
	<-entered
	now = now.Add(2 * time.Minute)
	if err := w.Check(nil); err == nil {
		t.Fatal("a reconcile stuck for 2m passes a 1m watchdog")
	}
	close(stuck)
	<-done
	if err := w.Check(nil); err != nil {
		t.Fatalf("after the reconcile ended: %v", err)
	}
}
