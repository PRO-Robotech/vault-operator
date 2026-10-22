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
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/PRO-Robotech/vault-operator/internal/health"
)

// Runtime is what every reconciler of one process shares at run time. The
// zero value changes nothing: no jitter, no deadline, the default queue and
// no progress tracking.
type Runtime struct {
	// RequeueJitter stretches every RequeueAfter by a random fraction up to
	// this one, so claims started together do not keep calling Vault and
	// cloud-manager in the same second.
	RequeueJitter float64
	// ReconcileTimeout bounds one Reconcile call; 0 means no bound.
	ReconcileTimeout time.Duration
	// PriorityQueue serves events of a real change before the initial list
	// and the periodic requeues of every other object.
	PriorityQueue bool
	// Progress, when set, tracks reconciles in flight for the liveness probe.
	Progress *health.Watchdog
}

func (rt Runtime) controllerOptions(workers int) controller.Options {
	opts := controller.Options{MaxConcurrentReconciles: workers, ReconciliationTimeout: rt.ReconcileTimeout}
	if rt.PriorityQueue {
		opts.UsePriorityQueue = ptr.To(true)
	}
	return opts
}

// wrap applies the jitter and the progress tracking around r.
func (rt Runtime) wrap(r reconcile.Reconciler) reconcile.Reconciler {
	if rt.RequeueJitter <= 0 && rt.Progress == nil {
		return r
	}
	return reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
		if rt.Progress != nil {
			defer rt.Progress.Begin()()
		}
		res, err := r.Reconcile(ctx, req)
		if rt.RequeueJitter > 0 && res.RequeueAfter > 0 {
			res.RequeueAfter = wait.Jitter(res.RequeueAfter, rt.RequeueJitter)
		}
		return res, err
	})
}
