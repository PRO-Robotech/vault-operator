/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package operator is the process wiring the three operator binaries share:
// the run-time flags, the manager options, the probes and the log format.
package operator

import (
	"flag"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/health"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// Defaults of the run-time flags.
const (
	DefaultRequeueJitter    = 0.15
	DefaultReconcileTimeout = 5 * time.Minute
	DefaultShutdownTimeout  = 25 * time.Second
	DefaultVaultTimeout     = 10 * time.Second
	// stallWithoutTimeout is the watchdog limit when reconciles have no
	// deadline of their own.
	stallWithoutTimeout = 10 * time.Minute
)

// Flags are the run-time knobs every binary exposes.
type Flags struct {
	VaultQPS         float64
	VaultBurst       int
	VaultMaxConns    int
	VaultTimeout     time.Duration
	RequeueJitter    float64
	ReconcileTimeout time.Duration
	PriorityQueue    bool
	ShutdownTimeout  time.Duration
}

// Bind registers the flags on fs.
func (f *Flags) Bind(fs *flag.FlagSet) {
	fs.Float64Var(&f.VaultQPS, "vault-qps", vault.DefaultQPS,
		"Requests per second to Vault, per VaultConfig; a negative value disables the limit.")
	fs.IntVar(&f.VaultBurst, "vault-burst", vault.DefaultBurst, "Burst of the Vault request limit.")
	fs.IntVar(&f.VaultMaxConns, "vault-max-conns", 0,
		"Connections to Vault per VaultConfig; 0 picks the larger of 6 and the controller's workers plus 2.")
	fs.DurationVar(&f.VaultTimeout, "vault-timeout", DefaultVaultTimeout, "Deadline of one Vault HTTP call.")
	fs.Float64Var(&f.RequeueJitter, "requeue-jitter", DefaultRequeueJitter,
		"Every requeue interval is stretched by a random fraction up to this one; 0 disables it.")
	fs.DurationVar(&f.ReconcileTimeout, "reconcile-timeout", DefaultReconcileTimeout,
		"Deadline of one reconcile; 0 disables it. The liveness probe fails on a reconcile running twice as long.")
	fs.BoolVar(&f.PriorityQueue, "priority-queue", false,
		"Serve events of a real change before the initial list and periodic requeues (controller-runtime priority queue).")
	fs.DurationVar(&f.ShutdownTimeout, "graceful-shutdown-timeout", DefaultShutdownTimeout,
		"Time the reconciles in flight get to finish on shutdown; keep it below terminationGracePeriodSeconds.")
}

// VaultOptions are the client options for a process whose busiest
// controller runs workers reconciles in parallel.
func (f *Flags) VaultOptions(workers int) controller.VaultClientOptions {
	conns := f.VaultMaxConns
	if conns <= 0 {
		conns = max(vault.DefaultMaxConnsPerHost, workers+2)
	}
	return controller.VaultClientOptions{Timeout: f.VaultTimeout, QPS: f.VaultQPS, Burst: f.VaultBurst, MaxConnsPerHost: conns}
}

// NewWatchdog returns the liveness watchdog: a reconcile running twice its
// deadline has outlived every timeout below it.
func (f *Flags) NewWatchdog() *health.Watchdog {
	stall := 2 * f.ReconcileTimeout
	if stall <= 0 {
		stall = stallWithoutTimeout
	}
	return health.NewWatchdog(stall, nil)
}

// Runtime is the reconcile settings of the process.
func (f *Flags) Runtime(progress *health.Watchdog) controller.Runtime {
	return controller.Runtime{
		RequeueJitter:    f.RequeueJitter,
		ReconcileTimeout: f.ReconcileTimeout,
		PriorityQueue:    f.PriorityQueue,
		Progress:         progress,
	}
}

// Apply sets the manager options every binary shares: no Secret or ConfigMap
// body in the informer cache (they are read live), no managedFields in it,
// a leader that steps down on shutdown, and a bounded graceful shutdown.
func (f *Flags) Apply(o *ctrl.Options) {
	ApplyCacheOptions(o)
	o.LeaderElectionReleaseOnCancel = true
	shutdown := f.ShutdownTimeout
	o.GracefulShutdownTimeout = &shutdown
}

// ApplyCacheOptions keeps Secret and ConfigMap bodies out of the informer
// cache and strips managedFields from what it holds. Reads of a Secret or a
// ConfigMap go to the API server; Secret events come from a metadata watch.
func ApplyCacheOptions(o *ctrl.Options) {
	o.Cache.DefaultTransform = cache.TransformStripManagedFields()
	o.Client.Cache = &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}}}
}

// AddProbes registers the probes: readyz passes once the informer cache has
// synced, healthz fails while a reconcile is stuck.
func AddProbes(mgr ctrl.Manager, progress *health.Watchdog) error {
	if err := mgr.AddHealthzCheck("reconcile-progress", progress.Check); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("informer-cache", health.CacheSynced(mgr.GetCache())); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}
	return nil
}

// LogOptions log JSON at info level; --zap-devel and the other zap flags
// still override it.
func LogOptions() zap.Options {
	return zap.Options{Development: false}
}
