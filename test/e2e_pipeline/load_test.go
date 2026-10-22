//go:build e2e && load
// +build e2e,load

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e_pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/operator"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// Load thresholds (plan §4.3, SO-16): at most 1.2 passes per claim per ten
// minutes of steady state, and the operator process under 256 MiB RSS.
const (
	loadClaims          = 1000
	loadPassesPer10Min  = 1.2
	loadRSSLimitBytes   = 256 << 20
	loadDefaultWindow   = 10 * time.Minute
	loadReadyTimeout    = 10 * time.Minute
	loadControllerLabel = "vaultclaim"
)

// metricSum sums a counter family over the series whose labels contain want.
func metricSum(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sum float64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			for k, v := range want {
				if labels[k] != v {
					continue series
				}
			}
			sum += m.GetCounter().GetValue()
		}
	}
	return sum
}

// rssBytes is the resident set of this process: the operator's controllers,
// cache and clients (envtest and Vault run as their own processes).
func rssBytes(t *testing.T) int64 {
	t.Helper()
	f, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatalf("open /proc/self/status: %v", err)
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if fields := strings.Fields(s.Text()); len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("parse VmRSS %q: %v", s.Text(), err)
			}
			return kb << 10
		}
	}
	t.Fatal("no VmRSS in /proc/self/status")
	return 0
}

// TestLoadThousandClaimsE2E runs the VaultConfig and VaultClaim controllers
// under a manager, the way the operator runs, against Vault 1.20 with a
// thousand guest claims, and measures a steady window: passes per claim,
// Vault calls per claim, new Vault tokens and the process RSS.
func TestLoadThousandClaimsE2E(t *testing.T) {
	window := loadDefaultWindow
	if v := os.Getenv("LOAD_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("LOAD_WINDOW: %v", err)
		}
		window = d
	}
	// The window and the ramp-up both run on the harness context.
	h := newHarnessWithin(t, "", window+loadReadyTimeout+5*time.Minute)
	h.vaultConfig("default", mgmtRole)
	h.namespace("load")
	// The claims log nothing the measurement reads; info level keeps the
	// thousand passes from flooding the job log.
	logf.SetLogger(zap.New(zap.WriteTo(os.Stderr)))

	mgrOpts := ctrl.Options{
		Scheme:                 h.scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	}
	operator.ApplyCacheOptions(&mgrOpts)
	mgr, err := ctrl.NewManager(h.cfg, mgrOpts)
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	rt := controller.Runtime{RequeueJitter: operator.DefaultRequeueJitter, ReconcileTimeout: operator.DefaultReconcileTimeout}
	if err := (&controller.VaultConfigReconciler{
		Client: mgr.GetClient(), Scheme: h.scheme, VaultFactory: h.factory, Runtime: rt,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("VaultConfig controller: %v", err)
	}
	if err := (&controller.VaultClaimReconciler{
		Client: mgr.GetClient(), Scheme: h.scheme, VaultFactory: h.factory,
		TargetManager: target.NewClusterManager(h.scheme), Runtime: rt,
	}).SetupWithManager(mgr); err != nil {
		t.Fatalf("VaultClaim controller: %v", err)
	}
	ctx, stop := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})

	start := time.Now()
	for i := range loadClaims {
		name := fmt.Sprintf("load-%d", i)
		c := guestClaim("load", name, name)
		c.Spec.Roles[0].Policies = []string{name + "-read"}
		if err := h.k8s.Create(h.ctx, c); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	ready := func() int {
		var list vaultv1alpha1.VaultClaimList
		if err := h.k8s.List(h.ctx, &list, client.InNamespace("load")); err != nil {
			t.Fatalf("list claims: %v", err)
		}
		n := 0
		for i := range list.Items {
			if list.Items[i].Status.Phase == vaultv1alpha1.PhaseReady {
				n++
			}
		}
		return n
	}
	for n := ready(); n < loadClaims; n = ready() {
		if time.Since(start) > loadReadyTimeout {
			t.Fatalf("%d of %d claims Ready after %s", n, loadClaims, loadReadyTimeout)
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("%d claims Ready in %s", loadClaims, time.Since(start).Round(time.Second))

	passes0 := metricSum(t, "controller_runtime_reconcile_total", map[string]string{"controller": loadControllerLabel})
	calls0 := metricSum(t, "vault_api_calls_total", nil)
	tokens0 := len(h.listKeys("auth/token/accessors"))
	time.Sleep(window)
	passes := metricSum(t, "controller_runtime_reconcile_total", map[string]string{"controller": loadControllerLabel}) - passes0
	calls := metricSum(t, "vault_api_calls_total", nil) - calls0
	tokens := len(h.listKeys("auth/token/accessors")) - tokens0
	rss := rssBytes(t)

	perClaim := passes / loadClaims
	limit := loadPassesPer10Min * window.Minutes() / 10
	t.Logf("window %s: %.0f passes (%.2f per claim, limit %.2f), %.0f Vault calls (%.2f per claim), %d new tokens, RSS %d MiB",
		window, passes, perClaim, limit, calls, calls/loadClaims, tokens, rss>>20)
	if perClaim > limit {
		t.Errorf("%.2f passes per claim in %s, limit %.2f", perClaim, window, limit)
	}
	if tokens != 0 {
		t.Errorf("%d Vault tokens created in the steady window, want 0", tokens)
	}
	if rss > loadRSSLimitBytes {
		t.Errorf("RSS %d MiB, limit %d MiB", rss>>20, loadRSSLimitBytes>>20)
	}
	if n := ready(); n != loadClaims {
		t.Errorf("%d of %d claims Ready after the window", n, loadClaims)
	}
}
