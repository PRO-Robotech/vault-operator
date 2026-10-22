/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package operator

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// The default log is one JSON object per line at info level: V(1) is not
// written.
func TestLogOptionsWriteJSONAtInfo(t *testing.T) {
	opts := LogOptions()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	opts.BindFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	logger := zap.New(zap.UseFlagOptions(&opts), zap.WriteTo(&buf))
	logger.Info("starting manager", "k", "v")
	logger.V(1).Info("debug detail")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %q, want the info line only", lines)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line is not JSON: %q: %v", lines[0], err)
	}
	if entry["msg"] != "starting manager" || entry["k"] != "v" {
		t.Fatalf("entry = %v", entry)
	}
}

// Twin: --zap-devel still gives the console format.
func TestLogOptionsKeepTheDevelFlag(t *testing.T) {
	opts := LogOptions()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	opts.BindFlags(fs)
	if err := fs.Parse([]string{"--zap-devel"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	zap.New(zap.UseFlagOptions(&opts), zap.WriteTo(&buf)).Info("starting manager")
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatalf("--zap-devel wrote JSON: %q", buf.String())
	}
}

// The shared manager options keep Secret and ConfigMap bodies out of the
// cache and bound the shutdown.
func TestApplySetsTheSharedManagerOptions(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f.Bind(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var o ctrl.Options
	f.Apply(&o)
	if o.Cache.DefaultTransform == nil {
		t.Error("managedFields are kept in the cache")
	}
	if o.Client.Cache == nil {
		t.Fatal("no client cache options")
	}
	var secret, configMap bool
	for _, obj := range o.Client.Cache.DisableFor {
		switch obj.(type) {
		case *corev1.Secret:
			secret = true
		case *corev1.ConfigMap:
			configMap = true
		}
	}
	if !secret || !configMap {
		t.Errorf("cache disabled for Secret=%t ConfigMap=%t, want both", secret, configMap)
	}
	if !o.LeaderElectionReleaseOnCancel {
		t.Error("the leader does not step down on shutdown")
	}
	if o.GracefulShutdownTimeout == nil || *o.GracefulShutdownTimeout != 25*time.Second {
		t.Errorf("graceful shutdown = %v, want 25s", o.GracefulShutdownTimeout)
	}
}

// The default connection cap follows the worker count.
func TestVaultOptionsSizeTheConnectionsToTheWorkers(t *testing.T) {
	f := Flags{VaultTimeout: time.Second}
	if got := f.VaultOptions(4).MaxConnsPerHost; got != 6 {
		t.Errorf("4 workers: %d connections, want 6", got)
	}
	if got := f.VaultOptions(16).MaxConnsPerHost; got != 18 {
		t.Errorf("16 workers: %d connections, want 18", got)
	}
	f.VaultMaxConns = 3
	if got := f.VaultOptions(16).MaxConnsPerHost; got != 3 {
		t.Errorf("explicit cap: %d, want 3", got)
	}
}
