/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package e2e_pipeline contains end-to-end tests that exercise the full
// VaultClaim / VaultSecretClaim pipelines against a real `vault server -dev`
// instance plus envtest k8s. Build-gated with `e2e`.
//
// They are not part of `make test` (build tag), and they fail, not skip, when
// the `vault` binary is missing or is not the version production runs
// (E2E_VAULT_VERSION, default 1.20.1): a skipped or mismatched run executes
// nothing about production and must not read as green. `make
// test-e2e-pipeline` downloads the pinned binary into bin/.
package e2e_pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// StartVaultDev starts a dev Vault for t and stops it in t.Cleanup. It fails
// t when NewVaultDevServer refuses: the binary is missing or is not the
// wanted version.
func StartVaultDev(ctx context.Context, t *testing.T) *VaultDevServer {
	t.Helper()
	srv, err := NewVaultDevServer(ctx)
	if err != nil {
		t.Fatalf("start vault dev: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// VaultDevServer is a process handle for an out-of-process `vault server -dev`
// instance. Use NewVaultDevServer to spawn one and call Close to terminate.
type VaultDevServer struct {
	cmd       *exec.Cmd
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer

	// Addr is the http://127.0.0.1:PORT base URL of the Vault HTTP API.
	Addr string

	// RootToken is the dev-mode root token (set via -dev-root-token-id).
	RootToken string
}

// devRootToken is fixed: each test spawns its own isolated Vault.
const devRootToken = "root-e2e"

// NewVaultDevServer spawns `vault server -dev` on a self-allocated port (Vault's
// `-dev-listen-address=:0` reports a literal ":0" we can't parse back) with a
// known root token, then waits until the API answers. A missing `vault` binary
// returns an error wrapping ErrVaultBinaryMissing, a different version
// ErrVaultVersionMismatch; callers fail on both.
func NewVaultDevServer(ctx context.Context) (*VaultDevServer, error) {
	if _, err := exec.LookPath("vault"); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultBinaryMissing, err)
	}
	want := os.Getenv("E2E_VAULT_VERSION")
	if want == "" {
		want = DefaultVaultVersion
	}
	out, err := exec.CommandContext(ctx, "vault", "version").Output()
	if err != nil {
		return nil, fmt.Errorf("vault version: %w", err)
	}
	if !strings.HasPrefix(string(out), "Vault v"+want+" ") {
		return nil, fmt.Errorf("%w: want v%s, got %q", ErrVaultVersionMismatch, want, strings.TrimSpace(string(out)))
	}

	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("allocate vault port: %w", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.CommandContext(ctx, "vault", "server",
		"-dev",
		"-dev-listen-address="+listenAddr,
		"-dev-root-token-id="+devRootToken,
	)
	// Send Vault its own process group so we can kill the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start vault server: %w", err)
	}

	srv := &VaultDevServer{
		cmd:       cmd,
		stdoutBuf: stdout,
		stderrBuf: stderr,
		Addr:      "http://" + listenAddr,
		RootToken: devRootToken,
	}

	const startupTimeout = 15 * time.Second
	if err := srv.waitReady(ctx, startupTimeout); err != nil {
		_ = srv.Close()
		return nil, fmt.Errorf("vault dev not ready: %w; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	return srv, nil
}

// ErrVaultBinaryMissing is wrapped by NewVaultDevServer when `vault` is not in
// PATH.
var ErrVaultBinaryMissing = errors.New("vault binary not found in PATH")

// ErrVaultVersionMismatch is wrapped when `vault version` is not the wanted one.
var ErrVaultVersionMismatch = errors.New("vault binary is not the wanted version")

// DefaultVaultVersion is the Vault production runs.
const DefaultVaultVersion = "1.20.1"

// freePort asks the OS for an unused TCP port on loopback. There is a small
// race between closing the probe listener and Vault binding it; acceptable for
// single-host test fixtures.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitReady polls GET /v1/sys/seal-status until it returns 200, or the
// deadline elapses.
func (s *VaultDevServer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Addr+"/v1/sys/seal-status", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("vault dev not ready within %s", timeout)
}

// Close terminates Vault and waits for the process to exit.
func (s *VaultDevServer) Close() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
	_ = s.cmd.Wait()
	return nil
}
