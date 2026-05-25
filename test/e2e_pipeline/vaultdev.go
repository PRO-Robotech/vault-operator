/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package e2e_pipeline contains end-to-end tests that exercise the full
// VaultClaim pipeline against a real `vault server -dev` instance plus envtest
// k8s. Build-gated with `e2e` (run via `make test-e2e-pipeline`).
//
// These tests skip cleanly when the `vault` binary is not in PATH, so the
// local dev workflow (`make test`) is unaffected.
package e2e_pipeline

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// VaultDevServer is a process handle for an out-of-process `vault server -dev`
// instance. Use NewVaultDevServer to spawn one and call Close to terminate.
type VaultDevServer struct {
	cmd       *exec.Cmd
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer

	// Addr is the http://127.0.0.1:PORT base URL of the Vault HTTP API.
	Addr string

	// RootToken is the dev-mode root token printed on stdout. Bootstrap helpers
	// use it; the operator itself logs in as `vault-operator` once bootstrap
	// is complete.
	RootToken string
}

// NewVaultDevServer spawns `vault server -dev -dev-listen-address=127.0.0.1:0`
// in the background and parses its stdout for the actual listen address and
// root token. The function blocks until Vault reports it is unsealed (or
// `startupTimeout` elapses).
//
// If the `vault` binary cannot be located in $PATH, an error wrapping
// ErrVaultBinaryMissing is returned — callers should Skip the test rather
// than fail.
func NewVaultDevServer(ctx context.Context) (*VaultDevServer, error) {
	if _, err := exec.LookPath("vault"); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultBinaryMissing, err)
	}

	cmd := exec.CommandContext(ctx, "vault", "server",
		"-dev",
		"-dev-listen-address=127.0.0.1:0",
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

	srv := &VaultDevServer{cmd: cmd, stdoutBuf: stdout, stderrBuf: stderr}

	// Vault dev prints API address + root token to stdout. Wait for both.
	const startupTimeout = 10 * time.Second
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		if srv.parseStartupBanner() && srv.Addr != "" && srv.RootToken != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if srv.Addr == "" || srv.RootToken == "" {
		_ = srv.Close()
		return nil, fmt.Errorf("vault did not announce listen address/root token within %s; stdout=%q stderr=%q",
			startupTimeout, stdout.String(), stderr.String())
	}

	// Probe the API until it responds. Some seconds may elapse between the
	// banner and the listener actually accepting connections.
	if err := srv.waitReady(ctx, 5*time.Second); err != nil {
		_ = srv.Close()
		return nil, err
	}
	return srv, nil
}

// ErrVaultBinaryMissing is wrapped by NewVaultDevServer when `vault` is not in
// PATH. Test fixtures should `errors.Is` this and Skip rather than Fail.
var ErrVaultBinaryMissing = errors.New("vault binary not found in PATH")

var (
	// Vault dev banner formats vary slightly across versions; match both
	// "Api Address: http://..." and "API Address: http://..." plus the
	// uppercase "Root Token:".
	addrRegexp  = regexp.MustCompile(`(?i)Api Address:\s*(http[^\s]+)`)
	tokenRegexp = regexp.MustCompile(`Root Token:\s*(\S+)`)
)

// parseStartupBanner scans the captured stdout for Vault's startup banner. It
// is called repeatedly; once both fields are populated they stay set.
func (s *VaultDevServer) parseStartupBanner() bool {
	if s.Addr != "" && s.RootToken != "" {
		return true
	}
	r := bufio.NewReader(bytes.NewReader(s.stdoutBuf.Bytes()))
	for {
		line, err := r.ReadString('\n')
		if s.Addr == "" {
			if m := addrRegexp.FindStringSubmatch(line); len(m) == 2 {
				s.Addr = strings.TrimRight(m[1], "/")
			}
		}
		if s.RootToken == "" {
			if m := tokenRegexp.FindStringSubmatch(line); len(m) == 2 {
				s.RootToken = m[1]
			}
		}
		if err == io.EOF {
			break
		}
	}
	return s.Addr != "" && s.RootToken != ""
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
