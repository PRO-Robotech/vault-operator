/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

const (
	login      = "dlputi1u"
	secretMark = "do-not-print-5c2e"
	// fakeAddr — адрес, который сюда передан и в журнал попасть не должен.
	fakeAddr = "10.9.8.7:50051"
)

// serveTCP поднимает двойник cloud-manager на настоящем сокете: команда
// звонит ему тем же путём, что службе.
func serveTCP(t *testing.T, srv *cmfake.Server) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := grpc.NewServer()
	pb.RegisterCloudServiceServer(g, srv)
	pb.RegisterCloudS3ServiceServer(g, srv)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	return lis.Addr().String()
}

// closedAddr — адрес, на котором никто не слушает.
func closedAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	return addr
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// seed сеет живой (RUNNING) бакет владельца login с ключами, которых в журнале
// быть не должно; иного статуса пробам команды не нужно.
func seed(srv *cmfake.Server, name string) {
	srv.Seed(&pb.Bucket{Name: name, CustLogin: login, Status: pb.Status_RUNNING,
		AccessKey: "AK-" + secretMark, SecretKey: "SK-" + secretMark})
}

func assertClean(t *testing.T, out string, addrs ...string) {
	t.Helper()
	for _, bad := range append(addrs, secretMark) {
		if strings.Contains(out, bad) {
			t.Fatalf("stderr carries %q:\n%s", bad, out)
		}
	}
}

func TestRun_UsageErrorsExitTwoBeforeAnyCall(t *testing.T) {
	addrEnv := map[string]string{"CLOUD_MANAGER_ADDR": fakeAddr}
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"no mode":        {nil, addrEnv},
		"unknown mode":   {[]string{"purge", "--login", login}, addrEnv},
		"job without id": {[]string{"job", "--login", login}, addrEnv},
		"job id not num": {[]string{"job", "--login", login, "--job-id", "12a"}, addrEnv},
		"job id zero":    {[]string{"job", "--login", login, "--job-id", "0"}, addrEnv},
		"job id empty":   {[]string{"job", "--login", login, "--job-id", ""}, addrEnv},
		"no login":       {[]string{"job", "--job-id", "5"}, addrEnv},
		"empty login":    {[]string{"job", "--login", "", "--job-id", "5"}, addrEnv},
		"bad login":      {[]string{"job", "--login", "Bad Login", "--job-id", "5"}, addrEnv},
		"no address":     {[]string{"job", "--login", login, "--job-id", "5"}, nil},
		"stray argument": {[]string{"job", "--login", login, "--job-id", "5", "extra"}, addrEnv},
		"sweep no alive": {[]string{"sweep", "--login", login}, addrEnv},
		"sweep http alive": {[]string{"sweep", "--login", login,
			"--job-alive", "http://gl.example.test/jobs/{job}"}, addrEnv},
		"sweep job id": {[]string{"sweep", "--login", login, "--job-id", "5",
			"--job-alive", "https://gl.example.test/jobs/{job}"}, addrEnv},
		"zero timeout": {[]string{"job", "--login", login, "--job-id", "5", "--timeout", "0s"}, addrEnv},
	}
	for name, c := range cases {
		var stderr bytes.Buffer
		code := run(context.Background(), c.args, env(c.env), &stderr, nil)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, code, stderr.String())
		}
		if stderr.Len() == 0 {
			t.Errorf("%s: stderr is empty, want the refusal named", name)
		}
		assertClean(t, stderr.String(), fakeAddr)
	}
}

// Режим job против двойника по сети: свои бакеты сняты до REMOVED, соседний
// не тронут, код 0; адрес берётся флагом и в журнал не попадает.
func TestRun_JobRemovesTheJobBucketsOverTheNetwork(t *testing.T) {
	srv := cmfake.New()
	addr := serveTCP(t, srv)
	own := cmfake.Prefix(login) + "-k8s-" + login + "-ci-4242"
	other := cmfake.Prefix(login) + "-k8s-" + login + "-ci-4243"
	seed(srv, own)
	seed(srv, other)

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"job", "--cloud-manager-addr", addr, "--login", login,
		"--job-id", "4242", "--poll-interval", "5ms", "--timeout", "10s"}, env(nil), &stderr, nil)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, stderr.String())
	}
	if st := srv.Get(own).GetStatus(); st != pb.Status_REMOVED {
		t.Errorf("own bucket: %s, want REMOVED", st)
	}
	if st := srv.Get(other).GetStatus(); st != pb.Status_RUNNING {
		t.Errorf("another job's bucket: %s, want RUNNING", st)
	}
	assertClean(t, stderr.String(), addr)
}

// Адрес из переменной окружения; --dry-run ничего не снимает и выходит с 0.
func TestRun_AddressFromEnvAndDryRun(t *testing.T) {
	srv := cmfake.New()
	addr := serveTCP(t, srv)
	own := cmfake.Prefix(login) + "-k8s-" + login + "-ci-31"
	seed(srv, own)

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"job", "--login", login, "--job-id", "31", "--dry-run"},
		env(map[string]string{"CLOUD_MANAGER_ADDR": addr}), &stderr, nil)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), own) {
		t.Errorf("plan does not name %s:\n%s", own, stderr.String())
	}
	if _, _, removes := srv.Counters(); removes != 0 {
		t.Errorf("removeBucket calls = %d, want 0 under --dry-run", removes)
	}
	assertClean(t, stderr.String(), addr)
}

// Служба недоступна: код 1, адреса в журнале нет.
func TestRun_RefusedConnectionIsRedWithoutTheAddress(t *testing.T) {
	addr := closedAddr(t)
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"job", "--cloud-manager-addr", addr, "--login", login,
		"--job-id", "5", "--poll-interval", "20ms", "--timeout", "300ms", "--call-timeout", "200ms"}, env(nil), &stderr, nil)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, stderr.String())
	}
	host, _, _ := net.SplitHostPort(addr)
	assertClean(t, stderr.String(), addr, host)
}

// Режим sweep: статус задания из API CI, токен — из окружения; бакет
// завершённого задания снят, идущего — нет.
func TestRun_SweepAsksTheJobStatus(t *testing.T) {
	srv := cmfake.New()
	addr := serveTCP(t, srv)
	done := cmfake.Prefix(login) + "-k8s-" + login + "-ci-100"
	alive := cmfake.Prefix(login) + "-k8s-" + login + "-ci-200"
	seed(srv, done)
	seed(srv, alive)
	gl := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "tok-1" {
			http.Error(w, "token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/jobs/100":
			_, _ = w.Write([]byte(`{"id":100,"status":"failed"}`))
		case "/jobs/200":
			_, _ = w.Write([]byte(`{"id":200,"status":"running"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gl.Close()

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"sweep", "--cloud-manager-addr", addr, "--login", login,
		"--job-alive", gl.URL + "/jobs/{job}", "--poll-interval", "5ms", "--timeout", "10s"},
		env(map[string]string{"S3_SWEEPER_GITLAB_TOKEN": "tok-1"}), &stderr, gl.Client())
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, stderr.String())
	}
	if st := srv.Get(done).GetStatus(); st != pb.Status_REMOVED {
		t.Errorf("finished job bucket: %s, want REMOVED", st)
	}
	if st := srv.Get(alive).GetStatus(); st != pb.Status_RUNNING {
		t.Errorf("running job bucket: %s, want RUNNING", st)
	}
	assertClean(t, stderr.String(), addr, strings.TrimPrefix(gl.URL, "https://"), "tok-1")
}
