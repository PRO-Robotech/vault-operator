/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package s3sweeper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const testToken = "glpat-test-token-31d"

func newGitLab(t *testing.T, h http.HandlerFunc) (*httptest.Server, *GitLabJobs) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jobs, err := NewGitLabJobs(srv.URL+"/api/v4/projects/2274/jobs/{job}", "PRIVATE-TOKEN", testToken, srv.Client())
	if err != nil {
		t.Fatalf("NewGitLabJobs: %v", err)
	}
	return srv, jobs
}

// assertNoLeak: текст ошибки не несёт ни адреса, ни токена.
func assertNoLeak(t *testing.T, srv *httptest.Server, err error) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	for _, bad := range []string{u.Host, u.Hostname(), testToken} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("error %q carries %q", err, bad)
		}
	}
}

func TestGitLabJobs_ReadsTheStatusWithTheTokenHeader(t *testing.T) {
	_, jobs := newGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/2274/jobs/77" {
			http.Error(w, "path", http.StatusBadRequest)
			return
		}
		if r.Header.Get("PRIVATE-TOKEN") != testToken {
			http.Error(w, "token", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":77,"status":"success","name":"kind-full"}`))
	})
	st, err := jobs.JobStatus(context.Background(), 77)
	if err != nil || st != "success" {
		t.Fatalf("JobStatus = %q, %v, want success", st, err)
	}
}

func TestGitLabJobs_RefusalsAreNamedWithoutAddressOrToken(t *testing.T) {
	cases := map[string]struct {
		h    http.HandlerFunc
		want error
	}{
		"not found": {func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }, ErrJobNotFound},
		"server error": {func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}, ErrJobLookup},
		"forbidden": {func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusForbidden)
		}, ErrJobLookup},
		"another job": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":78,"status":"success"}`))
		}, ErrJobLookup},
		"no status": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":77}`))
		}, ErrJobLookup},
		"not json": {func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html>`))
		}, ErrJobLookup},
	}
	for name, c := range cases {
		srv, jobs := newGitLab(t, c.h)
		_, err := jobs.JobStatus(context.Background(), 77)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
			continue
		}
		assertNoLeak(t, srv, err)
	}
}

// Перенаправление не исполняется: токен не уходит по адресу из ответа.
func TestGitLabJobs_DoesNotFollowARedirect(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"id":77,"status":"success"}`))
	}))
	defer elsewhere.Close()
	srv, jobs := newGitLab(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/x", http.StatusFound)
	})
	_, err := jobs.JobStatus(context.Background(), 77)
	if !errors.Is(err, ErrJobLookup) {
		t.Fatalf("err = %v, want ErrJobLookup", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect target hit %d times, want 0", hits.Load())
	}
	assertNoLeak(t, srv, err)
}

func TestGitLabJobs_RefusedConnectionNamesNoAddress(t *testing.T) {
	srv, jobs := newGitLab(t, func(http.ResponseWriter, *http.Request) {})
	srv.Close()
	_, err := jobs.JobStatus(context.Background(), 77)
	if !errors.Is(err, ErrJobLookup) {
		t.Fatalf("err = %v, want ErrJobLookup", err)
	}
	assertNoLeak(t, srv, err)
}

func TestNewGitLabJobs_RefusesAnUnsafeTemplate(t *testing.T) {
	for _, tmpl := range []string{
		"",
		"http://gitlab.example.test/api/v4/projects/2274/jobs/{job}",
		"https://gitlab.example.test/api/v4/projects/2274/jobs/",
		"https://gitlab.example.test/{job}/jobs/{job}",
		"https://user:pass@gitlab.example.test/jobs/{job}",
		"https:///jobs/{job}",
		"gitlab.example.test/jobs/{job}",
	} {
		if _, err := NewGitLabJobs(tmpl, "PRIVATE-TOKEN", testToken, nil); err == nil {
			t.Errorf("template %q: err = nil, want a refusal", tmpl)
		}
	}
	if _, err := NewGitLabJobs("https://gitlab.example.test/jobs/{job}", "X-Other", testToken, nil); err == nil {
		t.Error("unknown token header: err = nil, want a refusal")
	}
}

func TestClassifyJobStatus(t *testing.T) {
	for _, s := range []string{"success", "failed", "canceled", "skipped"} {
		if got := ClassifyJobStatus(s); got != JobFinished {
			t.Errorf("%q = %v, want finished", s, got)
		}
	}
	for _, s := range []string{"created", "pending", "running", "preparing", "scheduled", "manual",
		"waiting_for_resource", "waiting_for_callback", "canceling"} {
		if got := ClassifyJobStatus(s); got != JobAlive {
			t.Errorf("%q = %v, want alive", s, got)
		}
	}
	for _, s := range []string{"", "weird", "SUCCESS"} {
		if got := ClassifyJobStatus(s); got != JobUnknown {
			t.Errorf("%q = %v, want unknown", s, got)
		}
	}
}
