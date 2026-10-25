/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cloudmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

func newTestClient(t *testing.T, srv *cmfake.Server, opts Options) *Client {
	t.Helper()
	l := cmfake.Serve(srv)
	t.Cleanup(l.Stop)
	conn, err := l.Dial()
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	c := NewFromConn(conn, opts)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func seedBucket(srv *cmfake.Server, name, login string, st pb.Status) {
	srv.Seed(&pb.Bucket{Name: name, CustLogin: login, Status: st, AccessKey: "AK", SecretKey: "SK"})
}

// A hanging server must not hang the caller past the per-call timeout (the
// create deadline for create).
func TestClient_HangingServerIsCutByTheCallTimeout(t *testing.T) {
	srv := cmfake.New()
	srv.HangFindAll = true
	srv.HangCreate = true
	srv.HangRemove = true
	const timeout = 200 * time.Millisecond
	c := newTestClient(t, srv, Options{CallTimeout: timeout, CreateTimeout: timeout})

	calls := map[string]func(context.Context) error{
		"findAll": func(ctx context.Context) error { _, err := c.FindByBucket(ctx, "c1", "b1"); return err },
		"create": func(ctx context.Context) error {
			_, err := c.Create(ctx, CreateInput{CustomerLogin: "c1", BucketName: "b1"})
			return err
		},
		"remove": func(ctx context.Context) error { return c.Remove(ctx, "b1") },
	}
	for name, call := range calls {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		err := call(ctx)
		took := time.Since(start)
		cancel()
		if status.Code(errors.Unwrap(err)) != codes.DeadlineExceeded && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want DeadlineExceeded", name, err)
		}
		if took > timeout+time.Second {
			t.Errorf("%s: took %s, want <= %s + 1s", name, took, timeout)
		}
	}
}

// A known name is queried by ByBucket alone, so a bucket of another login comes
// back and is recognised as foreign instead of looking absent.
func TestClient_FindByBucketQueriesByBucketOnly(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "aa11-k8s-c1-x", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{FindByBucket: true})

	b, err := c.FindByBucket(context.Background(), "c1", "aa11-k8s-c1-x")
	if err != nil {
		t.Fatalf("FindByBucket: %v", err)
	}
	if b.Name != "aa11-k8s-c1-x" {
		t.Fatalf("name = %q", b.Name)
	}
	if len(srv.LastScopes) != 1 {
		t.Fatalf("scopes = %v, want one", srv.LastScopes)
	}
	bb := srv.LastScopes[0].GetByBucket()
	if bb == nil || len(bb.GetName()) != 1 || bb.GetName()[0] != "aa11-k8s-c1-x" {
		t.Fatalf("scope = %v, want ByBucket[aa11-k8s-c1-x]", srv.LastScopes[0])
	}
}

// The fallback path keeps the old query shape and the same client-side filter.
func TestClient_FindByBucketFallbackQueriesByCustomerOnly(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "aa11-k8s-c1-x", "c1", pb.Status_RUNNING)
	seedBucket(srv, "aa11-k8s-c1-y", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{FindByBucket: false})

	b, err := c.FindByBucket(context.Background(), "c1", "aa11-k8s-c1-y")
	if err != nil || b.Name != "aa11-k8s-c1-y" {
		t.Fatalf("FindByBucket fallback = %v, %v", b, err)
	}
	if len(srv.LastScopes) != 1 || srv.LastScopes[0].GetByCustomer() == nil {
		t.Fatalf("fallback scopes = %v, want ByCustomer only", srv.LastScopes)
	}
}

// Whatever the server-side scope semantics, a bucket of another login is never
// handed out as ours: the client filters every result itself.
func TestClient_FindByBucketRefusesAnotherLogin(t *testing.T) {
	for _, or := range []bool{false, true} {
		for _, byBucket := range []bool{true, false} {
			srv := cmfake.New()
			srv.ScopesOR = or
			seedBucket(srv, "aa11-k8s-c1-x", "other", pb.Status_RUNNING)
			c := newTestClient(t, srv, Options{FindByBucket: byBucket})

			_, err := c.FindByBucket(context.Background(), "c1", "aa11-k8s-c1-x")
			if byBucket && !errors.Is(err, ErrForeignBucket) {
				t.Errorf("or=%v byBucket=%v: err = %v, want ErrForeignBucket", or, byBucket, err)
			}
			if !byBucket && !errors.Is(err, ErrBucketNotFound) {
				t.Errorf("or=%v byBucket=%v: err = %v, want ErrBucketNotFound", or, byBucket, err)
			}
		}
	}
	// Twin: our own login gets the bucket.
	srv := cmfake.New()
	seedBucket(srv, "aa11-k8s-c1-x", "c1", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{FindByBucket: true})
	if _, err := c.FindByBucket(context.Background(), "c1", "aa11-k8s-c1-x"); err != nil {
		t.Fatalf("own bucket: %v", err)
	}
}

// An empty owner is handed to the caller unchanged: whether it is acceptable is
// the caller's decision (strict for purge and adopt).
func TestClient_FindByBucketReturnsAnEmptyOwnerAsIs(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "aa11-k8s-c1-x", "", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{FindByBucket: true})
	b, err := c.FindByBucket(context.Background(), "c1", "aa11-k8s-c1-x")
	if err != nil {
		t.Fatalf("FindByBucket: %v", err)
	}
	if b.CustLogin != "" {
		t.Fatalf("CustLogin = %q, want empty", b.CustLogin)
	}
}

func TestClient_FindByRequestedMatchesTheServerNameShape(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x", "c1", pb.Status_RUNNING) // exact shape
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-1", "c1", pb.Status_RUNNING)
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-old", "c1", pb.Status_RUNNING) // different requested name
	seedBucket(srv, "zz-k8s-c1-x", "c1", pb.Status_RUNNING)               // prefix is not hex
	seedBucket(srv, "k8s-c1-x", "c1", pb.Status_RUNNING)                  // no prefix
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-2", "c1", pb.Status_REMOVED)
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-3", "c1", pb.Status_REMOVING)
	seedBucket(srv, "aaaa-k8s-c1-x", "other", pb.Status_RUNNING)
	srv.ScopesOR = true
	c := newTestClient(t, srv, Options{FindByBucket: true})

	got, err := c.FindByRequested(context.Background(), "c1", "k8s-c1-x", false)
	if err != nil {
		t.Fatalf("FindByRequested: %v", err)
	}
	if len(got) != 1 || got[0].Name != "4682dfe35dd7-k8s-c1-x" {
		t.Fatalf("exact-only candidates = %v", names(got))
	}

	got, err = c.FindByRequested(context.Background(), "c1", "k8s-c1-x", true)
	if err != nil {
		t.Fatalf("FindByRequested suffix: %v", err)
	}
	if len(got) != 2 || got[0].Name != "4682dfe35dd7-k8s-c1-x" || got[1].Name != "4682dfe35dd7-k8s-c1-x-1" {
		t.Fatalf("suffix candidates = %v", names(got))
	}
}

// NamesByRequested is the pre-create snapshot: the same name shape as
// FindByRequested with the suffix, but REMOVED and REMOVING rows count (the
// server suffixes over them too).
func TestClient_NamesByRequestedKeepsEveryStatus(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x", "c1", pb.Status_REMOVED)
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-1", "c1", pb.Status_RUNNING)
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-2", "c1", pb.Status_REMOVING)
	seedBucket(srv, "4682dfe35dd7-k8s-c1-x-old", "c1", pb.Status_RUNNING) // different requested name
	seedBucket(srv, "aaaa-k8s-c1-x-3", "other", pb.Status_RUNNING)        // another login
	srv.ScopesOR = true
	c := newTestClient(t, srv, Options{FindByBucket: true})

	got, err := c.NamesByRequested(context.Background(), "c1", "k8s-c1-x")
	if err != nil {
		t.Fatalf("NamesByRequested: %v", err)
	}
	want := []string{"4682dfe35dd7-k8s-c1-x", "4682dfe35dd7-k8s-c1-x-1", "4682dfe35dd7-k8s-c1-x-2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", got, want)
	}
}

func names(bs []*Bucket) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.Name)
	}
	return out
}

func TestClient_RemoveClassifiesTheClosedVocabulary(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "b-running", "c1", pb.Status_RUNNING)
	seedBucket(srv, "b-removed", "c1", pb.Status_REMOVED)
	c := newTestClient(t, srv, Options{})
	ctx := context.Background()

	if err := c.Remove(ctx, "b-running"); err != nil {
		t.Fatalf("remove running: %v", err)
	}
	if err := c.Remove(ctx, "b-removed"); !errors.Is(err, ErrAlreadyRemoved) {
		t.Fatalf("remove removed: %v, want ErrAlreadyRemoved", err)
	}
	if err := c.Remove(ctx, "b-none"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("remove absent: %v, want ErrBucketNotFound", err)
	}

	before := removeUnknownResponses()
	srv.RemoveMessage = "failed to acquire mutex bucket-x"
	err := c.Remove(ctx, "b-running")
	if !errors.Is(err, ErrRemoveFailed) || errors.Is(err, ErrAlreadyRemoved) || errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("remove unknown text: %v, want ErrRemoveFailed only", err)
	}
	if removeUnknownResponses() != before+1 {
		t.Fatalf("unknown-response counter = %v, want %v", removeUnknownResponses(), before+1)
	}
}

// findAll is read-only, so one UNAVAILABLE is retried; create is not.
func TestClient_RetriesOnlyFindAllOnUnavailable(t *testing.T) {
	srv := cmfake.New()
	seedBucket(srv, "b1", "c1", pb.Status_RUNNING)
	srv.FindAllErrs = []error{status.Error(codes.Unavailable, "down")}
	srv.CreateErrs = []error{status.Error(codes.Unavailable, "down")}
	c := newTestClient(t, srv, Options{FindRetries: 1})
	ctx := context.Background()

	if _, err := c.FindByBucket(ctx, "c1", "b1"); err != nil {
		t.Fatalf("findAll after one UNAVAILABLE: %v", err)
	}
	if srv.FindAlls != 2 {
		t.Fatalf("findAll calls = %d, want 2", srv.FindAlls)
	}
	if _, err := c.Create(ctx, CreateInput{CustomerLogin: "c1", BucketName: "x"}); err == nil {
		t.Fatalf("create after UNAVAILABLE: want error")
	}
	if srv.Creates != 1 {
		t.Fatalf("create calls = %d, want 1 (no retry)", srv.Creates)
	}

	// Twin: a non-UNAVAILABLE error on findAll is not retried.
	srv.FindAllErrs = []error{status.Error(codes.Internal, "boom")}
	calls := srv.FindAlls
	if _, err := c.FindByBucket(ctx, "c1", "b1"); err == nil {
		t.Fatalf("findAll Internal: want error")
	}
	if srv.FindAlls != calls+1 {
		t.Fatalf("findAll calls = %d, want %d", srv.FindAlls, calls+1)
	}
}

func TestClient_CreateReturnsTheServerName(t *testing.T) {
	srv := cmfake.New()
	c := newTestClient(t, srv, Options{})
	ctx := context.Background()
	first, err := c.Create(ctx, CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if first != cmfake.Prefix("c1")+"-k8s-c1-x" {
		t.Fatalf("name = %q", first)
	}
	second, err := c.Create(ctx, CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-x"})
	if err != nil {
		t.Fatalf("create again: %v", err)
	}
	if second != first+"-1" {
		t.Fatalf("second name = %q, want suffixed", second)
	}
}

func removeUnknownResponses() float64 {
	return testutil.ToFloat64(removeUnknownResponseCounter)
}

// Create is not idempotent on the server side: a create cut by the client
// deadline still runs there, and its retry answers "user already exists"
// (system-test 2026-10-22: DeadlineExceeded ×7 at 15s, creates finishing
// within ~75s). The read deadline therefore does not bound a create.
func TestClient_CreateIsNotCutByTheReadDeadline(t *testing.T) {
	srv := cmfake.New()
	srv.CreateDelay = 400 * time.Millisecond
	c := newTestClient(t, srv, Options{CallTimeout: 100 * time.Millisecond})

	name, err := c.Create(context.Background(), CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-slow"})
	if err != nil {
		t.Fatalf("create slower than the read deadline: err = %v, want the server name", err)
	}
	if name != cmfake.Prefix("c1")+"-k8s-c1-slow" {
		t.Fatalf("name = %q", name)
	}

	// Twin: a create slower than the create deadline is cut by it.
	cut := cmfake.New()
	cut.CreateDelay = 400 * time.Millisecond
	cc := newTestClient(t, cut, Options{CallTimeout: time.Second, CreateTimeout: 100 * time.Millisecond})
	if _, err := cc.Create(context.Background(), CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-cut"}); status.Code(errors.Unwrap(err)) != codes.DeadlineExceeded {
		t.Fatalf("create past the create deadline: err = %v, want DeadlineExceeded", err)
	}

	// Twin: a read slower than the read deadline is still cut by it.
	hung := cmfake.New()
	hung.HangFindAll = true
	hc := newTestClient(t, hung, Options{CallTimeout: 100 * time.Millisecond})
	if _, err := hc.FindByBucket(context.Background(), "c1", name); status.Code(errors.Unwrap(err)) != codes.DeadlineExceeded {
		t.Fatalf("findAll past the read deadline: err = %v, want DeadlineExceeded", err)
	}
}

// cloud-manager answers a create it cannot classify with CODE_RESERVED and a
// free text ("failed to create user: user already exists"): the client names
// it as a rejected create, not as an unknown transport outcome.
func TestClient_CreateRejectedWithoutACodeIsNamed(t *testing.T) {
	srv := cmfake.New()
	srv.CreateError = &pb.CreateError{Code: pb.CreateError_CODE_RESERVED, Message: "failed to create user: user already exists"}
	c := newTestClient(t, srv, Options{})
	reserved := createRejectedCounter.WithLabelValues(pb.CreateError_CODE_RESERVED.String())
	limit := createRejectedCounter.WithLabelValues(pb.CreateError_BUCKET_LIMIT_REACHED.String())
	reservedBefore, limitBefore := testutil.ToFloat64(reserved), testutil.ToFloat64(limit)

	_, err := c.Create(context.Background(), CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-rej"})
	if err == nil || !strings.Contains(err.Error(), "create rejected [CODE_RESERVED]") {
		t.Fatalf("err = %v, want a rejected create naming CODE_RESERVED", err)
	}
	if !errors.Is(err, ErrCreateRejected) {
		t.Fatalf("err = %v, want it to wrap ErrCreateRejected", err)
	}
	if d := testutil.ToFloat64(reserved) - reservedBefore; d != 1 {
		t.Fatalf("create_rejected_total{code=CODE_RESERVED} grew by %v, want 1", d)
	}
	// Twin: a mapped code is not a rejection of this kind and is not counted.
	srv.CreateError = &pb.CreateError{Code: pb.CreateError_BUCKET_LIMIT_REACHED, Message: "limit"}
	if _, err := c.Create(context.Background(), CreateInput{CustomerLogin: "c1", BucketName: "k8s-c1-lim"}); errors.Is(err, ErrCreateRejected) || !errors.Is(err, ErrBucketLimitReached) {
		t.Fatalf("limit: err = %v, want ErrBucketLimitReached only", err)
	}
	if d := testutil.ToFloat64(limit) - limitBefore; d != 0 {
		t.Fatalf("create_rejected_total{code=BUCKET_LIMIT_REACHED} grew by %v, want 0", d)
	}
	if d := testutil.ToFloat64(reserved) - reservedBefore; d != 1 {
		t.Fatalf("create_rejected_total{code=CODE_RESERVED} grew by %v after a mapped code, want it unchanged at 1", d)
	}
}

// A process whose create deadline, with the findAll calls before it, does not
// fit the reconcile deadline refuses to start: the reconcile deadline would
// cut the create unseen.
func TestOptions_CreateMustFitTheReconcileDeadline(t *testing.T) {
	def := DefaultOptions() // create 2m; findAll 15s, 2 attempts, 200ms apart
	need := 2*time.Minute + 2*(2*15*time.Second+200*time.Millisecond)
	for _, tc := range []struct {
		name      string
		opts      Options
		reconcile time.Duration
		refused   bool
	}{
		{"defaults within the default reconcile deadline", def, 5 * time.Minute, false},
		{"no reconcile deadline", def, 0, false},
		{"exactly the calls of a creating pass", def, need, true},
		{"one second above them", def, need + time.Second, false},
		{"create deadline at the reconcile deadline", Options{CreateTimeout: 5 * time.Minute, FindRetries: 1}, 5 * time.Minute, true},
		// Zero values take the defaults, no retries: 2m + 2×15s.
		{"zero options, at the bound", Options{}, 2*time.Minute + 30*time.Second, true},
		{"zero options, above the bound", Options{}, 2*time.Minute + 31*time.Second, false},
	} {
		err := tc.opts.CheckReconcileTimeout(tc.reconcile)
		if (err != nil) != tc.refused {
			t.Errorf("%s: CheckReconcileTimeout(%s) = %v, refused want %v", tc.name, tc.reconcile, err, tc.refused)
		}
	}
	if got := (Options{}).CreateDeadline(); got != defaultCreateTimeout {
		t.Errorf("CreateDeadline of zero options = %s, want the default %s", got, defaultCreateTimeout)
	}
	if got := (Options{CreateTimeout: time.Minute}).CreateDeadline(); got != time.Minute {
		t.Errorf("CreateDeadline = %s, want the configured 1m", got)
	}
}

// ListByCustomer отдаёт строки логина в любом статусе, REMOVED тоже, и не
// судит владельца: строку другого логина, которую вернула служба с широкой
// областью поиска, вызывающий видит и решает о ней сам. Ключей в перечне нет.
func TestClient_ListByCustomerReturnsEveryRowWithoutKeys(t *testing.T) {
	srv := cmfake.New()
	srv.Seed(&pb.Bucket{Name: "aa11-k8s-c1-x", CustLogin: "c1", Status: pb.Status_RUNNING,
		AccessKey: "AK-x", SecretKey: "SK-x", ManagedBy: pb.S3BucketManagedBy_SYSTEM})
	seedBucket(srv, "aa11-k8s-c1-y", "c1", pb.Status_REMOVED)
	seedBucket(srv, "bb22-k8s-other-z", "other", pb.Status_RUNNING)
	c := newTestClient(t, srv, Options{})

	got, err := c.ListByCustomer(context.Background(), "c1")
	if err != nil {
		t.Fatalf("ListByCustomer: %v", err)
	}
	if strings.Join(names(got), ",") != "aa11-k8s-c1-x,aa11-k8s-c1-y" {
		t.Fatalf("rows = %v, want both rows of c1 in server order", names(got))
	}
	if got[0].Status != StatusRunning || got[1].Status != StatusRemoved || got[0].CustLogin != "c1" {
		t.Fatalf("rows = %+v, want statuses and owner as the server answered", got)
	}
	for _, b := range got {
		if b.AccessKey != "" || b.SecretKey != "" {
			t.Fatalf("row %q carries keys; a listing must not hand them out", b.Name)
		}
	}
	if len(srv.LastScopes) != 1 || len(srv.LastScopes[0].GetByCustomer().GetLogin()) != 1 ||
		srv.LastScopes[0].GetByCustomer().GetLogin()[0] != "c1" {
		t.Fatalf("scopes = %v, want ByCustomer[c1] only", srv.LastScopes)
	}

	// Служба с областью шире запрошенной: чужая строка доходит до вызывающего.
	srv.IgnoreScopes = true
	got, err = c.ListByCustomer(context.Background(), "c1")
	if err != nil {
		t.Fatalf("ListByCustomer wide: %v", err)
	}
	if len(got) != 3 || got[2].CustLogin != "other" {
		t.Fatalf("wide rows = %v, want the foreign row passed through unjudged", names(got))
	}
}
