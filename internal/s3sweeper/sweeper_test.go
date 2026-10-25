/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package s3sweeper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

const (
	loginA = "dlputi1u"
	loginB = "godjee"
	// secretMark стоит в ключах каждого засеянного бакета: в журнале его быть
	// не должно ни в одном исходе.
	secretMark = "do-not-print-7f3a"
	// addrMark — адрес в тексте сетевого отказа: в журнал он не попадает.
	addrMark = "10.1.2.3:50051"
)

var (
	prefA     = cmfake.Prefix(loginA)
	prefOther = "c90bf04ae9a8" // префикс логина сменился после снятия последнего бакета
	prefB     = "f226169dec3a"
)

// fakeClock — управляемые часы: Sleep сдвигает время и зовёт onSleep с
// номером ожидания, чтобы тест менял состояние двойника между проходами.
type fakeClock struct {
	now     time.Time
	sleeps  int
	onSleep func(n int)
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps++
	c.now = c.now.Add(d)
	if c.onSleep != nil {
		c.onSleep(c.sleeps)
	}
	return nil
}

type harness struct {
	srv   *cmfake.Server
	lis   *cmfake.Listener
	cloud *cloudmanager.Client
	clk   *fakeClock
	log   *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	srv := cmfake.New()
	lis := cmfake.Serve(srv)
	t.Cleanup(lis.Stop)
	conn, err := lis.Dial()
	if err != nil {
		t.Fatalf("dial fake: %v", err)
	}
	cloud := cloudmanager.NewFromConn(conn, cloudmanager.Options{QPS: -1, CallTimeout: 5 * time.Second})
	t.Cleanup(func() { _ = cloud.Close() })
	return &harness{srv: srv, lis: lis, cloud: cloud, clk: &fakeClock{now: time.Unix(1_800_000_000, 0)}, log: &bytes.Buffer{}}
}

func (h *harness) opts(logins ...string) Options {
	return Options{
		Logins:       logins,
		Timeout:      time.Minute,
		PollInterval: time.Second,
		MaxRemovals:  20,
		Log:          slog.New(slog.NewJSONHandler(h.log, nil)),
		Clock:        h.clk,
	}
}

func (h *harness) seed(name, owner string, st pb.Status) {
	h.srv.Seed(&pb.Bucket{Name: name, CustLogin: owner, Status: st,
		AccessKey: "AK-" + secretMark, SecretKey: "SK-" + secretMark, Fqdn: name + ".s3.example.test"})
}

func (h *harness) status(t *testing.T, name string) pb.Status {
	t.Helper()
	b := h.srv.Get(name)
	if b == nil {
		t.Fatalf("bucket %q is not in the fake", name)
	}
	return b.GetStatus()
}

func (h *harness) removes() int {
	_, _, r := h.srv.Counters()
	return r
}

// assertLogClean: ни ключей, ни адреса в журнале.
func (h *harness) assertLogClean(t *testing.T) {
	t.Helper()
	out := h.log.String()
	if out == "" {
		t.Fatal("log is empty: the run reported nothing")
	}
	for _, bad := range []string{secretMark, addrMark} {
		if strings.Contains(out, bad) {
			t.Fatalf("log carries %q:\n%s", bad, out)
		}
	}
}

// records — записи журнала с данным сообщением.
func (h *harness) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(h.log.Bytes()))
	for sc.Scan() {
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

func ci(prefix, login, rest string) string { return prefix + "-k8s-" + login + "-ci-" + rest }

// Режим job снимает ровно бакеты своего задания у своих логинов — с
// суффиксом «-N» и с любым шестнадцатеричным префиксом — и не трогает ни
// соседние имена того же логина, ни чужие бакеты рядом (ai-test-*), ни имена
// других заданий, чей номер — начало, конец или продолжение нашего.
func TestJob_RemovesOnlyTheBucketsOfItsJobAndLogins(t *testing.T) {
	h := newHarness(t)
	targets := []string{
		ci(prefA, loginA, "4242"),
		ci(prefA, loginA, "4242-1"),
		ci(prefOther, loginA, "4242-2"),
		ci(prefB, loginB, "4242"),
	}
	for _, n := range targets[:3] {
		h.seed(n, loginA, pb.Status_RUNNING)
	}
	h.seed(targets[3], loginB, pb.Status_RUNNING)
	untouchedA := []string{
		ci(prefA, loginA, "42"),
		ci(prefA, loginA, "424212"),
		ci(prefA, loginA, "14242"),
		ci(prefA, loginA, "4242-x"),
		ci(prefA, loginA, "4242-1-2"),
		prefA + "-k8s-" + loginA + "-w13507",
		"k8s-" + loginA + "-ci-4242",
		"xyz1-k8s-" + loginA + "-ci-4242",
		ci(prefA, loginB, "4242-3"), // имя другого логина в перечне нашего
	}
	for _, n := range untouchedA {
		h.seed(n, loginA, pb.Status_RUNNING)
	}
	untouchedB := []string{
		prefB + "-k8s-" + loginB + "-ai-test-35-7-5",
		prefB + "-k8s-" + loginB + "-ai-test-35-7-6",
	}
	for _, n := range untouchedB {
		h.seed(n, loginB, pb.Status_RUNNING)
	}
	removed := ci(prefA, loginA, "4242-5")
	h.seed(removed, loginA, pb.Status_REMOVED)

	rep, err := RunJob(context.Background(), h.cloud, 4242, h.opts(loginA, loginB))
	if err != nil {
		t.Fatalf("RunJob: %v\nlog:\n%s", err, h.log)
	}
	for _, n := range targets {
		if st := h.status(t, n); st != pb.Status_REMOVED {
			t.Errorf("%s: status %s, want REMOVED", n, st)
		}
	}
	for _, n := range append(untouchedA, untouchedB...) {
		if st := h.status(t, n); st != pb.Status_RUNNING {
			t.Errorf("%s: status %s, want RUNNING (not ours)", n, st)
		}
	}
	if got := h.removes(); got != len(targets) {
		t.Errorf("removeBucket calls = %d, want %d (one per live target, none for REMOVED)", got, len(targets))
	}
	got := slices.Clone(rep.Removed)
	slices.Sort(got)
	want := slices.Clone(targets)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("report removed = %v, want %v", got, want)
	}
	if rep.Rows != len(targets)+len(untouchedA)+len(untouchedB)+1 {
		t.Errorf("report rows = %d, want every row of both logins read", rep.Rows)
	}
	h.assertLogClean(t)
}

// Владелец строки судится по cust_login, а не по имени: строка с именем
// нашей формы и чужим владельцем, отданная службой с широкой областью
// поиска, не снимается; законный близнец рядом снимается.
func TestJob_NeverRemovesABucketOfAnotherOwner(t *testing.T) {
	h := newHarness(t)
	h.srv.IgnoreScopes = true
	foreign := ci(prefA, loginA, "4242")
	twin := ci(prefA, loginA, "4242-1")
	h.seed(foreign, "intruder", pb.Status_RUNNING)
	h.seed(twin, loginA, pb.Status_RUNNING)

	rep, err := RunJob(context.Background(), h.cloud, 4242, h.opts(loginA))
	if err != nil {
		t.Fatalf("RunJob: %v\nlog:\n%s", err, h.log)
	}
	if rep.Rows != 2 {
		t.Fatalf("rows = %d, want 2: the foreign row must reach the sweeper for the probe to judge it", rep.Rows)
	}
	if st := h.status(t, foreign); st != pb.Status_RUNNING {
		t.Errorf("foreign-owned %s: status %s, want RUNNING", foreign, st)
	}
	if st := h.status(t, twin); st != pb.Status_REMOVED {
		t.Errorf("own twin %s: status %s, want REMOVED", twin, st)
	}
	if got := h.removes(); got != 1 {
		t.Errorf("removeBucket calls = %d, want 1", got)
	}
	h.assertLogClean(t)
}

// CREATING не снимается (создание идёт), а ждётся; ставший RUNNING снимается
// следующим проходом.
func TestJob_WaitsOutCreatingAndRemovesItOnceRunning(t *testing.T) {
	h := newHarness(t)
	name := ci(prefA, loginA, "7")
	h.seed(name, loginA, pb.Status_CREATING)
	removesWhileCreating := -1
	h.clk.onSleep = func(n int) {
		if n == 1 {
			removesWhileCreating = h.removes()
			h.srv.Update(name, func(b *pb.Bucket) { b.Status = pb.Status_RUNNING })
		}
	}

	if _, err := RunJob(context.Background(), h.cloud, 7, h.opts(loginA)); err != nil {
		t.Fatalf("RunJob: %v\nlog:\n%s", err, h.log)
	}
	if removesWhileCreating != 0 {
		t.Errorf("removeBucket calls while CREATING = %d, want 0", removesWhileCreating)
	}
	if st := h.status(t, name); st != pb.Status_REMOVED {
		t.Errorf("status %s, want REMOVED", st)
	}
	h.assertLogClean(t)
}

// Срок вышел, бакет всё ещё REMOVING — исход красный, остаток назван; снятие
// не повторяется на каждом проходе.
func TestJob_DeadlineWithABucketStillRemovingIsRed(t *testing.T) {
	h := newHarness(t)
	h.srv.RemovalPolls = 1_000_000
	name := ci(prefA, loginA, "9")
	h.seed(name, loginA, pb.Status_RUNNING)
	o := h.opts(loginA)
	o.Timeout = 10 * time.Second

	rep, err := RunJob(context.Background(), h.cloud, 9, o)
	if !errors.Is(err, ErrLeftovers) {
		t.Fatalf("err = %v, want ErrLeftovers", err)
	}
	if len(rep.Left) != 1 || rep.Left[0].Name != name || rep.Left[0].Status != cloudmanager.StatusRemoving ||
		rep.Left[0].Login != loginA {
		t.Fatalf("left = %+v, want [%s REMOVING]", rep.Left, name)
	}
	if got := h.removes(); got != 1 {
		t.Errorf("removeBucket calls = %d, want 1 (REMOVING is waited, not removed again)", got)
	}
	if h.clk.sleeps < 10 {
		t.Errorf("sleeps = %d, want the whole 10s waited at 1s polls", h.clk.sleeps)
	}
	h.assertLogClean(t)
}

// Отказ снятия текстом вне словаря оставляет бакет RUNNING: по сроку исход
// красный, остаток — RUNNING.
func TestJob_UnknownRemoveAnswerLeavesItRunningAndRed(t *testing.T) {
	h := newHarness(t)
	h.srv.RemoveMessage = "Internal failure"
	name := ci(prefA, loginA, "11")
	h.seed(name, loginA, pb.Status_RUNNING)
	o := h.opts(loginA)
	o.Timeout = 3 * time.Second

	rep, err := RunJob(context.Background(), h.cloud, 11, o)
	if !errors.Is(err, ErrLeftovers) {
		t.Fatalf("err = %v, want ErrLeftovers", err)
	}
	if len(rep.Left) != 1 || rep.Left[0].Status != cloudmanager.StatusRunning {
		t.Fatalf("left = %+v, want one RUNNING", rep.Left)
	}
	h.assertLogClean(t)
}

// Повторный прогон того же задания: всё уже REMOVED — снятий ноль, исход
// зелёный. Ответы «Already removed» и «Not found» — конечные, не ошибка.
func TestJob_RepeatedRunAlreadyRemovedAndNotFoundAreTerminal(t *testing.T) {
	h := newHarness(t)
	name := ci(prefA, loginA, "13")
	h.seed(name, loginA, pb.Status_RUNNING)
	if _, err := RunJob(context.Background(), h.cloud, 13, h.opts(loginA)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	first := h.removes()
	if _, err := RunJob(context.Background(), h.cloud, 13, h.opts(loginA)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := h.removes(); got != first {
		t.Errorf("second run removeBucket calls = %d, want 0", got-first)
	}

	for _, answer := range []string{"Already removed", "Not found"} {
		h2 := newHarness(t)
		h2.srv.RemoveMessage = answer
		n := ci(prefA, loginA, "15")
		h2.seed(n, loginA, pb.Status_RUNNING)
		rep, err := RunJob(context.Background(), h2.cloud, 15, h2.opts(loginA))
		if err != nil {
			t.Errorf("%q: err = %v, want a terminal answer to end the run green", answer, err)
		}
		if len(rep.Left) != 0 {
			t.Errorf("%q: left = %+v, want none", answer, rep.Left)
		}
		if h2.clk.sleeps != 0 {
			t.Errorf("%q: sleeps = %d, want no waiting after a terminal answer", answer, h2.clk.sleeps)
		}
		h2.assertLogClean(t)
	}
}

// Сетевой отказ: перечня нет — ни одного снятия, исход красный по сроку, в
// журнале нет адреса из текста отказа.
func TestJob_NetworkRefusalIsRedAndNamesNoAddress(t *testing.T) {
	h := newHarness(t)
	h.seed(ci(prefA, loginA, "17"), loginA, pb.Status_RUNNING)
	for range 100 {
		h.srv.FindAllErrs = append(h.srv.FindAllErrs,
			status.Error(codes.Unavailable, "connection error: dial tcp "+addrMark+": connect: connection refused"))
	}
	o := h.opts(loginA)
	o.Timeout = 5 * time.Second

	_, err := RunJob(context.Background(), h.cloud, 17, o)
	if err == nil {
		t.Fatal("err = nil, want a red outcome on a refused listing")
	}
	if strings.Contains(err.Error(), addrMark) {
		t.Errorf("error carries the address: %v", err)
	}
	if got := h.removes(); got != 0 {
		t.Errorf("removeBucket calls = %d, want 0", got)
	}
	h.assertLogClean(t)

	// Служба недоступна целиком.
	h2 := newHarness(t)
	h2.lis.Stop()
	o2 := h2.opts(loginA)
	o2.Timeout = 2 * time.Second
	if _, err := RunJob(context.Background(), h2.cloud, 17, o2); err == nil {
		t.Fatal("stopped service: err = nil, want red")
	}
}

// Целей больше предела — отказ без единого снятия.
func TestJob_MoreTargetsThanTheLimitRemovesNothing(t *testing.T) {
	h := newHarness(t)
	for _, s := range []string{"19", "19-1", "19-2"} {
		h.seed(ci(prefA, loginA, s), loginA, pb.Status_RUNNING)
	}
	o := h.opts(loginA)
	o.MaxRemovals = 2

	_, err := RunJob(context.Background(), h.cloud, 19, o)
	if !errors.Is(err, ErrTooManyRemovals) {
		t.Fatalf("err = %v, want ErrTooManyRemovals", err)
	}
	if got := h.removes(); got != 0 {
		t.Errorf("removeBucket calls = %d, want 0", got)
	}
	h.assertLogClean(t)
}

// --dry-run печатает план — цели с действием и статусом — и ничего не снимает.
func TestJob_DryRunPrintsThePlanAndRemovesNothing(t *testing.T) {
	h := newHarness(t)
	target := ci(prefA, loginA, "21")
	removing := ci(prefA, loginA, "21-1")
	neighbour := prefB + "-k8s-" + loginB + "-ai-test-35-7-5"
	h.seed(target, loginA, pb.Status_RUNNING)
	h.seed(removing, loginA, pb.Status_REMOVING)
	h.seed(neighbour, loginB, pb.Status_RUNNING)
	o := h.opts(loginA, loginB)
	o.DryRun = true

	if _, err := RunJob(context.Background(), h.cloud, 21, o); err != nil {
		t.Fatalf("RunJob dry-run: %v", err)
	}
	if got := h.removes(); got != 0 {
		t.Errorf("removeBucket calls = %d, want 0", got)
	}
	plan := map[string]string{}
	for _, r := range h.records(t, "plan") {
		plan[r["bucket"].(string)] = r["action"].(string)
	}
	want := map[string]string{target: "remove", removing: "wait"}
	if len(plan) != len(want) || plan[target] != want[target] || plan[removing] != want[removing] {
		t.Fatalf("plan = %v, want %v (the neighbour is not in it)", plan, want)
	}
	h.assertLogClean(t)
}

// fakeJobs — статусы заданий CI; отсутствующий номер — ErrJobNotFound.
type fakeJobs struct {
	status map[uint64]string
	asked  map[uint64]int
}

func (f *fakeJobs) JobStatus(_ context.Context, id uint64) (string, error) {
	f.asked[id]++
	st, ok := f.status[id]
	if !ok {
		return "", ErrJobNotFound
	}
	return st, nil
}

// Режим sweep снимает бакеты только завершённых заданий; идущие, неизвестные
// и задания с непонятным статусом не трогаются, а неклассифицированные
// делают исход красным. Статус каждого задания спрашивается один раз;
// задание, у которого живых бакетов нет, не спрашивается вовсе.
func TestSweep_RemovesOnlyTheBucketsOfFinishedJobs(t *testing.T) {
	h := newHarness(t)
	jobs := &fakeJobs{asked: map[uint64]int{}, status: map[uint64]string{
		100: "success", 200: "running", 400: "failed", 500: "success",
		600: "canceled", 700: "weird", 800: "pending", 900: "success",
	}}
	gone := []string{ci(prefA, loginA, "100"), ci(prefA, loginA, "100-1"), ci(prefA, loginA, "400"),
		ci(prefOther, loginA, "600")}
	for _, n := range gone {
		h.seed(n, loginA, pb.Status_RUNNING)
	}
	goneB := ci(prefB, loginB, "900")
	h.seed(goneB, loginB, pb.Status_RUNNING)
	kept := []string{ci(prefA, loginA, "200"), ci(prefA, loginA, "300"), ci(prefA, loginA, "700"),
		ci(prefA, loginA, "800"), prefA + "-k8s-" + loginA + "-w13507"}
	for _, n := range kept {
		h.seed(n, loginA, pb.Status_RUNNING)
	}
	keptB := prefB + "-k8s-" + loginB + "-ai-test-35-7-5"
	h.seed(keptB, loginB, pb.Status_RUNNING)
	h.seed(ci(prefA, loginA, "500"), loginA, pb.Status_REMOVED)

	rep, err := RunSweep(context.Background(), h.cloud, jobs, h.opts(loginA, loginB))
	if !errors.Is(err, ErrJobUnclassified) {
		t.Fatalf("err = %v, want ErrJobUnclassified (job 300 unknown, job 700 status weird)", err)
	}
	for _, n := range append(gone, goneB) {
		if st := h.status(t, n); st != pb.Status_REMOVED {
			t.Errorf("%s: status %s, want REMOVED (job finished)", n, st)
		}
	}
	for _, n := range append(kept, keptB) {
		if st := h.status(t, n); st != pb.Status_RUNNING {
			t.Errorf("%s: status %s, want RUNNING", n, st)
		}
	}
	for id, n := range jobs.asked {
		if n != 1 {
			t.Errorf("job %d asked %d times, want once", id, n)
		}
	}
	if jobs.asked[500] != 0 {
		t.Errorf("job 500 asked although it has no live bucket")
	}
	if len(rep.Removed) != len(gone)+1 {
		t.Errorf("removed = %v, want %d", rep.Removed, len(gone)+1)
	}
	h.assertLogClean(t)
}

// Владелец судится и в sweep: бакет завершённого задания с чужим cust_login
// не снимается.
func TestSweep_NeverRemovesABucketOfAnotherOwner(t *testing.T) {
	h := newHarness(t)
	h.srv.IgnoreScopes = true
	foreign := ci(prefA, loginA, "100")
	twin := ci(prefA, loginA, "100-1")
	h.seed(foreign, "intruder", pb.Status_RUNNING)
	h.seed(twin, loginA, pb.Status_RUNNING)
	jobs := &fakeJobs{asked: map[uint64]int{}, status: map[uint64]string{100: "success"}}

	if _, err := RunSweep(context.Background(), h.cloud, jobs, h.opts(loginA)); err != nil {
		t.Fatalf("RunSweep: %v\nlog:\n%s", err, h.log)
	}
	if st := h.status(t, foreign); st != pb.Status_RUNNING {
		t.Errorf("foreign-owned: status %s, want RUNNING", st)
	}
	if st := h.status(t, twin); st != pb.Status_REMOVED {
		t.Errorf("own twin: status %s, want REMOVED", st)
	}
}

// Опции проверяются до первого вызова службы.
func TestOptions_AreRefusedBeforeAnyCall(t *testing.T) {
	h := newHarness(t)
	bad := map[string]func(*Options){
		"no login":        func(o *Options) { o.Logins = nil },
		"bad login":       func(o *Options) { o.Logins = []string{"Bad Login"} },
		"login too long":  func(o *Options) { o.Logins = []string{strings.Repeat("a", 33)} },
		"zero timeout":    func(o *Options) { o.Timeout = 0 },
		"zero poll":       func(o *Options) { o.PollInterval = 0 },
		"zero max":        func(o *Options) { o.MaxRemovals = 0 },
		"no logger":       func(o *Options) { o.Log = nil },
		"regexp in login": func(o *Options) { o.Logins = []string{"a.*"} },
	}
	for name, mut := range bad {
		o := h.opts(loginA)
		mut(&o)
		if _, err := RunJob(context.Background(), h.cloud, 1, o); err == nil {
			t.Errorf("%s: RunJob err = nil, want a refusal", name)
		}
	}
	if _, err := RunJob(context.Background(), h.cloud, 0, h.opts(loginA)); err == nil {
		t.Error("job id 0: err = nil, want a refusal")
	}
	if _, _, f := h.srv.Counters(); f != 0 {
		t.Errorf("findAll calls = %d, want 0: options are judged first", f)
	}
}

func TestParseJobID(t *testing.T) {
	for in, want := range map[string]uint64{"1": 1, "4242": 4242, "18446744073709551615": 18446744073709551615} {
		got, err := ParseJobID(in)
		if err != nil || got != want {
			t.Errorf("ParseJobID(%q) = %d, %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "01", "-1", "12a", " 12", "1.5", "18446744073709551616", "$CI_JOB_ID"} {
		if _, err := ParseJobID(in); err == nil {
			t.Errorf("ParseJobID(%q): err = nil, want a refusal", in)
		}
	}
}

// Ни одно задание не завершено: снятий ноль, исход зелёный, знаменатель
// (строк прочитано) назван и в итоге, и в журнале.
func TestSweep_NothingFinishedRemovesNothingAndCountsRows(t *testing.T) {
	h := newHarness(t)
	h.seed(ci(prefA, loginA, "200"), loginA, pb.Status_RUNNING)
	h.seed(prefA+"-k8s-"+loginA+"-w13507", loginA, pb.Status_RUNNING)
	jobs := &fakeJobs{asked: map[uint64]int{}, status: map[uint64]string{200: "running"}}

	rep, err := RunSweep(context.Background(), h.cloud, jobs, h.opts(loginA))
	if err != nil {
		t.Fatalf("RunSweep: %v", err)
	}
	if rep.Rows != 2 || len(rep.Removed) != 0 || h.removes() != 0 {
		t.Fatalf("report = %+v, removes = %d; want rows 2 and nothing removed", rep, h.removes())
	}
	sum := h.records(t, "summary")
	if len(sum) != 1 || sum[0]["rows"] != float64(2) {
		t.Fatalf("summary records = %v, want one with rows 2", sum)
	}
	h.assertLogClean(t)
}
