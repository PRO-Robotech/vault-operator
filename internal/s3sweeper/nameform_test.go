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
	"strconv"
	"testing"

	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

// refTail — ссылка бакета формы registry-operator #49: девять знаков hex и
// буква a..p на месте последнего знака (g..p — цифра, записанная буквой).
const (
	refTailG = "3f9a01c2bg"
	refTailF = "3f9a01c2bf"
	refTailP = "012345678p"
	// legacyDigits — ссылка CI прежней формы (#44): тринадцать цифр.
	legacyDigits = "0012345678901"
)

// Форма имени знает обе ссылки CI — прежнюю из цифр и новую с буквой на
// конце — с дописанным облаком -<N> и без него, и номер задания берёт из
// первой группы. Чужие имена той же длины и того же алфавита — без -ci-,
// с другим префиксом, другим логином, лишним или испорченным хвостом —
// формой не опознаются.
func TestCiNameForm_KnowsTheLegacyAndTheLetterTailRef(t *testing.T) {
	re := ciNameRe(loginA)
	ours := map[string]uint64{
		ci(prefA, loginA, "4242"):                  4242,
		ci(prefA, loginA, "4242-1"):                4242,
		ci(prefA, loginA, "4242-"+legacyDigits):    4242,
		ci(prefA, loginA, "4242-"+refTailG):        4242,
		ci(prefA, loginA, "4242-"+refTailF):        4242,
		ci(prefA, loginA, "4242-"+refTailG+"-2"):   4242,
		ci(prefOther, loginA, "7-"+refTailP+"-12"): 7,
		ci(prefA, loginA, "100-"+refTailP):         100,
	}
	for name, want := range ours {
		sub := re.FindStringSubmatch(name)
		if sub == nil {
			t.Errorf("%s: not recognised as a CI bucket name", name)
			continue
		}
		if sub[1] != strconv.FormatUint(want, 10) {
			t.Errorf("%s: job id %q, want %d", name, sub[1], want)
		}
	}
	foreign := []string{
		ci(prefA, loginA, "4242-3f9a01c2bq"),  // буква вне a..p
		ci(prefA, loginA, "4242-3f9a01c2b"),   // девять знаков вместо десяти
		ci(prefA, loginA, "4242-3f9a01c2g"),   // восемь hex и буква
		ci(prefA, loginA, "4242-3f9a01c2bgg"), // одиннадцать знаков
		ci(prefA, loginA, "4242-3F9A01C2BG"),  // заглавные
		ci(prefA, loginA, "4242-x3f9a01c2b"),  // не hex в начале ссылки
		ci(prefA, loginA, "4242-"+refTailG+"-2-3"),
		ci(prefA, loginA, "4242-"+refTailG+"-x"),
		ci(prefA, loginA, "4242-"+refTailG+refTailG),
		ci(prefA, loginA, "0-"+refTailG),
		ci(prefA, loginA, "04242-"+refTailG),
		ci(prefA, loginA, refTailG),
		prefA + "-k8s-" + loginA + "-" + refTailG,
		prefA + "-k8s-" + loginA + "-4242-" + refTailG,
		"xyz1-k8s-" + loginA + "-ci-4242-" + refTailG,
		"k8s-" + loginA + "-ci-4242-" + refTailG,
		ci(prefA, loginB, "4242-"+refTailG),
		ci(prefA, loginA+"x", "4242-"+refTailG),
	}
	for _, name := range foreign {
		if re.MatchString(name) {
			t.Errorf("%s: recognised as a CI bucket name, want foreign", name)
		}
	}
}

// Режим job снимает бакеты своего задания и в новой форме ссылки — с
// буквой на конце и с -<N> после неё — и не трогает бакеты новой формы
// других заданий, чьё имя — начало или продолжение нашего, ни имён с
// испорченной ссылкой.
func TestJob_RemovesTheLetterTailBucketsOfItsJobOnly(t *testing.T) {
	h := newHarness(t)
	targets := []string{
		ci(prefA, loginA, "4242-"+refTailG),
		ci(prefA, loginA, "4242-"+refTailF+"-1"),
		ci(prefOther, loginA, "4242-"+refTailP+"-2"),
		ci(prefA, loginA, "4242-"+legacyDigits),
	}
	untouched := []string{
		ci(prefA, loginA, "424-"+refTailG),
		ci(prefA, loginA, "42421-"+refTailG),
		ci(prefA, loginA, "14242-"+refTailG),
		ci(prefA, loginA, "4242-3f9a01c2bq"),
		ci(prefA, loginA, "4242-"+refTailG+"-1-2"),
		prefA + "-k8s-" + loginA + "-ai-test-4242-" + refTailG,
		"xyz1-k8s-" + loginA + "-ci-4242-" + refTailG,
	}
	for _, n := range append(append([]string{}, targets...), untouched...) {
		h.seed(n, loginA, pb.Status_RUNNING)
	}

	rep, err := RunJob(context.Background(), h.cloud, 4242, h.opts(loginA))
	if err != nil {
		t.Fatalf("RunJob: %v\nlog:\n%s", err, h.log)
	}
	for _, n := range targets {
		if st := h.status(t, n); st != pb.Status_REMOVED {
			t.Errorf("%s: status %s, want REMOVED", n, st)
		}
	}
	for _, n := range untouched {
		if st := h.status(t, n); st != pb.Status_RUNNING {
			t.Errorf("%s: status %s, want RUNNING (not ours)", n, st)
		}
	}
	if got := h.removes(); got != len(targets) {
		t.Errorf("removeBucket calls = %d, want %d", got, len(targets))
	}
	if rep.Rows != len(targets)+len(untouched) {
		t.Errorf("report rows = %d, want %d", rep.Rows, len(targets)+len(untouched))
	}
	h.assertLogClean(t)
}

// Владелец судится и в новой форме: бакет нашего имени с чужим cust_login
// не снимается, законный близнец рядом снимается.
func TestJob_NeverRemovesALetterTailBucketOfAnotherOwner(t *testing.T) {
	h := newHarness(t)
	h.srv.IgnoreScopes = true
	foreign := ci(prefA, loginA, "4242-"+refTailG)
	twin := ci(prefA, loginA, "4242-"+refTailG+"-1")
	h.seed(foreign, "intruder", pb.Status_RUNNING)
	h.seed(twin, loginA, pb.Status_RUNNING)

	if _, err := RunJob(context.Background(), h.cloud, 4242, h.opts(loginA)); err != nil {
		t.Fatalf("RunJob: %v\nlog:\n%s", err, h.log)
	}
	if st := h.status(t, foreign); st != pb.Status_RUNNING {
		t.Errorf("foreign-owned %s: status %s, want RUNNING", foreign, st)
	}
	if st := h.status(t, twin); st != pb.Status_REMOVED {
		t.Errorf("own twin %s: status %s, want REMOVED", twin, st)
	}
}

// Режим sweep берёт номер задания из имени новой формы: бакет завершённого
// задания снимается, идущего — остаётся.
func TestSweep_JudgesTheLetterTailBucketByItsJob(t *testing.T) {
	h := newHarness(t)
	jobs := &fakeJobs{asked: map[uint64]int{}, status: map[uint64]string{100: "success", 200: "running"}}
	gone := ci(prefA, loginA, "100-"+refTailG+"-3")
	kept := ci(prefA, loginA, "200-"+refTailF)
	h.seed(gone, loginA, pb.Status_RUNNING)
	h.seed(kept, loginA, pb.Status_RUNNING)

	if _, err := RunSweep(context.Background(), h.cloud, jobs, h.opts(loginA)); err != nil {
		t.Fatalf("RunSweep: %v\nlog:\n%s", err, h.log)
	}
	if st := h.status(t, gone); st != pb.Status_REMOVED {
		t.Errorf("%s: status %s, want REMOVED (job 100 finished)", gone, st)
	}
	if st := h.status(t, kept); st != pb.Status_RUNNING {
		t.Errorf("%s: status %s, want RUNNING (job 200 running)", kept, st)
	}
	if jobs.asked[100] != 1 || jobs.asked[200] != 1 {
		t.Errorf("jobs asked = %v, want 100 and 200 once each", jobs.asked)
	}
}
