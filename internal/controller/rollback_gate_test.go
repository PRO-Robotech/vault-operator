/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// rollbackGateCounts is the rollback gate of docs/user-guide/rollback.md for
// one claim: any condition whose reason is in RefusalReasons.
func rollbackGateCounts(claim *vaultv1alpha1.VaultClaim) bool {
	for _, c := range claim.Status.Conditions {
		if slices.Contains(RefusalReasons, c.Reason) {
			return true
		}
	}
	return false
}

func renderGateClaim(rules string) *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 3},
		Spec: vaultv1alpha1.VaultClaimSpec{
			SecretsPrefix: "clusters/ec8a00",
			Auth:          vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"},
			Policies:      []vaultv1alpha1.PolicySpec{{Name: "ec8a00-apps", Rules: rules}},
		},
	}
}

// A claim refused for rules that do not render is counted by the rollback
// gate. v0.0.9 renders rules without the closed set of forms and without the
// size limit, so the same claim under it runs `{{ range 1e11 }}` to the end
// (#21). The twin of the same harness is admitted and is not counted, so the
// count is not the harness marking every claim.
func TestRollbackGateCountsAClaimRefusedForRulesThatDoNotRender(t *testing.T) {
	const admitted = `path "secret/data/clusters/ec8a00/{{ vaultSAName }}" { capabilities = ["read"] }`

	t.Run("rules outside the closed set: counted", func(t *testing.T) {
		claim := renderGateClaim(admitted + "\n{{ range 3 }}x{{ end }}")
		state := &pipelineState{Vault: &fakeVaultClient{AccessorResp: testAccessor}}
		res, err := (&VaultClaimReconciler{}).stepApplyPolicies(context.Background(), claim, state)
		if err != nil || res != Refuse || state.RefusedReason != reasonRenderFailed {
			t.Fatalf("stepApplyPolicies = %v, %v, reason %q; want Refuse, <nil>, %s: the case does not reach the refusal",
				res, err, state.RefusedReason, reasonRenderFailed)
		}
		if !rollbackGateCounts(claim) {
			t.Errorf("the rollback gate does not count a claim refused with %s: RefusalReasons = %v",
				reasonRenderFailed, RefusalReasons)
		}
	})

	t.Run("the twin: admitted rules, not counted", func(t *testing.T) {
		claim := renderGateClaim(admitted)
		fake := &fakeVaultClient{AccessorResp: testAccessor}
		res, err := (&VaultClaimReconciler{}).stepApplyPolicies(context.Background(), claim, &pipelineState{Vault: fake})
		if err != nil || res != Proceed || fake.PutPolicyCalls != 1 {
			t.Fatalf("stepApplyPolicies = %v, %v, put %d; want Proceed, <nil>, 1", res, err, fake.PutPolicyCalls)
		}
		if rollbackGateCounts(claim) {
			t.Errorf("the rollback gate counts an admitted claim: conditions %v", claim.Status.Conditions)
		}
	})
}

// quotedNameList is a jq array of reason names: ["A","B",...].
var quotedNameList = regexp.MustCompile(`\[\s*"[A-Za-z]+"(?:\s*,\s*"[A-Za-z]+")*\s*\]`)

var quotedName = regexp.MustCompile(`"([A-Za-z]+)"`)

var backtickedName = regexp.MustCompile("`([A-Za-z]+)`")

func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("premise: %s is not readable: %v", rel, err)
	}
	return string(b)
}

// rollbackDocSet is the reason list of the jq command in rollback.md: the one
// array of quoted names in the file.
func rollbackDocSet(t *testing.T) []string {
	t.Helper()
	const rel = "docs/user-guide/rollback.md"
	lists := quotedNameList.FindAllString(readDoc(t, rel), -1)
	if len(lists) != 1 {
		t.Fatalf("premise: %s holds %d arrays of reason names, want 1", rel, len(lists))
	}
	var out []string
	for _, m := range quotedName.FindAllStringSubmatch(lists[0], -1) {
		out = append(out, m[1])
	}
	return out
}

// ownershipDocSet is the names in backticks of the sentence that starts with
// «Закрытый набор:» in ownership.md, up to its full stop outside parentheses.
func ownershipDocSet(t *testing.T) []string {
	t.Helper()
	const rel, anchor = "docs/concepts/ownership.md", "Закрытый набор:"
	text := readDoc(t, rel)
	if n := strings.Count(text, anchor); n != 1 {
		t.Fatalf("premise: %s holds %q %d times, want 1", rel, anchor, n)
	}
	rest := text[strings.Index(text, anchor)+len(anchor):]
	depth, end := 0, -1
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case '.', '\n':
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		t.Fatalf("premise: the sentence after %q in %s has no end", anchor, rel)
	}
	var out []string
	for _, m := range backtickedName.FindAllStringSubmatch(rest[:end], -1) {
		out = append(out, m[1])
	}
	return out
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// The two documents that spell out the refusal set say what RefusalReasons
// holds: the jq command an operator runs before a rollback counts exactly the
// claims the code counts as refused. A list that lost a reason lets a claim
// through to v0.0.9; one that gained a reason the code no longer has blocks
// rollbacks for nothing.
func TestRollbackDocumentsSpellTheRefusalSetOfTheCode(t *testing.T) {
	code := sortedCopy(RefusalReasons)
	if len(code) == 0 {
		t.Fatal("premise: RefusalReasons is empty")
	}
	for _, doc := range []struct {
		rel  string
		read func(*testing.T) []string
	}{
		{"docs/user-guide/rollback.md", rollbackDocSet},
		{"docs/concepts/ownership.md", ownershipDocSet},
	} {
		got := sortedCopy(doc.read(t))
		if len(got) == 0 {
			t.Fatalf("premise: no reason names read from %s", doc.rel)
		}
		t.Logf("%s: %d names read, RefusalReasons: %d", doc.rel, len(got), len(code))
		for _, r := range code {
			if !slices.Contains(got, r) {
				t.Errorf("%s does not list %s, which RefusalReasons holds", doc.rel, r)
			}
		}
		for _, r := range got {
			if !slices.Contains(code, r) {
				t.Errorf("%s lists %s, which RefusalReasons does not hold", doc.rel, r)
			}
		}
	}
}
