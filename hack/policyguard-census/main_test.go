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
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// censusBound is how long one census over one claim may take. The operator
// refuses a range before executing it, so a census that agrees with the
// operator ends in milliseconds.
const censusBound = 10 * time.Second

type censusResult struct {
	code int
	out  string
}

// census runs the command over one claim holding policy, within censusBound.
func census(t *testing.T, policy vaultv1alpha1.PolicySpec) censusResult {
	t.Helper()
	list := vaultv1alpha1.VaultClaimList{Items: []vaultv1alpha1.VaultClaim{{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			SecretsPrefix: "clusters/x",
			Policies:      []vaultv1alpha1.PolicySpec{policy},
		},
	}}}
	in, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	done := make(chan censusResult, 1)
	go func() {
		var out, errOut bytes.Buffer
		code := run(nil, bytes.NewReader(in), &out, &errOut)
		done <- censusResult{code: code, out: out.String() + errOut.String()}
	}()
	select {
	case res := <-done:
		return res
	case <-time.After(censusBound):
		t.Fatalf("census did not finish within %s on rules %q", censusBound, policy.Rules)
		return censusResult{}
	}
}

// A range over a number is a loop the operator never runs: the census refuses
// it as the operator does, and in bounded time.
func TestCensusRefusesARangeOverANumberInBoundedTime(t *testing.T) {
	res := census(t, vaultv1alpha1.PolicySpec{Name: "loop",
		Rules: `path "secret/data/clusters/x/a" { capabilities = ["read"] }` + "\n{{range 4611686018427387904}}{{end}}"})
	if res.code != 1 {
		t.Fatalf("exit code %d, want 1; output:\n%s", res.code, res.out)
	}
	if !strings.Contains(res.out, `ns/c1 policy "loop": does not render: `) || !strings.Contains(res.out, "range") {
		t.Fatalf("the refusal does not name the range; output:\n%s", res.out)
	}
	if !strings.Contains(res.out, "census: claims=1 policies=1 violations=1") {
		t.Fatalf("summary missing; output:\n%s", res.out)
	}
}

// Twin: the forms the operator admits render in the census as they do in the
// operator, so a claim inside its scope is no violation.
func TestCensusRendersTheAdmittedFormsAsTheOperatorDoes(t *testing.T) {
	res := census(t, vaultv1alpha1.PolicySpec{Name: "own",
		Rules: `path "secret/data/clusters/x/{{ vaultSAName }}" { capabilities = ["read"] }`})
	if res.code != 0 {
		t.Fatalf("exit code %d, want 0; output:\n%s", res.code, res.out)
	}
	if !strings.Contains(res.out, "census: claims=1 policies=1 violations=0") {
		t.Fatalf("summary missing; output:\n%s", res.out)
	}
}
