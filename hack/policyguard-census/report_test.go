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
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// brokenPipe refuses every write, as a closed stdout does.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// cleanClaimList is one claim whose only policy stays inside its scope: the
// census over it is a pass when its report reaches the reader.
func cleanClaimList(t *testing.T) []byte {
	t.Helper()
	in, err := json.Marshal(vaultv1alpha1.VaultClaimList{Items: []vaultv1alpha1.VaultClaim{{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "ns"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			SecretsPrefix: "clusters/x",
			Policies: []vaultv1alpha1.PolicySpec{{Name: "own",
				Rules: `path "secret/data/clusters/x/a" { capabilities = ["read"] }`}},
		},
	}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return in
}

// A census whose report did not reach its reader is not a pass: the rollout
// gate reads the report, and an unwritten zero is no zero.
func TestCensusWhoseReportIsNotWrittenIsNotAPass(t *testing.T) {
	var errOut bytes.Buffer
	code := run(nil, bytes.NewReader(cleanClaimList(t)), brokenPipe{}, &errOut)
	if code != 2 {
		t.Fatalf("exit code %d, want 2; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "write census report: broken pipe") {
		t.Fatalf("stderr does not name the write failure:\n%s", errOut.String())
	}
}

// Twin: the same claim with a writable report is a pass.
func TestCensusWhoseReportIsWrittenIsAPass(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, bytes.NewReader(cleanClaimList(t)), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code %d, want 0; output:\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "census: claims=1 policies=1 violations=0") {
		t.Fatalf("summary missing; output:\n%s", out.String())
	}
}
