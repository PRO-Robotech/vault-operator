/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cloudmanager

import (
	"errors"
	"testing"

	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

func TestMapCreateError(t *testing.T) {
	cases := []struct {
		code pb.CreateError_Code
		want error
	}{
		{pb.CreateError_CONFIGURATION_NOT_FOUND, ErrConfigurationNotFound},
		{pb.CreateError_BUCKET_NAME_ALREADY_EXISTS, ErrBucketNameAlreadyExists},
		{pb.CreateError_INVALID_BUCKET_NAME, ErrInvalidBucketName},
		{pb.CreateError_BUCKET_LIMIT_REACHED, ErrBucketLimitReached},
		{pb.CreateError_INSUFFICIENT_FUNDS, ErrInsufficientFunds},
	}
	for _, c := range cases {
		got := mapCreateError(&pb.CreateError{Code: c.code, Message: "x"})
		if !errors.Is(got, c.want) {
			t.Errorf("code %v: got %v, want wraps %v", c.code, got, c.want)
		}
	}
	// Unmapped code → generic error, not any sentinel.
	other := mapCreateError(&pb.CreateError{Code: pb.CreateError_INVALID_DESCRIPTION, Message: "d"})
	if errors.Is(other, ErrConfigurationNotFound) {
		t.Errorf("unmapped code should not match a sentinel: %v", other)
	}
}

func TestManagedByEnum(t *testing.T) {
	if managedByEnum("CUSTOMER") != pb.S3BucketManagedBy_CUSTOMER {
		t.Error("CUSTOMER should map to enum CUSTOMER")
	}
	if managedByEnum("") != pb.S3BucketManagedBy_SYSTEM {
		t.Error("empty should default to SYSTEM")
	}
	if managedByEnum("SYSTEM") != pb.S3BucketManagedBy_SYSTEM {
		t.Error("SYSTEM should map to enum SYSTEM")
	}
}

func TestRequestedNameRe(t *testing.T) {
	cases := []struct {
		name   string
		suffix bool
		want   bool
	}{
		{"c942bd41757d-k8s-dkolbin-ipam-3", false, true},
		{"c942bd41757d-k8s-dkolbin-ipam-3-1", false, false},
		{"c942bd41757d-k8s-dkolbin-ipam-3-1", true, true},
		{"c942bd41757d-k8s-dkolbin-ipam-3-x", true, false},
		{"k8s-dkolbin-ipam-3", true, false},    // no prefix
		{"zz-k8s-dkolbin-ipam-3", true, false}, // prefix is not hex
		{"c942bd41757d-k8s-dkolbin-ipam", true, false},
	}
	re := requestedNameRe("k8s-dkolbin-ipam-3", false)
	reS := requestedNameRe("k8s-dkolbin-ipam-3", true)
	for _, c := range cases {
		r := re
		if c.suffix {
			r = reS
		}
		if got := r.MatchString(c.name); got != c.want {
			t.Errorf("match(%q, suffix=%v) = %v, want %v", c.name, c.suffix, got, c.want)
		}
	}
}

func TestClassifyRemove(t *testing.T) {
	if err := classifyRemove(""); err != nil {
		t.Errorf("empty: %v", err)
	}
	if err := classifyRemove("Not found"); !errors.Is(err, ErrBucketNotFound) {
		t.Errorf("Not found: %v", err)
	}
	if err := classifyRemove("Already removed"); !errors.Is(err, ErrAlreadyRemoved) {
		t.Errorf("Already removed: %v", err)
	}
	// Near misses are not the vocabulary.
	for _, msg := range []string{"not found", "Already removed.", "Not found: x"} {
		if err := classifyRemove(msg); !errors.Is(err, ErrRemoveFailed) {
			t.Errorf("%q: %v, want ErrRemoveFailed", msg, err)
		}
	}
}
