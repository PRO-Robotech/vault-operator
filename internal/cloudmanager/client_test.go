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

func TestFakeBucketAPIRoundtrip(t *testing.T) {
	ctx := context.Background()
	f := NewFakeBucketAPI()

	realName, err := f.Create(ctx, CreateInput{CustomerLogin: "c1", BucketName: "b1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if realName == "b1" || stripBucketPrefix(realName) != "b1" {
		t.Fatalf("expected prefixed real name for b1, got %q", realName)
	}
	// Exact lookup works by real name, not the requested one.
	if _, err := f.FindByCustomerBucket(ctx, "c1", "b1"); !errors.Is(err, ErrBucketNotFound) {
		t.Errorf("exact lookup by requested name should miss, got %v", err)
	}
	b, err := f.FindByCustomerBucket(ctx, "c1", realName)
	if err != nil {
		t.Fatalf("find by real name: %v", err)
	}
	if b.Status != StatusRunning || b.AccessKey == "" || b.SecretKey == "" || b.ManagedBy != ManagedBySystem {
		t.Errorf("unexpected bucket: %+v", b)
	}
	// Requested-name lookup finds it despite the prefix.
	if _, err := f.FindByCustomerRequested(ctx, "c1", "b1"); err != nil {
		t.Errorf("requested lookup should find prefixed bucket: %v", err)
	}
	if err := f.Remove(ctx, realName); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := f.FindByCustomerRequested(ctx, "c1", "b1"); !errors.Is(err, ErrBucketNotFound) {
		t.Errorf("after remove, want ErrBucketNotFound, got %v", err)
	}
}

func TestStripBucketPrefix(t *testing.T) {
	cases := map[string]string{
		"c942bd41757d-k8s-dkolbin-ipam-3": "k8s-dkolbin-ipam-3",
		"k8s-dkolbin-ipam-3":              "dkolbin-ipam-3", // no hex prefix: strips first segment
		"nodash":                          "nodash",
	}
	for in, want := range cases {
		if got := stripBucketPrefix(in); got != want {
			t.Errorf("stripBucketPrefix(%q)=%q, want %q", in, got, want)
		}
	}
}
