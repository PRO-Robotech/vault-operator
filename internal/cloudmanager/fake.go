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
	"sync"
)

// FakePrefix is prepended to the requested name to mimic the server-assigned
// real name; tests rely on requested != real.
const FakePrefix = "fakehash-"

// FakeBucketAPI is an in-memory BucketAPI for tests; a set *Hook overrides the
// default behaviour.
type FakeBucketAPI struct {
	mu      sync.Mutex
	buckets map[string]*Bucket

	CreateHook func(ctx context.Context, in CreateInput) (string, error)
	FindHook   func(ctx context.Context, custLogin, bucketName string) (*Bucket, error)
	RemoveHook func(ctx context.Context, bucketName string) error

	Creates int
	Finds   int
	Removes int
}

var _ BucketAPI = (*FakeBucketAPI)(nil)

func NewFakeBucketAPI() *FakeBucketAPI {
	return &FakeBucketAPI{buckets: map[string]*Bucket{}}
}

func (f *FakeBucketAPI) Create(ctx context.Context, in CreateInput) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Creates++
	if f.CreateHook != nil {
		return f.CreateHook(ctx, in)
	}
	mb := in.ManagedBy
	if mb == "" {
		mb = ManagedBySystem
	}
	realName := FakePrefix + in.BucketName
	f.buckets[realName] = &Bucket{
		Name:      realName,
		CustLogin: in.CustomerLogin,
		AccessKey: "AK-" + in.BucketName,
		SecretKey: "SK-" + in.BucketName,
		Fqdn:      realName + ".s3.ru1.storage.beget.cloud",
		Status:    StatusRunning,
		ManagedBy: mb,
		Public:    in.Public,
	}
	return realName, nil
}

func (f *FakeBucketAPI) FindByCustomerBucket(ctx context.Context, custLogin, bucketName string) (*Bucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Finds++
	if f.FindHook != nil {
		return f.FindHook(ctx, custLogin, bucketName)
	}
	b, ok := f.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}
	cp := *b
	return &cp, nil
}

func (f *FakeBucketAPI) FindByCustomerRequested(ctx context.Context, custLogin, requestedName string) (*Bucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Finds++
	for _, b := range f.buckets {
		if b.CustLogin == custLogin && stripBucketPrefix(b.Name) == requestedName {
			cp := *b
			return &cp, nil
		}
	}
	return nil, ErrBucketNotFound
}

func (f *FakeBucketAPI) Remove(ctx context.Context, bucketName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Removes++
	if f.RemoveHook != nil {
		return f.RemoveHook(ctx, bucketName)
	}
	if _, ok := f.buckets[bucketName]; !ok {
		return ErrBucketNotFound
	}
	delete(f.buckets, bucketName)
	return nil
}

// Seed inserts a bucket directly.
func (f *FakeBucketAPI) Seed(b Bucket) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := b
	f.buckets[b.Name] = &cp
}
