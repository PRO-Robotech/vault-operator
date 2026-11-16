/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package beget

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

func TestEnsureUsesCloudManagerDefaults(t *testing.T) {
	const realName = "prefix-k8s-user-cluster"
	api := cloudmanager.NewFakeBucketAPI()
	api.CreateHook = func(_ context.Context, input cloudmanager.CreateInput) (string, error) {
		want := cloudmanager.CreateInput{
			CustomerLogin: "user", BucketName: "k8s-user-cluster", ConfigurationID: "s3_default",
			DisplayName: "k8s cluster Cluster backup", ManagedBy: cloudmanager.ManagedBySystem,
		}
		if input != want {
			t.Fatalf("CreateInput = %+v, want %+v", input, want)
		}
		return realName, nil
	}
	api.Seed(cloudmanager.Bucket{
		Name: realName, CustLogin: "user", Status: cloudmanager.StatusRunning,
		AccessKey: "access", SecretKey: "secret", Cname: "bucket-cname",
	})

	result, err := New(api, "s3_default").Ensure(t.Context(), bucketprovider.EnsureRequest{CustomerLogin: "user", ClusterName: "Cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if result.BucketName != realName || !result.Created || result.Provisioned.Reason != "Created" || result.Running.State != bucketprovider.Succeeded {
		t.Fatalf("unexpected bucket observations: %q, %+v, %+v", result.BucketName, result.Provisioned, result.Running)
	}
	want := bucketprovider.Connection{
		BucketName: realName, AccessKey: "access", SecretKey: "secret",
		Endpoint: "s3.ru1.storage.beget.cloud", Region: "ru1", ForcePathStyle: true, Cname: "bucket-cname",
	}
	if result.Connection == nil || *result.Connection != want {
		t.Fatal("unexpected connection parameters")
	}
}

func TestEnsureCreateOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		state   bucketprovider.State
		reason  string
		retry   time.Duration
		warning string
	}{
		{name: "no name yet", state: bucketprovider.Pending, reason: "Locating", retry: 5 * time.Second},
		{name: "conflict not visible", err: cloudmanager.ErrBucketNameAlreadyExists, state: bucketprovider.Pending, reason: "Locating", retry: 5 * time.Second},
		{name: "missing configuration", err: cloudmanager.ErrConfigurationNotFound, state: bucketprovider.Failed, reason: "ConfigurationMissing"},
		{name: "invalid name", err: cloudmanager.ErrInvalidBucketName, state: bucketprovider.Failed, reason: "InvalidBucketName"},
		{name: "quota", err: cloudmanager.ErrBucketLimitReached, state: bucketprovider.Pending, reason: "QuotaExceeded", retry: 5 * time.Minute,
			warning: "customer bucket limit reached; retrying"},
		{name: "unavailable", err: errors.New("unavailable"), state: bucketprovider.Pending, reason: "CreateFailed", retry: time.Minute,
			warning: "unavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := cloudmanager.NewFakeBucketAPI()
			api.CreateHook = func(context.Context, cloudmanager.CreateInput) (string, error) { return "", tt.err }
			result, err := New(api, "s3_default").Ensure(t.Context(), bucketprovider.EnsureRequest{CustomerLogin: "user", ClusterName: "cluster"})
			if err != nil {
				t.Fatal(err)
			}
			if result.Provisioned.State != tt.state || result.Provisioned.Reason != tt.reason ||
				result.Provisioned.Warning != tt.warning || result.RetryAfter != tt.retry || result.Connection != nil {
				t.Fatalf("unexpected provision outcome: %+v, retry %s", result.Provisioned, result.RetryAfter)
			}
		})
	}
}

func TestEnsureObserveOutcomes(t *testing.T) {
	const realName = "prefix-k8s-user-cluster"
	for _, tt := range []struct {
		name   string
		bucket *cloudmanager.Bucket
		err    error
		state  bucketprovider.State
		reason string
		retry  time.Duration
	}{
		{name: "missing", err: cloudmanager.ErrBucketNotFound, state: bucketprovider.Pending, reason: "NotVisibleYet", retry: 5 * time.Second},
		{name: "lookup failure", err: errors.New("unavailable"), state: bucketprovider.Pending, reason: "FindFailed", retry: time.Minute},
		{name: "foreign", bucket: &cloudmanager.Bucket{Name: realName, CustLogin: "other"}, state: bucketprovider.Failed, reason: "ForeignBucket"},
		{name: "creating", bucket: &cloudmanager.Bucket{Name: realName, Status: cloudmanager.StatusCreating},
			state: bucketprovider.Pending, reason: "Creating", retry: 15 * time.Second},
		{name: "stopped", bucket: &cloudmanager.Bucket{Name: realName, Status: "STOPPED"}, state: bucketprovider.Failed, reason: "BadStatus"},
		{name: "empty keys", bucket: &cloudmanager.Bucket{Name: realName, Status: cloudmanager.StatusRunning},
			state: bucketprovider.Failed, reason: "NoKeys"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := cloudmanager.NewFakeBucketAPI()
			api.FindHook = func(context.Context, string, string) (*cloudmanager.Bucket, error) { return tt.bucket, tt.err }
			result, err := New(api, "s3_default").Ensure(t.Context(), bucketprovider.EnsureRequest{
				BucketName: realName, CustomerLogin: "user", ClusterName: "cluster",
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.BucketName != realName || result.Running.State != tt.state || result.Running.Reason != tt.reason ||
				result.RetryAfter != tt.retry || result.Connection != nil || api.Creates != 0 {
				t.Fatalf("unexpected observation: name %q, %+v, retry %s, creates %d", result.BucketName, result.Running, result.RetryAfter, api.Creates)
			}
		})
	}
}

func TestDeleteOutcomes(t *testing.T) {
	const realName = "prefix-k8s-user-cluster"
	for _, tt := range []struct {
		name      string
		login     string
		managedBy string
		status    string
		allowed   bool
		findErr   error
		removeErr error
		done      bool
		reason    string
		removes   int
	}{
		{name: "missing", findErr: cloudmanager.ErrBucketNotFound, reason: "DeletionStuck"},
		{name: "lookup failure", findErr: errors.New("lookup unavailable"), reason: "DeletionStuck"},
		{name: "foreign", login: "other", managedBy: "SYSTEM", allowed: true, reason: "DeletionBlocked"},
		{name: "empty owner", managedBy: "SYSTEM", allowed: true, reason: "DeletionBlocked"},
		{name: "other management mode", login: "user", managedBy: "CUSTOMER", allowed: true, reason: "DeletionBlocked"},
		{name: "unproven ownership", login: "user", managedBy: "SYSTEM", status: "RUNNING", reason: "DeletionBlocked"},
		{name: "remove failure", login: "user", managedBy: "SYSTEM", status: "RUNNING", allowed: true,
			removeErr: errors.New("remove unavailable"), reason: "DeletionStuck", removes: 1},
		{name: "removal requested", login: "user", managedBy: "SYSTEM", status: "RUNNING", allowed: true, reason: "BucketRemoving", removes: 1},
		{name: "removing", login: "user", managedBy: "SYSTEM", status: "REMOVING", allowed: true, reason: "BucketRemoving"},
		{name: "removed", login: "user", managedBy: "SYSTEM", status: "REMOVED", allowed: true, done: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := cloudmanager.NewFakeBucketAPI()
			api.FindHook = func(_ context.Context, _ string, name string) (*cloudmanager.Bucket, error) {
				if name != realName {
					t.Fatalf("looked up %q, want %q", name, realName)
				}
				return &cloudmanager.Bucket{Name: realName, CustLogin: tt.login, ManagedBy: tt.managedBy, Status: tt.status}, tt.findErr
			}
			api.RemoveHook = func(_ context.Context, name string) error {
				if name != realName {
					t.Fatalf("removed %q, want %q", name, realName)
				}
				return tt.removeErr
			}
			result, err := New(api, "s3_default").Delete(t.Context(), bucketprovider.DeleteRequest{
				BucketName: realName, CustomerLogin: "user", ClusterName: "cluster", PurgeAllowed: tt.allowed,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Done != tt.done || result.WarningReason != tt.reason ||
				(result.RetryAfter > 0) == tt.done || api.Removes != tt.removes {
				t.Fatalf("unexpected deletion outcome: %+v, removes %d", result, api.Removes)
			}
		})
	}
}
