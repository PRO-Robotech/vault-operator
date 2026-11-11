/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package yandex

import (
	"errors"
	"maps"
	"slices"
	"testing"

	iampb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	keypb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1/awscompatibility"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

const existingBucket = "security-root"

func existingBucketFixture() (*Provider, bucketprovider.ClaimContext, *testVault, *testCloud) {
	provider, claim, vault, api := fixture()
	claim.UID = "27eaebd9-57ec-4012-a034-9f611d618398"
	api.buckets[existingBucket] = &storagepb.Bucket{
		Name: existingBucket, FolderId: "folder", Tags: []*storagepb.Tag{{Key: ownerLabel, Value: claim.UID}},
	}
	api.account = &iampb.ServiceAccount{
		Id: "agent", Name: "beget-backup-" + claim.UID, FolderId: "folder", Labels: map[string]string{ownerLabel: claim.UID},
	}
	api.keys = []*keypb.AccessKey{{Id: "existing-key", KeyId: "existing-access", Description: "beget:" + claim.UID + ":old-attempt"}}
	vault.published = map[string]any{
		"bucketName": existingBucket, "accessKey": "existing-access", "secretKey": "existing-secret",
		"endpoint": s3Endpoint, "region": s3Region, "s3ForcePathStyle": "true",
	}
	vault.state[journalKey] = stateEntry{
		values: map[string]any{"uid": claim.UID, "folderID": "folder", "bucketName": existingBucket}, version: 1,
	}
	return provider, claim, vault, api
}

func assertBucketCalls(t *testing.T, api *testCloud, name string) {
	t.Helper()
	for _, call := range api.calls {
		switch call.operation {
		case "GetBucket", "CreateBucket", "SetAgentACL", "HeadBucket", "EmptyBucket", "DeleteBucket":
			if call.name != name {
				t.Fatalf("%s addressed %q, want %q", call.operation, call.name, name)
			}
		}
	}
}

func TestEnsureUsesSavedBucketName(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		status, journal, vault bool
		legacyJournal          bool
	}{
		{name: "all sources", status: true, journal: true, vault: true},
		{name: "status only", status: true},
		{name: "journal only", journal: true},
		{name: "published only", vault: true},
		{name: "status and published", status: true, vault: true},
		{name: "old journal and status", status: true, legacyJournal: true},
		{name: "old journal and published", vault: true, legacyJournal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, claim, vault, api := existingBucketFixture()
			if !tc.vault {
				vault.published = nil
			}
			if tc.legacyJournal {
				delete(vault.state[journalKey].values, "bucketName")
			} else if !tc.journal {
				delete(vault.state, journalKey)
			}
			req := bucketprovider.EnsureRequest{Claim: claim}
			if tc.status {
				req.BucketName = existingBucket
			}
			result, err := provider.Ensure(t.Context(), req)
			if err != nil || result.Connection == nil || result.Connection.BucketName != existingBucket || result.BucketName != existingBucket {
				t.Fatalf("expected the saved bucket, got %+v, error %v", result, err)
			}
			if api.createCalls != 0 || len(api.buckets) != 1 || field(vault.state[journalKey].values, "bucketName") != existingBucket {
				t.Fatal("expected to persist the existing bucket name without creating a second bucket")
			}
			if tc.vault && (api.keyCalls != 0 || result.Connection.AccessKey != "existing-access") {
				t.Fatal("expected to reuse the published access key")
			}
			assertBucketCalls(t, api, existingBucket)

			conn := result.Connection
			vault.published = map[string]any{
				"bucketName": conn.BucketName, "accessKey": conn.AccessKey, "secretKey": conn.SecretKey,
				"endpoint": conn.Endpoint, "region": conn.Region, "s3ForcePathStyle": "true",
			}
			restarted := &Provider{connect: provider.connect}
			result, err = restarted.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim})
			if err != nil || result.Connection == nil || *result.Connection != *conn || result.Running.State != bucketprovider.Succeeded {
				t.Fatal("expected the same connection after restart without a status name")
			}
			assertBucketCalls(t, api, existingBucket)
		})
	}
}

func TestIdentityConflictStopsEnsureAndPurge(t *testing.T) {
	const conflictingName = "conflicting-bucket"
	for _, tc := range []struct {
		name   string
		change func(*testVault, *bucketprovider.EnsureRequest)
	}{
		{name: "status disagrees", change: func(_ *testVault, req *bucketprovider.EnsureRequest) { req.BucketName = conflictingName }},
		{name: "journal disagrees", change: func(v *testVault, _ *bucketprovider.EnsureRequest) {
			v.state[journalKey].values["bucketName"] = conflictingName
		}},
		{name: "published disagrees", change: func(v *testVault, _ *bucketprovider.EnsureRequest) { v.published["bucketName"] = conflictingName }},
		{name: "journal owner disagrees", change: func(v *testVault, _ *bucketprovider.EnsureRequest) {
			v.state[journalKey].values["uid"] = "foreign-uid"
		}},
		{name: "journal folder disagrees", change: func(v *testVault, _ *bucketprovider.EnsureRequest) {
			v.state[journalKey].values["folderID"] = "foreign-folder"
		}},
		{name: "legacy pending creation disagrees", change: func(v *testVault, _ *bucketprovider.EnsureRequest) {
			delete(v.state[journalKey].values, "bucketName")
			v.state[journalKey].values["bucketCreate"] = testUID
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, claim, vault, api := existingBucketFixture()
			req := bucketprovider.EnsureRequest{Claim: claim, BucketName: existingBucket}
			tc.change(vault, &req)
			published := maps.Clone(vault.published)
			result, err := provider.Ensure(t.Context(), req)
			if err != nil || result.Connection != nil || result.BucketName != "" || result.Provisioned.Reason != reasonOwnershipConflict {
				t.Fatalf("expected an identity conflict, got %+v, error %v", result, err)
			}
			purge, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim, BucketName: req.BucketName})
			if err != nil || purge.Done || purge.WarningReason != reasonOwnershipConflict {
				t.Fatalf("expected purge to stop on the identity conflict, got %+v, error %v", purge, err)
			}
			if len(api.calls) != 0 || !maps.Equal(vault.published, published) {
				t.Fatal("identity conflict must stop before cloud calls and preserve the published connection")
			}
		})
	}
}

func TestIdentityReadFailureStopsCloudCalls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testVault)
	}{
		{name: "journal read", change: func(v *testVault) { v.stateErr = errors.New("Vault unavailable") }},
		{name: "published read", change: func(v *testVault) { v.publishedErr = errors.New("Vault unavailable") }},
		{name: "invalid journal name", change: func(v *testVault) { v.state[journalKey].values["bucketName"] = 42 }},
		{name: "invalid published name", change: func(v *testVault) { v.published["bucketName"] = 42 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, claim, vault, api := existingBucketFixture()
			tc.change(vault)
			published := maps.Clone(vault.published)
			result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim, BucketName: existingBucket})
			if err != nil || result.Connection != nil || result.Provisioned.Reason != "ProviderStateUnavailable" {
				t.Fatalf("expected a state error, got %+v, error %v", result, err)
			}
			purge, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim, BucketName: existingBucket})
			if err != nil || purge.Done || purge.WarningReason != "DeletionStuck" || len(api.calls) != 0 || !maps.Equal(vault.published, published) {
				t.Fatal("unreadable identity must preserve the published connection and stop cloud calls")
			}
		})
	}
}

func TestRejectsMissingOrForeignBoundBucket(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*testCloud)
	}{
		{name: "missing", reason: "ProviderBucketNotFound", change: func(c *testCloud) { delete(c.buckets, existingBucket) }},
		{name: "foreign owner", reason: reasonOwnershipConflict, change: func(c *testCloud) { c.buckets[existingBucket].Tags[0].Value = "foreign-uid" }},
		{name: "foreign folder", reason: reasonOwnershipConflict, change: func(c *testCloud) { c.buckets[existingBucket].FolderId = "foreign-folder" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, claim, vault, api := existingBucketFixture()
			tc.change(api)
			published := maps.Clone(vault.published)
			result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim, BucketName: existingBucket})
			if err != nil || result.Connection != nil || result.BucketName != "" || result.Provisioned.Reason != tc.reason {
				t.Fatalf("expected %s, got %+v, error %v", tc.reason, result, err)
			}
			if !slices.Equal(api.calls, []cloudCall{{"GetBucket", existingBucket}}) || !maps.Equal(vault.published, published) {
				t.Fatal("expected only a lookup of the bound bucket and no change to its published connection")
			}
			if tc.reason == reasonOwnershipConflict {
				api.calls = nil
				purge, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim, BucketName: existingBucket})
				if err != nil || purge.Done || purge.WarningReason != reasonOwnershipConflict ||
					!slices.Equal(api.calls, []cloudCall{{"GetBucket", existingBucket}}) || !maps.Equal(vault.published, published) {
					t.Fatal("purge must preserve the connection and stop before mutating foreign resources")
				}
			}
		})
	}
}

func TestCreationPersistsNameAndAttemptBeforeCallingYandex(t *testing.T) {
	provider, claim, vault, api := fixture()
	var attempts []string
	api.onCreateBucket = func(name, key string) {
		entry := vault.state[journalKey]
		if field(entry.values, "bucketName") != name || field(entry.values, "bucketCreate") != key || key == "" {
			t.Fatal("bucket name and idempotency key must be persisted before creation")
		}
		attempts = append(attempts, key)
	}
	api.lostCreate = true
	req := bucketprovider.EnsureRequest{Claim: claim}
	result, err := provider.Ensure(t.Context(), req)
	if err != nil || result.Connection != nil || len(attempts) != 1 {
		t.Fatal("expected a retry after the lost creation response")
	}
	name := "beget-backup-" + claim.UID
	delete(api.buckets, name)
	restarted := &Provider{connect: provider.connect}
	result, err = restarted.Ensure(t.Context(), req)
	if err != nil || result.Connection == nil || result.Connection.BucketName != name || len(attempts) != 2 || attempts[0] != attempts[1] {
		t.Fatal("expected the same bucket name and idempotency key after restart")
	}
	if field(vault.state[journalKey].values, "bucketName") != name || field(vault.state[journalKey].values, "bucketCreate") != "" {
		t.Fatal("expected the bucket binding to survive completion of the creation attempt")
	}
	assertBucketCalls(t, api, name)
}

func TestPurgeReplaysPendingCreationForTheBoundBucket(t *testing.T) {
	provider, claim, vault, api := existingBucketFixture()
	delete(api.buckets, existingBucket)
	vault.state[journalKey].values["bucketCreate"] = testUID
	api.onCreateBucket = func(name, key string) {
		if name != existingBucket || key != testUID {
			t.Fatal("purge must replay the recorded creation for the bound bucket")
		}
	}
	result, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim, BucketName: existingBucket})
	if err != nil || result.Done || result.WarningReason != "" || api.createCalls != 1 {
		t.Fatalf("expected purge to recover the in-flight creation, got %+v, error %v", result, err)
	}
	assertBucketCalls(t, api, existingBucket)
}

func TestPurgeUsesSavedBucketNameAfterRestart(t *testing.T) {
	for _, source := range []string{"status", "journal", "published"} {
		t.Run(source, func(t *testing.T) {
			provider, claim, vault, api := existingBucketFixture()
			req := bucketprovider.DeleteRequest{Claim: claim}
			if source == "status" {
				req.BucketName = existingBucket
			}
			if source != "journal" {
				delete(vault.state, journalKey)
			}
			if source != "published" {
				vault.published = nil
			}
			api.buckets["other-bucket"] = &storagepb.Bucket{Name: "other-bucket"}
			var result bucketprovider.DeleteResult
			for range 4 {
				restarted := &Provider{connect: provider.connect}
				var err error
				result, err = restarted.Delete(t.Context(), req)
				if err != nil || result.WarningReason != "" {
					t.Fatalf("purge failed, result %+v, error %v", result, err)
				}
			}
			if !result.Done || api.buckets[existingBucket] != nil || api.buckets["other-bucket"] == nil || len(vault.state) != 0 {
				t.Fatal("expected to delete only the bound bucket and its journal")
			}
			assertBucketCalls(t, api, existingBucket)
		})
	}
}

func TestPurgeAcceptsAnAlreadyRemovedBoundBucket(t *testing.T) {
	provider, claim, vault, api := existingBucketFixture()
	delete(api.buckets, existingBucket)
	api.account, api.keys = nil, nil
	result, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim, BucketName: existingBucket})
	if err != nil || !result.Done || len(vault.state) != 0 || api.createCalls != 0 {
		t.Fatal("expected purge to finish after confirming the bound resources are absent")
	}
	assertBucketCalls(t, api, existingBucket)
}

func TestLegacyJournalWithoutBucketName(t *testing.T) {
	for _, mode := range []string{"pending", "existing", "missing"} {
		t.Run(mode, func(t *testing.T) {
			provider, claim, vault, api := fixture()
			name := "beget-backup-" + claim.UID
			values := map[string]any{"uid": claim.UID, "folderID": "folder"}
			if mode == "pending" {
				values["bucketCreate"] = testUID
				api.onCreateBucket = func(createdName, key string) {
					if createdName != name || key != testUID || field(vault.state[journalKey].values, "bucketName") != name {
						t.Fatal("expected the legacy attempt to stay bound to its original name")
					}
				}
			}
			if mode == "existing" {
				api.buckets[name] = &storagepb.Bucket{
					Name: name, FolderId: "folder", Tags: []*storagepb.Tag{{Key: ownerLabel, Value: claim.UID}},
				}
			}
			vault.state[journalKey] = stateEntry{values: values, version: 1}
			result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				if result.Connection != nil || result.Provisioned.Reason != "ProviderBucketNotFound" {
					t.Fatal("expected a missing legacy bucket to require investigation")
				}
			} else if result.Connection == nil || result.Connection.BucketName != name {
				t.Fatal("expected to recover the legacy bucket binding")
			}
			if mode != "pending" && api.createCalls != 0 {
				t.Fatal("only a recorded legacy creation may be replayed")
			}
			assertBucketCalls(t, api, name)
		})
	}
}

func TestCreationStopsWhenBindingCannotBeSaved(t *testing.T) {
	provider, claim, vault, api := fixture()
	vault.writeErr = errors.New("Vault unavailable")
	result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim})
	if err != nil || result.Connection != nil || result.Provisioned.Reason != "ProviderStateUnavailable" || len(api.calls) != 0 {
		t.Fatal("expected to stop before any cloud call when the bucket binding cannot be saved")
	}
}

func TestPurgeFinishesForClaimWithoutStartedOperations(t *testing.T) {
	provider, claim, vault, api := fixture()
	vault.credentials = nil
	result, err := provider.Delete(t.Context(), bucketprovider.DeleteRequest{Claim: claim})
	if err != nil || !result.Done || len(api.calls) != 0 || len(vault.state) != 0 {
		t.Fatal("expected an unused claim to finish deletion without cloud resources")
	}
}
