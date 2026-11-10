/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package yandex

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	iampb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	keypb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1/awscompatibility"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"
	"github.com/yandex-cloud/go-sdk/v2/pkg/iamkey"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

const testUID = "f454449e-4ce0-40a7-832e-c518c72da6f1"

type stateEntry struct {
	values  map[string]any
	version int
}

type testVault struct {
	state       map[string]stateEntry
	credentials map[string]any
	published   map[string]any
}

func (v *testVault) ReadProfile(context.Context, string) (map[string]any, bool, error) {
	return v.credentials, v.credentials != nil, nil
}

func (v *testVault) ReadPublished(context.Context) (map[string]any, bool, error) {
	return v.published, v.published != nil, nil
}

func (v *testVault) ReadState(_ context.Context, name string) (map[string]any, int, error) {
	entry := v.state[name]
	return maps.Clone(entry.values), entry.version, nil
}

func (v *testVault) WriteState(_ context.Context, name string, values map[string]any, version int) error {
	if v.state[name].version != version {
		return errors.New("CAS mismatch")
	}
	v.state[name] = stateEntry{maps.Clone(values), version + 1}
	return nil
}

func (v *testVault) DeleteState(_ context.Context, name string) error {
	delete(v.state, name)
	return nil
}

type testCloud struct {
	bucket        *storagepb.Bucket
	account       *iampb.ServiceAccount
	keys          []*keypb.AccessKey
	createCalls   int
	keyCalls      int
	policyCalls   int
	lostCreate    bool
	emptyAttempts int
}

func (c *testCloud) close(context.Context) {}

func (c *testCloud) getBucket(context.Context, string) (*storagepb.Bucket, error) {
	return c.bucket, nil
}

func (c *testCloud) createBucket(_ context.Context, folder, name, uid, _ string) error {
	c.createCalls++
	c.bucket = &storagepb.Bucket{FolderId: folder, Name: name, Tags: []*storagepb.Tag{{Key: ownerLabel, Value: uid}}}
	if c.lostCreate {
		c.lostCreate = false
		return errors.New("response lost")
	}
	return nil
}

func (c *testCloud) setPolicy(_ context.Context, _ string, policy *structpb.Struct) error {
	c.policyCalls++
	c.bucket.Policy = policy
	return nil
}

func (c *testCloud) deleteBucket(context.Context, string) error { c.bucket = nil; return nil }

func (c *testCloud) findAccount(context.Context, string, string) (*iampb.ServiceAccount, error) {
	return c.account, nil
}

func (c *testCloud) createAccount(_ context.Context, folder, name, uid, _ string) error {
	c.account = &iampb.ServiceAccount{Id: "agent", Name: name, FolderId: folder, Labels: map[string]string{ownerLabel: uid}}
	return nil
}

func (c *testCloud) deleteAccount(context.Context, string) error {
	c.account, c.keys = nil, nil
	return nil
}

func (c *testCloud) listKeys(context.Context, string) ([]*keypb.AccessKey, error) {
	return slices.Clone(c.keys), nil
}

func (c *testCloud) createKey(_ context.Context, _, description string) (*keypb.CreateAccessKeyResponse, error) {
	c.keyCalls++
	key := &keypb.AccessKey{Id: fmt.Sprintf("key-%d", c.keyCalls), KeyId: fmt.Sprintf("access-%d", c.keyCalls), Description: description}
	c.keys = append(c.keys, key)
	return &keypb.CreateAccessKeyResponse{AccessKey: key, Secret: "agent-secret"}, nil
}

func (c *testCloud) deleteKey(_ context.Context, id string) error {
	c.keys = slices.DeleteFunc(c.keys, func(key *keypb.AccessKey) bool { return key.GetId() == id })
	return nil
}

func (c *testCloud) checkConnection(_ context.Context, _, access, _ string) error {
	if slices.ContainsFunc(c.keys, func(key *keypb.AccessKey) bool { return key.GetKeyId() == access }) {
		return nil
	}
	return errors.New("invalid key")
}

func (c *testCloud) emptyBucket(context.Context, string) (bool, error) {
	c.emptyAttempts++
	if len(c.keys) != 0 {
		return false, errors.New("keys must be revoked before cleanup")
	}
	return c.emptyAttempts > 1, nil
}

func fixture() (*Provider, bucketprovider.ClaimContext, *testVault, *testCloud) {
	api := &testCloud{}
	vault := &testVault{
		state:       map[string]stateEntry{},
		credentials: map[string]any{"folder_id": "folder", "id": "key", "service_account_id": "provisioner", "private_key": "pem"},
	}
	claim := bucketprovider.ClaimContext{UID: testUID, Profile: "system-backups", Vault: vault}
	provider := &Provider{
		connect: func(context.Context, *iamkey.Key) (cloudAPI, error) { return api, nil },
	}
	return provider, claim, vault, api
}

func TestEnsureRecoversLostBucketResponseAndInterruptedKey(t *testing.T) {
	provider, claim, vault, api := fixture()
	api.lostCreate = true
	req := bucketprovider.EnsureRequest{Claim: claim}
	result, err := provider.Ensure(t.Context(), req)
	if err != nil || result.Connection != nil || result.RetryAfter == 0 {
		t.Fatal("lost bucket response should retry without publishing")
	}
	result, err = provider.Ensure(t.Context(), req)
	if err != nil || result.Connection == nil || result.Connection.AccessKey != "access-1" || result.Running.State != bucketprovider.Pending {
		t.Fatal("first key should be ready to publish")
	}

	// A reconcile ended before the first key reached the agent's Vault path.
	result, err = provider.Ensure(t.Context(), req)
	if err != nil || result.Connection == nil || result.Published == nil || *result.Published {
		t.Fatalf("expected a replacement connection to publish, provision stage %v, running stage %v, error %v", result.Provisioned, result.Running, err)
	}
	if api.createCalls != 1 || api.keyCalls != 2 || len(api.keys) != 1 || result.Connection.AccessKey != "access-2" {
		t.Fatal("expected the owned bucket and one replacement key")
	}
	conn := result.Connection
	vault.published = map[string]any{
		"bucketName": conn.BucketName, "accessKey": conn.AccessKey, "secretKey": conn.SecretKey,
		"endpoint": conn.Endpoint, "region": conn.Region, "s3ForcePathStyle": "true",
	}
	vault.state[journalKey].values["keyAttempt"] = "old-attempt"
	vault.state["candidate"] = stateEntry{version: 1}
	result, err = provider.Ensure(t.Context(), req)
	if err != nil || result.Published == nil || !*result.Published || result.Running.State != bucketprovider.Succeeded ||
		api.keyCalls != 2 || len(vault.state) != 1 || field(vault.state[journalKey].values, "keyAttempt") != "" {
		t.Fatal("expected to verify and keep the published key with only the provisioning journal")
	}
	if api.policyCalls != 1 {
		t.Fatalf("policy updates = %d, want 1 across reconciles", api.policyCalls)
	}
}

func TestEnsureRejectsMissingCredentialsBeforeMutating(t *testing.T) {
	provider, claim, vault, api := fixture()
	vault.credentials["private_key"] = " "
	result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim})
	if err != nil || result.Provisioned.Reason != "ProviderConfigInvalid" || api.createCalls != 0 || len(vault.state) != 0 {
		t.Fatal("expected a credentials failure before any mutation")
	}
}

func TestPurgeChecksOwnershipAndResumesInBatches(t *testing.T) {
	provider, claim, vault, api := fixture()
	result, err := provider.Ensure(t.Context(), bucketprovider.EnsureRequest{Claim: claim})
	if err != nil || result.Connection == nil {
		t.Fatal("prepare Yandex bucket")
	}
	req := bucketprovider.DeleteRequest{Claim: claim}
	api.bucket.Tags[0].Value = "another-claim"
	purge, err := provider.Delete(t.Context(), req)
	if err != nil || purge.Done || purge.WarningReason != reasonOwnershipConflict || len(api.keys) != 1 || api.emptyAttempts != 0 {
		t.Fatal("purge must stop before touching a bucket with a foreign owner")
	}
	api.bucket.Tags[0].Value = testUID
	for range 3 {
		purge, err = provider.Delete(t.Context(), req)
		if err != nil || purge.Done || purge.WarningReason != "" {
			t.Fatal("expected cleanup to continue on a later pass")
		}
	}
	purge, err = provider.Delete(t.Context(), req)
	if err != nil || !purge.Done || len(vault.state) != 0 || api.account != nil || api.bucket != nil || len(api.keys) != 0 {
		t.Fatal("expected all owned resources and private state to be cleaned up")
	}
}
