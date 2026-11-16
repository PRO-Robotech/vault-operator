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
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	iampb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	keypb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1/awscompatibility"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"
	"github.com/yandex-cloud/go-sdk/v2/pkg/iamkey"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

const retryAfter = 15 * time.Second
const reasonOwnershipConflict = "ProviderOwnershipConflict"

type profile struct {
	folder string
	key    *iamkey.Key
}

type cloudAPI interface {
	close(context.Context)
	getBucket(context.Context, string) (*storagepb.Bucket, error)
	createBucket(context.Context, string, string, string, string) error
	setAgentACL(context.Context, string, *storagepb.ACL) error
	deleteBucket(context.Context, string) error
	findAccount(context.Context, string, string) (*iampb.ServiceAccount, error)
	createAccount(context.Context, string, string, string, string) error
	deleteAccount(context.Context, string) error
	listKeys(context.Context, string) ([]*keypb.AccessKey, error)
	createKey(context.Context, string, string) (*keypb.CreateAccessKeyResponse, error)
	deleteKey(context.Context, string) error
	checkConnection(context.Context, string, string, string) error
	emptyBucket(context.Context, string) (bool, error)
}

type Provider struct {
	connect func(context.Context, *iamkey.Key) (cloudAPI, error)
}

func New() *Provider {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Provider{
		connect: func(ctx context.Context, key *iamkey.Key) (cloudAPI, error) {
			return authenticate(ctx, client, key)
		},
	}
}

func readProfile(ctx context.Context, claim bucketprovider.ClaimContext) (profile, error) {
	if len(validation.IsDNS1123Label(claim.Profile)) != 0 {
		return profile{}, errors.New("invalid Yandex profile name")
	}
	data, found, err := claim.Vault.ReadProfile(ctx, claim.Profile)
	if err != nil {
		return profile{}, errors.New("unable to read Yandex profile from Vault")
	}
	if !found {
		return profile{}, errors.New("missing Yandex profile in Vault")
	}
	folder := strings.TrimSpace(field(data, "folder_id"))
	key := &iamkey.Key{
		Id: field(data, "id"), PrivateKey: field(data, "private_key"),
		Subject: &iamkey.Key_ServiceAccountId{ServiceAccountId: field(data, "service_account_id")},
	}
	if folder == "" || strings.TrimSpace(key.GetId()) == "" || strings.TrimSpace(key.GetServiceAccountId()) == "" || strings.TrimSpace(key.GetPrivateKey()) == "" {
		return profile{}, errors.New("incomplete Yandex profile: folder ID and authorized key are required")
	}
	return profile{folder: folder, key: key}, nil
}

func (p *Provider) Ensure(ctx context.Context, req bucketprovider.EnsureRequest) (bucketprovider.EnsureResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	claim := req.Claim
	if err := validateClaim(claim); err != nil {
		return provisionFailure("ProviderConfigInvalid", err), nil
	}
	profile, err := readProfile(ctx, claim)
	if err != nil {
		return provisionFailure("ProviderConfigInvalid", err), nil
	}
	state, err := loadJournal(ctx, claim, req.BucketName)
	if err != nil {
		return provisionFailure("ProviderStateUnavailable", err), nil
	}
	if state.version == 0 {
		state.folder = profile.folder
	}
	if state.folder != profile.folder {
		return provisionFailure(reasonOwnershipConflict, errOwnership), nil
	}
	api, err := p.connect(ctx, profile.key)
	if err != nil {
		return provisionFailure("ProviderCredentialsUnavailable", err), nil
	}
	defer api.close(ctx)
	if state.bucketName == "" {
		state.bucketName = state.accountName()
		if err := state.start(ctx, &state.bucket); err != nil {
			return provisionFailure("ProviderStateUnavailable", err), nil
		}
	}
	if !state.nameRecorded {
		if err := state.save(ctx); err != nil {
			return provisionFailure("ProviderStateUnavailable", err), nil
		}
	}
	if err := state.removeLegacyCandidate(ctx); err != nil {
		return provisionFailure("ProviderStateUnavailable", err), nil
	}

	b, err := ensureBucket(ctx, api, state, true)
	if err != nil {
		return provisionFailure("ProviderBucketUnavailable", err), nil
	}
	result := bucketprovider.EnsureResult{
		BucketName: b.GetName(), RetryAfter: retryAfter,
		Provisioned: bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Created", Message: "Yandex bucket ownership verified"},
	}
	conn, published, err := ensureAgent(ctx, api, state, b)
	if err != nil {
		result.Running = failure("ProviderAgentAccessUnavailable", err)
		return result, nil
	}
	result.Connection = conn
	result.Published = &published
	if !published {
		result.Running = bucketprovider.Stage{
			State: bucketprovider.Pending, Reason: "AwaitingAccessCheck", Message: "waiting to verify published Yandex credentials",
		}
		return result, nil
	}
	status := "RUNNING"
	result.BucketStatus = &status
	result.Running = bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Running", Message: "Yandex bucket is accessible with agent credentials"}
	result.RetryAfter = 0
	return result, nil
}

func ensureAgent(ctx context.Context, api cloudAPI, state *journal, b *storagepb.Bucket) (*bucketprovider.Connection, bool, error) {
	account, err := ensureAccount(ctx, api, state, true)
	if err != nil {
		return nil, false, err
	}
	acl, changed := agentACL(b, account.GetId())
	if changed {
		if err := api.setAgentACL(ctx, b.GetName(), acl); err != nil {
			return nil, false, fmt.Errorf("configure agent access: %w", err)
		}
	}
	return ensureCredentials(ctx, api, state, b.GetName(), account.GetId())
}

func validateClaim(claim bucketprovider.ClaimContext) error {
	uid, err := uuid.Parse(claim.UID)
	if err != nil || uid.String() != claim.UID || claim.Vault == nil {
		return errors.New("claim UID or Vault state access is invalid")
	}
	return nil
}

func field(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

func failure(reason string, err error) bucketprovider.Stage {
	if errors.Is(err, errOwnership) {
		reason = reasonOwnershipConflict
	}
	if errors.Is(err, errBucketNotFound) {
		reason = "ProviderBucketNotFound"
	}
	return bucketprovider.Stage{State: bucketprovider.Failed, Reason: reason, Message: err.Error()}
}

func provisionFailure(reason string, err error) bucketprovider.EnsureResult {
	return bucketprovider.EnsureResult{Provisioned: failure(reason, err), RetryAfter: retryAfter}
}
