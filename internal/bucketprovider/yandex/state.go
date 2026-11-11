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

	"github.com/google/uuid"
	iampb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

const journalKey = "journal"

var errOwnership = errors.New("resource ownership in Yandex does not match the claim")
var errBucketNotFound = errors.New("bound Yandex bucket does not exist")

type journal struct {
	claim           bucketprovider.ClaimContext
	version         int
	folder          string
	bucketName      string
	nameRecorded    bool
	published       map[string]any
	bucket          string
	account         string
	legacyCandidate bool
}

func loadJournal(ctx context.Context, claim bucketprovider.ClaimContext, requestedName string) (*journal, error) {
	data, version, err := claim.Vault.ReadState(ctx, journalKey)
	if err != nil {
		return nil, errors.New("unable to read Yandex state from Vault")
	}
	j := &journal{
		claim: claim, version: version, folder: field(data, "folderID"),
		bucket: field(data, "bucketCreate"), account: field(data, "accountCreate"),
		legacyCandidate: field(data, "keyAttempt") != "",
	}
	if version > 0 && (j.folder == "" || field(data, "uid") != claim.UID) {
		return nil, errOwnership
	}
	published, _, err := claim.Vault.ReadPublished(ctx)
	if err != nil {
		return nil, errors.New("unable to read published agent credentials")
	}
	j.published = published
	j.nameRecorded = field(data, "bucketName") != ""
	names := []any{requestedName, data["bucketName"], published["bucketName"]}
	if !j.nameRecorded && j.bucket != "" {
		// Older attempts always targeted the UID-derived bucket name.
		names = append(names, j.accountName())
	}
	for _, value := range names {
		if value == nil {
			continue
		}
		name, ok := value.(string)
		if !ok {
			return nil, errors.New("invalid saved Yandex bucket name")
		}
		if name == "" {
			continue
		}
		if j.bucketName != "" && j.bucketName != name {
			return nil, fmt.Errorf("%w: saved bucket names %q and %q differ", errOwnership, j.bucketName, name)
		}
		j.bucketName = name
	}
	if j.bucketName == "" && version > 0 {
		j.bucketName = j.accountName()
	}
	return j, nil
}

func (j *journal) save(ctx context.Context) error {
	err := j.claim.Vault.WriteState(ctx, journalKey, map[string]any{
		"uid": j.claim.UID, "folderID": j.folder, "bucketName": j.bucketName,
		"bucketCreate": j.bucket, "accountCreate": j.account,
	}, j.version)
	if err != nil {
		return errors.New("unable to persist Yandex state in Vault")
	}
	j.version++
	j.nameRecorded = true
	return nil
}

func (j *journal) removeLegacyCandidate(ctx context.Context) error {
	if !j.legacyCandidate {
		return nil
	}
	if err := j.claim.Vault.DeleteState(ctx, "candidate"); err != nil {
		return errors.New("unable to remove the legacy agent key candidate from Vault")
	}
	j.legacyCandidate = false
	return j.save(ctx)
}

func (j *journal) start(ctx context.Context, attempt *string) error {
	if *attempt != "" {
		return nil
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return errors.New("unable to generate Yandex operation ID")
	}
	*attempt = id.String()
	return j.save(ctx)
}

func (j *journal) finish(ctx context.Context, attempt *string) error {
	if *attempt == "" {
		return nil
	}
	*attempt = ""
	return j.save(ctx)
}

func (j *journal) accountName() string { return "beget-backup-" + j.claim.UID }

func ensureBucket(ctx context.Context, api cloudAPI, state *journal, required bool) (*storagepb.Bucket, error) {
	name := state.bucketName
	b, err := api.getBucket(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("lookup bucket: %w", err)
	}
	if b == nil && state.bucket != "" {
		if err := api.createBucket(ctx, state.folder, name, state.claim.UID, state.bucket); err != nil && !isConflict(err) {
			return nil, fmt.Errorf("create bucket: %w", err)
		}
		b, err = api.getBucket(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("lookup created bucket: %w", err)
		}
		if b == nil {
			return nil, errors.New("created Yandex bucket is not visible yet")
		}
	}
	if b == nil {
		if required {
			return nil, errBucketNotFound
		}
		return nil, nil
	}
	if b.GetFolderId() != state.folder || b.GetName() != name || !hasOwnerTag(b.GetTags(), state.claim.UID) {
		return nil, errOwnership
	}
	return b, state.finish(ctx, &state.bucket)
}

func hasOwnerTag(tags []*storagepb.Tag, uid string) bool {
	for _, tag := range tags {
		if tag.GetKey() == ownerLabel && tag.GetValue() == uid {
			return true
		}
	}
	return false
}

func ensureAccount(ctx context.Context, api cloudAPI, state *journal, create bool) (*iampb.ServiceAccount, error) {
	name := state.accountName()
	account, err := api.findAccount(ctx, state.folder, name)
	if err != nil {
		return nil, fmt.Errorf("lookup service account: %w", err)
	}
	if account == nil && (create || state.account != "") {
		if err := state.start(ctx, &state.account); err != nil {
			return nil, err
		}
		if err := api.createAccount(ctx, state.folder, name, state.claim.UID, state.account); err != nil && !isConflict(err) {
			return nil, fmt.Errorf("create service account: %w", err)
		}
		account, err = api.findAccount(ctx, state.folder, name)
		if err != nil {
			return nil, fmt.Errorf("lookup created service account: %w", err)
		}
		if account == nil {
			return nil, errors.New("created service account is not visible yet")
		}
	}
	if account == nil {
		return nil, nil
	}
	if account.GetId() == "" || account.GetFolderId() != state.folder || account.GetName() != name || account.GetLabels()[ownerLabel] != state.claim.UID {
		return nil, errOwnership
	}
	return account, state.finish(ctx, &state.account)
}
