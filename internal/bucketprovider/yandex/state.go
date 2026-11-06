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

type journal struct {
	claim           bucketprovider.ClaimContext
	version         int
	folder          string
	bucket          string
	account         string
	legacyCandidate bool
}

func loadJournal(ctx context.Context, claim bucketprovider.ClaimContext) (*journal, error) {
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
	return j, nil
}

func (j *journal) save(ctx context.Context) error {
	err := j.claim.Vault.WriteState(ctx, journalKey, map[string]any{
		"uid": j.claim.UID, "folderID": j.folder, "bucketCreate": j.bucket, "accountCreate": j.account,
	}, j.version)
	if err != nil {
		return errors.New("unable to persist Yandex state in Vault")
	}
	j.version++
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

func (j *journal) name() string { return "beget-backup-" + j.claim.UID }

func ensureBucket(ctx context.Context, api cloudAPI, state *journal, create bool) (*storagepb.Bucket, error) {
	name := state.name()
	b, err := api.getBucket(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("lookup bucket: %w", err)
	}
	if b == nil && (create || state.bucket != "") {
		if err := state.start(ctx, &state.bucket); err != nil {
			return nil, err
		}
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
	name := state.name()
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
