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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

func (p *Provider) Delete(ctx context.Context, req bucketprovider.DeleteRequest) (bucketprovider.DeleteResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	done, err := p.purge(ctx, req)
	result := bucketprovider.DeleteResult{Done: done}
	if !done {
		result.RetryAfter = retryAfter
	}
	if err != nil {
		result.WarningReason = "DeletionStuck"
		if errors.Is(err, errOwnership) {
			result.WarningReason = reasonOwnershipConflict
		}
		result.Warning = err.Error()
	}
	return result, nil
}

func (p *Provider) purge(ctx context.Context, req bucketprovider.DeleteRequest) (bool, error) {
	claim := req.Claim
	if err := validateClaim(claim); err != nil {
		return false, err
	}
	state, err := loadJournal(ctx, claim, req.BucketName)
	if err != nil {
		return false, err
	}
	if state.version == 0 && state.bucketName == "" {
		return true, nil
	}
	profile, err := readProfile(ctx, claim)
	if err != nil {
		return false, err
	}
	if state.version == 0 {
		state.folder = profile.folder
	}
	if state.folder != profile.folder {
		return false, errOwnership
	}
	if !state.nameRecorded {
		if err := state.save(ctx); err != nil {
			return false, err
		}
	}
	api, err := p.connect(ctx, profile.key)
	if err != nil {
		return false, err
	}
	defer api.close(ctx)
	if err := state.removeLegacyCandidate(ctx); err != nil {
		return false, err
	}
	done, err := purgeResources(ctx, api, state)
	if err != nil || !done {
		return false, err
	}
	if err := claim.Vault.DeleteState(ctx, journalKey); err != nil {
		return false, errors.New("unable to remove Yandex state from Vault")
	}
	return true, nil
}

func purgeResources(ctx context.Context, api cloudAPI, state *journal) (bool, error) {
	b, err := ensureBucket(ctx, api, state, false)
	if err != nil {
		return false, err
	}
	account, err := ensureAccount(ctx, api, state, false)
	if err != nil {
		return false, err
	}
	if account != nil {
		// Yandex deletes the static keys along with their service account.
		if err := api.deleteAccount(ctx, account.GetId()); err != nil {
			return false, fmt.Errorf("delete agent account: %w", err)
		}
		return false, nil
	}
	if b != nil {
		empty, err := api.emptyBucket(ctx, b.GetName())
		if err != nil || !empty {
			return false, err
		}
		if err := api.deleteBucket(ctx, b.GetName()); err != nil && status.Code(err) != codes.NotFound {
			return false, fmt.Errorf("delete bucket: %w", err)
		}
		// Observe absence in a fresh pass before dropping ownership state.
		return false, nil
	}
	return true, nil
}
