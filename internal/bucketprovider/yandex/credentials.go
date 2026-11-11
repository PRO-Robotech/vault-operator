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
	"fmt"
	"strings"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
)

func ensureCredentials(ctx context.Context, api cloudAPI, state *journal, name, accountID string) (*bucketprovider.Connection, bool, error) {
	published := state.published
	keys, err := api.listKeys(ctx, accountID)
	if err != nil {
		return nil, false, fmt.Errorf("list agent keys: %w", err)
	}

	// A key whose secret did not reach Vault can only be revoked and reissued.
	access, secret := field(published, "accessKey"), field(published, "secretKey")
	description := "beget:" + state.claim.UID + ":"
	var publishedKeyExists bool
	for _, key := range keys {
		if key.GetId() == "" || key.GetKeyId() == "" || !strings.HasPrefix(key.GetDescription(), description) {
			continue
		}
		if key.GetKeyId() == access {
			publishedKeyExists = true
		} else if err := api.deleteKey(ctx, key.GetId()); err != nil {
			return nil, false, fmt.Errorf("revoke unpublished agent key: %w", err)
		}
	}
	if publishedKeyExists && field(published, "bucketName") == name && secret != "" {
		conn := agentConnection(name, access, secret)
		if field(published, "endpoint") != s3Endpoint || field(published, "region") != s3Region ||
			field(published, "s3ForcePathStyle") != "true" {
			return conn, false, nil
		}
		if err := api.checkConnection(ctx, name, access, secret); err != nil {
			return nil, false, err
		}
		return conn, true, nil
	}

	key, err := api.createKey(ctx, accountID, description)
	if err != nil {
		return nil, false, fmt.Errorf("issue agent key: %w", err)
	}
	return agentConnection(name, key.GetAccessKey().GetKeyId(), key.GetSecret()), false, nil
}

func agentConnection(name, access, secret string) *bucketprovider.Connection {
	return &bucketprovider.Connection{
		BucketName: name, AccessKey: access, SecretKey: secret, Endpoint: s3Endpoint, Region: s3Region, ForcePathStyle: true,
	}
}
