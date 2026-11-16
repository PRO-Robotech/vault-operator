/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package bucketprovider

import (
	"context"
	"time"
)

type BucketProvider interface {
	Ensure(context.Context, EnsureRequest) (EnsureResult, error)
	Delete(context.Context, DeleteRequest) (DeleteResult, error)
}

type EnsureRequest struct {
	Claim           ClaimContext
	BucketName      string
	CustomerLogin   string
	ClusterName     string
	Region          string
	ConfigurationID string
	ManagedBy       string
	Public          bool
}

type DeleteRequest struct {
	ManagedBy     string
	PurgeAllowed  bool
	Claim         ClaimContext
	BucketName    string
	CustomerLogin string
	ClusterName   string
}

type ClaimContext struct {
	UID     string
	Profile string
	Vault   ClaimVault
}

// ClaimVault separates provider credentials and private state from agent access.
type ClaimVault interface {
	ReadProfile(ctx context.Context, name string) (map[string]any, bool, error)
	ReadPublished(context.Context) (map[string]any, bool, error)
	ReadState(ctx context.Context, key string) (map[string]any, int, error)
	WriteState(ctx context.Context, key string, data map[string]any, version int) error
	DeleteState(ctx context.Context, key string) error
}

type State uint8

const (
	Succeeded State = iota + 1
	Pending
	Failed
)

type Stage struct {
	State   State
	Reason  string
	Message string
	Warning string
}

// EnsureResult carries observations even while the connection is unavailable.
// A nil BucketStatus or zero Stage leaves the corresponding status unchanged.
type EnsureResult struct {
	Created      bool
	BucketName   string
	BucketStatus *string
	Provisioned  Stage
	Running      Stage
	// Connection can be published while Running is pending.
	Connection *Connection
	// Published is set when the provider has checked the current Vault payload.
	Published  *bool
	RetryAfter time.Duration
}

type Connection struct {
	BucketName     string
	AccessKey      string
	SecretKey      string
	Endpoint       string // S3 host without a URL scheme.
	Region         string
	ForcePathStyle bool
	Cname          string
}

type DeleteResult struct {
	BucketName    string
	Done          bool
	RetryAfter    time.Duration
	WarningReason string
	Warning       string
}
