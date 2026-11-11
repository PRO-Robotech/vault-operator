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

	iampb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1"
	keypb "github.com/yandex-cloud/go-genproto/yandex/cloud/iam/v1/awscompatibility"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"
	storagesdk "github.com/yandex-cloud/go-sdk/services/storage/v1"
	ycsdk "github.com/yandex-cloud/go-sdk/v2"
	"github.com/yandex-cloud/go-sdk/v2/credentials"
	"github.com/yandex-cloud/go-sdk/v2/pkg/authentication"
	"github.com/yandex-cloud/go-sdk/v2/pkg/endpoints"
	"github.com/yandex-cloud/go-sdk/v2/pkg/iamkey"
	"github.com/yandex-cloud/go-sdk/v2/pkg/operation"
	"github.com/yandex-cloud/go-sdk/v2/pkg/options"
	"github.com/yandex-cloud/go-sdk/v2/pkg/transport"
	transportgrpc "github.com/yandex-cloud/go-sdk/v2/pkg/transport/grpc"
	"github.com/yandex-cloud/go-sdk/v2/pkg/transport/middleware/idempotency"
	iamsdk "github.com/yandex-cloud/go-sdk/v2/services/iam/v1"
	keysdk "github.com/yandex-cloud/go-sdk/v2/services/iam/v1/awscompatibility"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	s3Endpoint = "storage.yandexcloud.net"
	s3Region   = "ru-central1"
	ownerLabel = "beget-claim-uid"
)

type cloud struct {
	sdk      *ycsdk.SDK
	buckets  storagesdk.BucketClient
	accounts iamsdk.ServiceAccountClient
	keys     keysdk.AccessKeyClient
	http     *http.Client
	token    string
}

var yandexEndpoints = endpoints.NewPrefixEndpointsResolver(endpoints.PrefixToEndpoint{
	"yandex.cloud.iam.v1":     endpoints.NewEndpointParams("iam.api.cloud.yandex.net:443"),
	"yandex.cloud.storage.v1": endpoints.NewEndpointParams("storage.api.cloud.yandex.net:443"),
	"yandex.cloud.operation":  endpoints.NewEndpointParams("operation.api.cloud.yandex.net:443"),
})

func authenticate(ctx context.Context, client *http.Client, key *iamkey.Key) (*cloud, error) {
	creds, err := credentials.ServiceAccountKey(key)
	if err != nil {
		return nil, errors.New("invalid Yandex authorized key")
	}
	// Use a managed connector for the token shared by the management and S3 clients.
	pool := transportgrpc.NewConnPool(nil)
	defer func() { _ = pool.Shutdown(ctx) }()
	iam := iamsdk.NewIamTokenClient(transport.NewConnector(yandexEndpoints, pool))
	token, err := authentication.NewAuthenticator(zap.NewNop(), creds, iam).CreateIAMToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain IAM token: %w", apiFailure(err))
	}
	if token.GetIamToken() == "" {
		return nil, errors.New("empty Yandex IAM token response")
	}
	sdk, err := ycsdk.Build(ctx,
		options.WithCredentials(credentials.IAMTokenWithExpiry(token.GetIamToken(), token.GetExpiresAt())),
		options.WithEndpointsResolver(yandexEndpoints),
		options.WithCustomDialOptions(grpc.WithChainUnaryInterceptor(idempotency.Interceptor())),
	)
	if err != nil {
		return nil, errors.New("unable to initialize Yandex SDK")
	}
	return &cloud{
		sdk: sdk, http: client, token: token.GetIamToken(), buckets: storagesdk.NewBucketClient(sdk),
		accounts: iamsdk.NewServiceAccountClient(sdk), keys: keysdk.NewAccessKeyClient(sdk),
	}, nil
}

func (c *cloud) close(ctx context.Context) {
	_ = c.sdk.Shutdown(ctx)
}

// Keep the status code for retry and ownership checks without exposing the server response.
func apiFailure(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(status.Code(err), "Yandex API request failed")
}

func isConflict(err error) bool {
	switch status.Code(err) {
	case codes.AlreadyExists, codes.FailedPrecondition, codes.Aborted:
		return true
	default:
		return false
	}
}

func waitOperation[Request any, Operation interface {
	Abstract() operation.AbstractOperation
}](
	ctx context.Context, call func(context.Context, *Request, ...grpc.CallOption) (Operation, error), request *Request,
) error {
	op, err := call(ctx, request)
	if err == nil {
		_, err = op.Abstract().Wait(ctx)
	}
	return apiFailure(err)
}

func (c *cloud) getBucket(ctx context.Context, name string) (*storagepb.Bucket, error) {
	b, err := c.buckets.Get(ctx, &storagepb.GetBucketRequest{Name: name, View: storagepb.GetBucketRequest_VIEW_FULL})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	return b, apiFailure(err)
}

func privateAccessFlags() *storagepb.AnonymousAccessFlags {
	return &storagepb.AnonymousAccessFlags{
		Read: wrapperspb.Bool(false), List: wrapperspb.Bool(false), ConfigRead: wrapperspb.Bool(false),
	}
}

func (c *cloud) createBucket(ctx context.Context, folder, name, uid, key string) error {
	return waitOperation(withIdempotencyKey(ctx, key), c.buckets.Create, &storagepb.CreateBucketRequest{
		FolderId: folder, Name: name, Tags: []*storagepb.Tag{{Key: ownerLabel, Value: uid}},
		AnonymousAccessFlags: privateAccessFlags(),
	})
}

func (c *cloud) setPolicy(ctx context.Context, name string, policy *structpb.Struct) error {
	return waitOperation(ctx, c.buckets.Update, &storagepb.UpdateBucketRequest{
		Name: name, Policy: policy, AnonymousAccessFlags: privateAccessFlags(),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"policy", "anonymous_access_flags"}},
	})
}

func (c *cloud) deleteBucket(ctx context.Context, name string) error {
	return waitOperation(ctx, c.buckets.Delete, &storagepb.DeleteBucketRequest{Name: name})
}

func (c *cloud) findAccount(ctx context.Context, folder, name string) (*iampb.ServiceAccount, error) {
	accounts, err := c.accounts.Iterator(ctx, &iampb.ListServiceAccountsRequest{
		FolderId: folder, Filter: fmt.Sprintf("name = %q", name),
	}).Take(2)
	if err != nil || len(accounts) == 0 {
		return nil, apiFailure(err)
	}
	if len(accounts) > 1 {
		return nil, errors.New("ambiguous service account lookup")
	}
	return accounts[0], nil
}

func (c *cloud) createAccount(ctx context.Context, folder, name, uid, key string) error {
	return waitOperation(withIdempotencyKey(ctx, key), c.accounts.Create, &iampb.CreateServiceAccountRequest{
		FolderId: folder, Name: name, Labels: map[string]string{ownerLabel: uid},
	})
}

func (c *cloud) deleteAccount(ctx context.Context, id string) error {
	err := waitOperation(ctx, c.accounts.Delete, &iampb.DeleteServiceAccountRequest{ServiceAccountId: id})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func (c *cloud) listKeys(ctx context.Context, accountID string) ([]*keypb.AccessKey, error) {
	keys, err := c.keys.Iterator(ctx, &keypb.ListAccessKeysRequest{ServiceAccountId: accountID}).TakeAll()
	return keys, apiFailure(err)
}

func (c *cloud) createKey(ctx context.Context, accountID, description string) (*keypb.CreateAccessKeyResponse, error) {
	response, err := c.keys.Create(ctx, &keypb.CreateAccessKeyRequest{
		ServiceAccountId: accountID, Description: description,
	})
	if err != nil {
		return nil, apiFailure(err)
	}
	k := response.GetAccessKey()
	if k.GetId() == "" || k.GetKeyId() == "" || response.GetSecret() == "" {
		return nil, errors.New("incomplete S3 credentials returned by Yandex")
	}
	return response, nil
}

func (c *cloud) deleteKey(ctx context.Context, id string) error {
	err := waitOperation(ctx, c.keys.Delete, &keypb.DeleteAccessKeyRequest{AccessKeyId: id})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func withIdempotencyKey(ctx context.Context, key string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "idempotency-key", key)
}
