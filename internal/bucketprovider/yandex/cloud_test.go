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
	"io"
	"net/http"
	"strings"
	"testing"

	operationpb "github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"
	storagesdk "github.com/yandex-cloud/go-sdk/services/storage/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

const testBucket = "backup-test"

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func reply(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type bucketRPC struct {
	grpc.ClientConnInterface
	t *testing.T
}

func (c bucketRPC) GetConnection(context.Context, protoreflect.FullName, ...grpc.CallOption) (grpc.ClientConnInterface, error) {
	return c, nil
}

func (c bucketRPC) Invoke(ctx context.Context, method string, req, response any, _ ...grpc.CallOption) error {
	c.t.Helper()
	bucket := &storagepb.Bucket{
		Name: testBucket, FolderId: "system", Tags: []*storagepb.Tag{{Key: ownerLabel, Value: testUID}},
	}
	switch method {
	case storagepb.BucketService_Create_FullMethodName:
		md, _ := metadata.FromOutgoingContext(ctx)
		if keys := md.Get("idempotency-key"); len(keys) != 1 || keys[0] != testUID {
			c.t.Fatalf("idempotency key = %v, want %s", keys, testUID)
		}
		want := &storagepb.CreateBucketRequest{
			Name: testBucket, FolderId: "system", Tags: bucket.Tags,
			AnonymousAccessFlags: &storagepb.AnonymousAccessFlags{
				Read: wrapperspb.Bool(false), List: wrapperspb.Bool(false), ConfigRead: wrapperspb.Bool(false),
			},
		}
		if !proto.Equal(req.(*storagepb.CreateBucketRequest), want) {
			c.t.Fatalf("create request = %v, want %v", req, want)
		}
		response.(*operationpb.Operation).Id = "create-bucket"
	case operationpb.OperationService_Get_FullMethodName:
		if id := req.(*operationpb.GetOperationRequest).GetOperationId(); id != "create-bucket" {
			c.t.Fatalf("operation ID = %q, want create-bucket", id)
		}
		body, err := anypb.New(bucket)
		if err != nil {
			c.t.Fatal(err)
		}
		proto.Merge(response.(*operationpb.Operation), &operationpb.Operation{
			Id: "create-bucket", Done: true, Result: &operationpb.Operation_Response{Response: body},
		})
	case storagepb.BucketService_Get_FullMethodName:
		want := &storagepb.GetBucketRequest{Name: testBucket, View: storagepb.GetBucketRequest_VIEW_FULL}
		if !proto.Equal(req.(*storagepb.GetBucketRequest), want) {
			c.t.Fatalf("get request = %v, want %v", req, want)
		}
		proto.Merge(response.(*storagepb.Bucket), bucket)
	default:
		c.t.Fatalf("unexpected RPC %s", method)
	}
	return nil
}

func TestCreateAndGetBucketThroughSDK(t *testing.T) {
	api := &cloud{buckets: storagesdk.NewBucketClient(bucketRPC{t: t})}
	if err := api.createBucket(t.Context(), "system", testBucket, testUID, testUID); err != nil {
		t.Fatal(err)
	}
	b, err := api.getBucket(t.Context(), testBucket)
	if err != nil || b == nil || !hasOwnerTag(b.Tags, testUID) {
		t.Fatalf("expected the full bucket view with its ownership tag, got %v, error %v", b, err)
	}
}

func TestEmptyBucketUsesIAMAndDeletesVersions(t *testing.T) {
	deletes := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "storage.yandexcloud.net" || req.Header.Get("X-YaCloud-SubjectToken") != "operator-token" {
			t.Fatal("expected operator IAM authentication for Object Storage")
		}
		query := req.URL.Query()
		switch {
		case req.Method == http.MethodGet && query.Has("uploads"):
			return reply(`<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`), nil
		case req.Method == http.MethodGet && query.Has("versions"):
			if deletes > 0 {
				return reply(`<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>`), nil
			}
			return reply(`<ListVersionsResult><Version><Key>snapshot</Key><VersionId>old</VersionId></Version><DeleteMarker><Key>snapshot</Key><VersionId>marker</VersionId></DeleteMarker></ListVersionsResult>`), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/"+testBucket+"/snapshot":
			want := []string{"old", "marker"}[deletes]
			if query.Get("versionId") != want {
				t.Fatalf("versionId = %q, want %q", query.Get("versionId"), want)
			}
			deletes++
			return reply(""), nil
		case req.Method == http.MethodGet && query.Get("list-type") == "2":
			return reply(`<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`), nil
		default:
			t.Fatalf("unexpected S3 request %s %s", req.Method, req.URL)
			return nil, nil
		}
	})}
	api := &cloud{http: client, token: "operator-token"}
	done, err := api.emptyBucket(t.Context(), testBucket)
	if err != nil || done || deletes != 2 {
		t.Fatalf("version cleanup: done %t, deletes %d, error %v", done, deletes, err)
	}
	done, err = api.emptyBucket(t.Context(), testBucket)
	if err != nil || !done {
		t.Fatalf("verify empty bucket: done %t, error %v", done, err)
	}
}
