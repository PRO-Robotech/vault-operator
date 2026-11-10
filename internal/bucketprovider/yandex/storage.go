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
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	storagepb "github.com/yandex-cloud/go-genproto/yandex/cloud/storage/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func agentPolicy(bucketName, accountID string) (*structpb.Struct, error) {
	resource := "arn:aws:s3:::" + bucketName
	principal := map[string]any{"CanonicalUser": accountID}
	allow := func(resource string, actions ...any) map[string]any {
		return map[string]any{"Effect": "Allow", "Principal": principal, "Action": actions, "Resource": resource}
	}
	policy, err := structpb.NewStruct(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			allow(resource, "s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"),
			allow(resource+"/*", "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"),
		},
	})
	if err != nil {
		return nil, errors.New("unable to encode Yandex bucket policy")
	}
	return policy, nil
}

func matchesPolicy(b *storagepb.Bucket, want *structpb.Struct) bool {
	flags := b.GetAnonymousAccessFlags()
	return proto.Equal(b.GetPolicy(), want) &&
		!flags.GetRead().GetValue() && !flags.GetList().GetValue() && !flags.GetConfigRead().GetValue()
}

type iamStorageHTTP struct {
	client *http.Client
	token  string
}

func (c iamStorageHTTP) Do(req *http.Request) (*http.Response, error) {
	request := req.Clone(req.Context())
	request.Header.Set("X-YaCloud-SubjectToken", c.token)
	return c.client.Do(request)
}

func storageClient(client aws.HTTPClient, creds aws.CredentialsProvider) *s3.Client {
	return s3.New(s3.Options{
		Region: s3Region, BaseEndpoint: aws.String(s3Endpoint), UsePathStyle: true,
		HTTPClient: client, Credentials: creds, RetryMaxAttempts: 2,
	})
}

func (c *cloud) checkConnection(ctx context.Context, name, access, secret string) error {
	client := storageClient(c.http, aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, Source: "Yandex IAM"}, nil
	}))
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(name)})
	if err != nil {
		return errors.New("backup agent S3 access is not ready")
	}
	return nil
}

// Each pass handles a bounded batch and starts again at the head of the bucket.
func (c *cloud) emptyBucket(ctx context.Context, name string) (bool, error) {
	client := storageClient(iamStorageHTTP{client: c.http, token: c.token}, aws.AnonymousCredentials{})
	bucketName := aws.String(name)
	batchSize := aws.Int32(20)
	uploads, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: bucketName, MaxUploads: batchSize})
	if err != nil {
		return false, errors.New("list incomplete multipart uploads failed")
	}
	for _, upload := range uploads.Uploads {
		_, err := client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: bucketName, Key: upload.Key, UploadId: upload.UploadId})
		if err != nil {
			return false, errors.New("abort incomplete multipart upload failed")
		}
	}
	if len(uploads.Uploads) > 0 || aws.ToBool(uploads.IsTruncated) {
		return false, nil
	}

	versions, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: bucketName, MaxKeys: batchSize})
	if err != nil {
		return false, errors.New("list object versions failed")
	}
	for _, object := range versions.Versions {
		if err := deleteVersion(ctx, client, bucketName, object.Key, object.VersionId); err != nil {
			return false, err
		}
	}
	for _, marker := range versions.DeleteMarkers {
		if err := deleteVersion(ctx, client, bucketName, marker.Key, marker.VersionId); err != nil {
			return false, err
		}
	}
	if len(versions.Versions)+len(versions.DeleteMarkers) > 0 || aws.ToBool(versions.IsTruncated) {
		return false, nil
	}

	objects, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: bucketName, MaxKeys: batchSize})
	if err != nil {
		return false, errors.New("list objects failed")
	}
	for _, object := range objects.Contents {
		if err := deleteVersion(ctx, client, bucketName, object.Key, nil); err != nil {
			return false, err
		}
	}
	return len(objects.Contents) == 0 && !aws.ToBool(objects.IsTruncated), nil
}

func deleteVersion(ctx context.Context, client *s3.Client, bucket, key, version *string) error {
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: bucket, Key: key, VersionId: version})
	if err != nil {
		return errors.New("delete object or version failed")
	}
	return nil
}
