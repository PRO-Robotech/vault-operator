/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package cloudmanager wraps the cloud-manager gRPC S3 surface: create a bucket,
// fetch its credentials, remove it.
package cloudmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

const (
	StatusRunning  = "RUNNING"
	StatusCreating = "CREATING"
	StatusRemoving = "REMOVING"
	StatusRemoved  = "REMOVED"
	StatusError    = "ERROR"
	StatusStopped  = "STOPPED"
)

// Bucket ownership values.
const (
	ManagedBySystem   = "SYSTEM"
	ManagedByCustomer = "CUSTOMER"
)

var (
	ErrConfigurationNotFound   = errors.New("cloud-manager: s3 configuration not found")
	ErrBucketNameAlreadyExists = errors.New("cloud-manager: bucket name already exists")
	ErrInvalidBucketName       = errors.New("cloud-manager: invalid bucket name")
	ErrBucketLimitReached      = errors.New("cloud-manager: bucket limit reached")
	ErrInsufficientFunds       = errors.New("cloud-manager: insufficient funds")
	ErrBucketNotFound          = errors.New("cloud-manager: bucket not found")
)

// Bucket is the domain view of an S3 bucket.
type Bucket struct {
	Name      string
	CustLogin string
	AccessKey string
	SecretKey string
	Fqdn      string
	Cname     string
	Status    string
	ManagedBy string
	Public    bool
}

// CreateInput are the parameters for creating a bucket.
type CreateInput struct {
	CustomerLogin   string
	BucketName      string
	ConfigurationID string
	Region          string
	DisplayName     string
	Public          bool
	ManagedBy       string
}

// BucketAPI is the subset of cloud-manager the bucket-operator depends on.
type BucketAPI interface {
	// Create returns the server-assigned bucket name (with prefix).
	Create(ctx context.Context, in CreateInput) (string, error)
	// FindByCustomerBucket matches by exact server name.
	FindByCustomerBucket(ctx context.Context, custLogin, bucketName string) (*Bucket, error)
	// FindByCustomerRequested matches by the requested name (server name with its
	// prefix stripped), for adopt and self-heal.
	FindByCustomerRequested(ctx context.Context, custLogin, requestedName string) (*Bucket, error)
	Remove(ctx context.Context, bucketName string) error
}

// Client talks to cloud-manager over gRPC.
type Client struct {
	conn  *grpc.ClientConn
	cloud pb.CloudServiceClient
	s3    pb.CloudS3ServiceClient
}

var _ BucketAPI = (*Client)(nil)

func New(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial cloud-manager %q: %w", addr, err)
	}
	return &Client{
		conn:  conn,
		cloud: pb.NewCloudServiceClient(conn),
		s3:    pb.NewCloudS3ServiceClient(conn),
	}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Create(ctx context.Context, in CreateInput) (string, error) {
	resp, err := c.cloud.Create(ctx, &pb.CreateRequest{
		CustomerIdentifier: in.CustomerLogin,
		ConfigurationId:    in.ConfigurationID,
		DisplayName:        in.DisplayName,
		Region:             in.Region,
		Params: &pb.CreateRequest_S3Params{S3Params: &pb.CreateParams{
			BucketName: in.BucketName,
			Public:     in.Public,
			ManagedBy:  managedByEnum(in.ManagedBy),
		}},
	})
	if err != nil {
		return "", fmt.Errorf("cloud-manager create: %w", err)
	}
	if s3err := resp.GetS3Error(); s3err != nil {
		return "", mapCreateError(s3err)
	}
	return resp.GetServiceInfo().GetSlug(), nil
}

func (c *Client) FindByCustomerBucket(ctx context.Context, custLogin, bucketName string) (*Bucket, error) {
	resp, err := c.findAllByCustomer(ctx, custLogin)
	if err != nil {
		return nil, err
	}
	for _, b := range resp.GetBucket() {
		if b.GetName() == bucketName {
			return toDomain(b), nil
		}
	}
	return nil, ErrBucketNotFound
}

func (c *Client) FindByCustomerRequested(ctx context.Context, custLogin, requestedName string) (*Bucket, error) {
	resp, err := c.findAllByCustomer(ctx, custLogin)
	if err != nil {
		return nil, err
	}
	for _, b := range resp.GetBucket() {
		if stripBucketPrefix(b.GetName()) == requestedName {
			return toDomain(b), nil
		}
	}
	return nil, ErrBucketNotFound
}

func (c *Client) findAllByCustomer(ctx context.Context, custLogin string) (*pb.FindAllResponse, error) {
	resp, err := c.s3.FindAll(ctx, &pb.FindAllRequest{Scope: []*pb.FindAllRequest_SearchScope{
		{Condition: &pb.FindAllRequest_SearchScope_ByCustomer{
			ByCustomer: &pb.FindAllRequest_SearchScope_ByCustomerLogin{Login: []string{custLogin}},
		}},
	}})
	if err != nil {
		return nil, fmt.Errorf("cloud-manager findAll: %w", err)
	}
	return resp, nil
}

// stripBucketPrefix drops the server-added "<hex>-" prefix, yielding the
// requested name (the prefix contains no '-').
func stripBucketPrefix(name string) string {
	if i := strings.IndexByte(name, '-'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func (c *Client) Remove(ctx context.Context, bucketName string) error {
	resp, err := c.s3.RemoveBucket(ctx, &pb.RemoveBucketRequest{BucketName: bucketName})
	if err != nil {
		return fmt.Errorf("cloud-manager removeBucket: %w", err)
	}
	if e := resp.GetError(); e != nil && e.GetMessage() != "" {
		return fmt.Errorf("cloud-manager removeBucket: %s", e.GetMessage())
	}
	return nil
}

func managedByEnum(s string) pb.S3BucketManagedBy {
	if s == "CUSTOMER" {
		return pb.S3BucketManagedBy_CUSTOMER
	}
	return pb.S3BucketManagedBy_SYSTEM
}

func toDomain(b *pb.Bucket) *Bucket {
	return &Bucket{
		Name:      b.GetName(),
		CustLogin: b.GetCustLogin(),
		AccessKey: b.GetAccessKey(),
		SecretKey: b.GetSecretKey(),
		Fqdn:      b.GetFqdn(),
		Cname:     b.GetCname(),
		Status:    b.GetStatus().String(),
		ManagedBy: b.GetManagedBy().String(),
		Public:    b.GetPublic(),
	}
}

func mapCreateError(e *pb.CreateError) error {
	switch e.GetCode() {
	case pb.CreateError_CONFIGURATION_NOT_FOUND:
		return fmt.Errorf("%w: %s", ErrConfigurationNotFound, e.GetMessage())
	case pb.CreateError_BUCKET_NAME_ALREADY_EXISTS:
		return fmt.Errorf("%w: %s", ErrBucketNameAlreadyExists, e.GetMessage())
	case pb.CreateError_INVALID_BUCKET_NAME:
		return fmt.Errorf("%w: %s", ErrInvalidBucketName, e.GetMessage())
	case pb.CreateError_BUCKET_LIMIT_REACHED:
		return fmt.Errorf("%w: %s", ErrBucketLimitReached, e.GetMessage())
	case pb.CreateError_INSUFFICIENT_FUNDS:
		return fmt.Errorf("%w: %s", ErrInsufficientFunds, e.GetMessage())
	default:
		return fmt.Errorf("cloud-manager create error [%s]: %s", e.GetCode(), e.GetMessage())
	}
}
