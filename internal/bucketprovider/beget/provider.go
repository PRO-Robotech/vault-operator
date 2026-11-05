/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package beget

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

const (
	requeueCreating  = 15 * time.Second
	requeueRace      = 5 * time.Second
	requeueQuota     = 5 * time.Minute
	requeueTransient = time.Minute
)

type Provider struct {
	buckets                cloudmanager.BucketAPI
	defaultConfigurationID string
}

func New(buckets cloudmanager.BucketAPI, defaultConfigurationID string) *Provider {
	return &Provider{buckets: buckets, defaultConfigurationID: defaultConfigurationID}
}

func (p *Provider) Ensure(ctx context.Context, req bucketprovider.EnsureRequest) (bucketprovider.EnsureResult, error) {
	result := bucketprovider.EnsureResult{BucketName: req.BucketName}
	if result.BucketName == "" {
		result = p.create(ctx, req)
		if result.Provisioned.State != bucketprovider.Succeeded {
			return result, nil
		}
	}

	bucket, name, err := p.resolve(ctx, req.CustomerLogin, req.ClusterName, result.BucketName)
	result.BucketName = name
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		result.Running = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "NotVisibleYet",
			Message: fmt.Sprintf("bucket for %q not yet returned by findAll", req.ClusterName)}
		result.RetryAfter = requeueRace
		return result, nil
	case err != nil:
		result.Running = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "FindFailed", Message: err.Error()}
		result.RetryAfter = requeueTransient
		return result, nil
	case !ownedBy(bucket, req.CustomerLogin):
		result.Running = foreignBucket(bucket, req.CustomerLogin)
		return result, nil
	}

	result.BucketStatus = &bucket.Status
	switch {
	case bucket.Status == cloudmanager.StatusCreating:
		result.Running = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "Creating", Message: "bucket is still CREATING"}
		result.RetryAfter = requeueCreating
	case bucket.Status != cloudmanager.StatusRunning:
		result.Running = bucketprovider.Stage{State: bucketprovider.Failed, Reason: "BadStatus",
			Message: fmt.Sprintf("bucket %q in unexpected status %q", bucket.Name, bucket.Status)}
	case bucket.AccessKey == "" || bucket.SecretKey == "":
		result.Running = bucketprovider.Stage{State: bucketprovider.Failed, Reason: "NoKeys",
			Message: fmt.Sprintf("bucket %q RUNNING but credentials are empty", bucket.Name)}
	default:
		result.Running = bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Running", Message: "bucket is RUNNING with credentials"}
		region := req.Region
		if region == "" {
			region = "ru1"
		}
		result.Connection = &bucketprovider.Connection{
			BucketName:     bucket.Name,
			AccessKey:      bucket.AccessKey,
			SecretKey:      bucket.SecretKey,
			Endpoint:       s3EndpointForRegion(region),
			Region:         region,
			ForcePathStyle: true,
			Cname:          bucket.Cname,
		}
	}
	return result, nil
}

func (p *Provider) create(ctx context.Context, req bucketprovider.EnsureRequest) bucketprovider.EnsureResult {
	requestedName := bucketBaseName(req.CustomerLogin, req.ClusterName)
	cfgID := req.ConfigurationID
	if cfgID == "" {
		cfgID = p.defaultConfigurationID
	}
	managedBy := req.ManagedBy
	if managedBy == "" {
		managedBy = cloudmanager.ManagedBySystem
	}

	realName, err := p.buckets.Create(ctx, cloudmanager.CreateInput{
		CustomerLogin:   req.CustomerLogin,
		BucketName:      requestedName,
		ConfigurationID: cfgID,
		Region:          req.Region,
		DisplayName:     fmt.Sprintf("k8s cluster %s backup", req.ClusterName),
		Public:          req.Public,
		ManagedBy:       managedBy,
	})
	var result bucketprovider.EnsureResult
	switch {
	case err == nil:
		if realName == "" {
			if bucket, findErr := p.buckets.FindByCustomerRequested(ctx, req.CustomerLogin, requestedName); findErr == nil {
				realName = bucket.Name
			}
		}
		if realName == "" {
			result.Provisioned = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "Locating", Message: "bucket created; resolving its name"}
			result.RetryAfter = requeueRace
			return result
		}
		result.BucketName = realName
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Created",
			Message: fmt.Sprintf("bucket %q create accepted", realName)}
	case errors.Is(err, cloudmanager.ErrBucketNameAlreadyExists):
		return p.adopt(ctx, req.CustomerLogin, requestedName)
	case errors.Is(err, cloudmanager.ErrConfigurationNotFound):
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Failed, Reason: "ConfigurationMissing",
			Message: fmt.Sprintf("s3 configuration %q not found (create it in cloud-manager)", cfgID)}
	case errors.Is(err, cloudmanager.ErrInvalidBucketName):
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Failed, Reason: "InvalidBucketName",
			Message: fmt.Sprintf("bucket name %q rejected: %v", requestedName, err)}
	case errors.Is(err, cloudmanager.ErrBucketLimitReached):
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "QuotaExceeded",
			Message: "customer bucket limit reached", Warning: "customer bucket limit reached; retrying"}
		result.RetryAfter = requeueQuota
	default:
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "CreateFailed",
			Message: err.Error(), Warning: err.Error()}
		result.RetryAfter = requeueTransient
	}
	return result
}

func (p *Provider) adopt(ctx context.Context, customerLogin, requestedName string) bucketprovider.EnsureResult {
	bucket, err := p.buckets.FindByCustomerRequested(ctx, customerLogin, requestedName)
	var result bucketprovider.EnsureResult
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "Locating",
			Message: fmt.Sprintf("bucket %q exists; resolving its name", requestedName)}
		result.RetryAfter = requeueRace
	case err != nil:
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Pending, Reason: "FindFailed", Message: err.Error()}
		result.RetryAfter = requeueTransient
	case !ownedBy(bucket, customerLogin):
		result.Provisioned = foreignBucket(bucket, customerLogin)
	default:
		result.BucketName = bucket.Name
		result.Provisioned = bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Exists",
			Message: fmt.Sprintf("bucket %q already exists", bucket.Name)}
	}
	return result
}

// resolve falls back to the requested name to recover old or missing status.
func (p *Provider) resolve(ctx context.Context, customerLogin, clusterName, name string) (*cloudmanager.Bucket, string, error) {
	if name != "" {
		bucket, err := p.buckets.FindByCustomerBucket(ctx, customerLogin, name)
		if !errors.Is(err, cloudmanager.ErrBucketNotFound) {
			return bucket, name, err
		}
	}
	bucket, err := p.buckets.FindByCustomerRequested(ctx, customerLogin, bucketBaseName(customerLogin, clusterName))
	if err != nil {
		return nil, name, err
	}
	return bucket, bucket.Name, nil
}

func (p *Provider) Delete(ctx context.Context, req bucketprovider.DeleteRequest) (bucketprovider.DeleteResult, error) {
	bucket, name, err := p.resolve(ctx, req.CustomerLogin, req.ClusterName, req.BucketName)
	result := bucketprovider.DeleteResult{BucketName: name}
	switch {
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		result.Done = true
	case err != nil:
		result.WarningReason = "DeletionStuck"
		result.Warning = fmt.Sprintf("find bucket for purge: %v", err)
		result.RetryAfter = requeueTransient
	case !ownedBy(bucket, req.CustomerLogin):
		result.Done = true
		result.WarningReason = "ForeignBucket"
		result.Warning = fmt.Sprintf("refusing to remove bucket %q owned by %q", bucket.Name, bucket.CustLogin)
	default:
		if err := p.buckets.Remove(ctx, bucket.Name); err != nil {
			result.WarningReason = "DeletionStuck"
			result.Warning = fmt.Sprintf("remove bucket: %v", err)
			result.RetryAfter = requeueTransient
			return result, nil
		}
		result.Done = true
	}
	return result, nil
}

func ownedBy(bucket *cloudmanager.Bucket, customerLogin string) bool {
	return bucket.CustLogin == "" || bucket.CustLogin == customerLogin
}

func foreignBucket(bucket *cloudmanager.Bucket, customerLogin string) bucketprovider.Stage {
	return bucketprovider.Stage{State: bucketprovider.Failed, Reason: "ForeignBucket",
		Message: fmt.Sprintf("bucket %q owned by %q, expected %q", bucket.Name, bucket.CustLogin, customerLogin)}
}
