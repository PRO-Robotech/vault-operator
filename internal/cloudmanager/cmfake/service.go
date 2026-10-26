/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmfake

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

// Service — адаптер gRPC над Store на контракте cloud-manager, которым
// пользуется клиент оператора: CloudService.create, CloudS3Service.findAll и
// removeBucket.
type Service struct {
	pb.UnimplementedCloudServiceServer
	pb.UnimplementedCloudS3ServiceServer

	store *Store
}

// NewService оборачивает хранилище.
func NewService(store *Store) *Service {
	return &Service{store: store}
}

// Register регистрирует обе службы контракта.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	pb.RegisterCloudServiceServer(r, s)
	pb.RegisterCloudS3ServiceServer(r, s)
}

// msgUnknownParams — отказ настоящей службы на create без параметров услуги.
const msgUnknownParams = "Unknown params for create"

// Create повторяет порядок настоящей службы: клиент ищется первым и вне
// перехвата ошибок S3 (неизвестный — ошибка gRPC INTERNAL), затем вид
// параметров (не S3 — UNIMPLEMENTED), затем создание, чьи отказы уходят
// полем s3_error.
func (s *Service) Create(ctx context.Context, req *pb.CreateRequest) (*pb.CreateResponse, error) {
	if !s.store.Knows(req.GetCustomerIdentifier()) {
		return nil, status.Error(codes.Internal, ErrUnknownCustomer.Error())
	}
	params := req.GetS3Params()
	if params == nil {
		return nil, status.Error(codes.Unimplemented, msgUnknownParams)
	}
	managedBy, ok := managedByName(params.GetManagedBy())
	if !ok {
		return s3ErrorResponse(&CreateError{Code: CodeReserved,
			Message: fmt.Sprintf("unknown bucket managed by: %d", params.GetManagedBy())}), nil
	}
	b, err := s.store.Create(ctx, CreateInput{
		Login:           req.GetCustomerIdentifier(),
		ConfigurationID: req.GetConfigurationId(),
		Region:          req.GetRegion(),
		BucketName:      params.GetBucketName(),
		ManagedBy:       managedBy,
		Public:          params.GetPublic(),
	})
	var ce *CreateError
	switch {
	case err == nil:
		return &pb.CreateResponse{Result: &pb.CreateResponse_ServiceInfo{
			ServiceInfo: &pb.Service{Id: b.ServiceID, Slug: b.Name},
		}}, nil
	case errors.As(err, &ce):
		return s3ErrorResponse(ce), nil
	default:
		return nil, toStatus(err)
	}
}

// FindAll отдаёт бакеты, подходящие под все области запроса.
func (s *Service) FindAll(_ context.Context, req *pb.FindAllRequest) (*pb.FindAllResponse, error) {
	scopes := make([]Scope, 0, len(req.GetScope()))
	for _, sc := range req.GetScope() {
		switch c := sc.GetCondition().(type) {
		case *pb.FindAllRequest_SearchScope_ByCustomer:
			scopes = append(scopes, Scope{Logins: nonNil(c.ByCustomer.GetLogin())})
		case *pb.FindAllRequest_SearchScope_ByBucket:
			scopes = append(scopes, Scope{Names: nonNil(c.ByBucket.GetName())})
		default:
			// Область без условия не совпадает ни с чем.
			scopes = append(scopes, Scope{})
		}
	}
	found := s.store.FindAll(scopes)
	resp := &pb.FindAllResponse{Bucket: make([]*pb.Bucket, 0, len(found))}
	for _, b := range found {
		resp.Bucket = append(resp.Bucket, toProto(b))
	}
	return resp, nil
}

// RemoveBucket принимает снятие; ответ — текст словаря настоящей службы.
func (s *Service) RemoveBucket(_ context.Context, req *pb.RemoveBucketRequest) (*pb.RemoveBucketResponse, error) {
	msg, err := s.store.Remove(req.GetBucketName())
	if err != nil {
		return nil, toStatus(err)
	}
	if msg == "" {
		return &pb.RemoveBucketResponse{}, nil
	}
	return &pb.RemoveBucketResponse{Error: &pb.RemoveBucketResponse_Error{Message: msg}}, nil
}

// nonNil отличает «область задана пустым перечнем» от «области нет»: пустой
// перечень значений (IN ()) не совпадает ни с чем.
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func managedByName(m pb.S3BucketManagedBy) (string, bool) {
	switch m {
	case pb.S3BucketManagedBy_SYSTEM:
		return ManagedBySystem, true
	case pb.S3BucketManagedBy_CUSTOMER:
		return ManagedByCustomer, true
	default:
		return "", false
	}
}

func s3ErrorResponse(ce *CreateError) *pb.CreateResponse {
	return &pb.CreateResponse{Result: &pb.CreateResponse_S3Error{S3Error: &pb.CreateError{
		Code: createCodeProto(ce.Code), Message: ce.Message,
	}}}
}

func createCodeProto(c CreateCode) pb.CreateError_Code {
	switch c {
	case CodeInsufficientFunds:
		return pb.CreateError_INSUFFICIENT_FUNDS
	case CodeConfigurationNotFound:
		return pb.CreateError_CONFIGURATION_NOT_FOUND
	case CodeInvalidBucketName:
		return pb.CreateError_INVALID_BUCKET_NAME
	case CodeBucketLimitReached:
		return pb.CreateError_BUCKET_LIMIT_REACHED
	default:
		return pb.CreateError_CODE_RESERVED
	}
}

func statusProto(st Status) pb.Status {
	switch st {
	case StatusCreating:
		return pb.Status_CREATING
	case StatusRemoving:
		return pb.Status_REMOVING
	case StatusRemoved:
		return pb.Status_REMOVED
	case StatusError:
		return pb.Status_ERROR
	case StatusStopped:
		return pb.Status_STOPPED
	default:
		return pb.Status_RUNNING
	}
}

func toProto(b Bucket) *pb.Bucket {
	managedBy := pb.S3BucketManagedBy_SYSTEM
	if b.ManagedBy == ManagedByCustomer {
		managedBy = pb.S3BucketManagedBy_CUSTOMER
	}
	return &pb.Bucket{
		Public:    b.Public,
		Name:      b.Name,
		CustLogin: b.CustLogin,
		AccessKey: b.AccessKey,
		SecretKey: b.SecretKey,
		Fqdn:      b.Fqdn,
		Status:    statusProto(b.Status),
		ManagedBy: managedBy,
	}
}

// toStatus переводит отказ хранилища в статус gRPC: остановка — UNAVAILABLE,
// неизвестный клиент — INTERNAL, как у настоящей службы, конец срока или
// отмена — их код.
func toStatus(err error) error {
	switch {
	case errors.Is(err, ErrStopped):
		return status.Error(codes.Unavailable, "cmfake is stopping")
	case errors.Is(err, ErrUnknownCustomer):
		return status.Error(codes.Internal, ErrUnknownCustomer.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
