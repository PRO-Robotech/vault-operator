/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package cmfake is an in-process cloud-manager gRPC server for tests. It
// reproduces the server semantics the operator depends on, as read from the
// cloud-manager sources:
//
//   - findAll: scopes are ANDed, values inside one scope are ORed (IN); no
//     scope returns everything; REMOVED rows are returned too;
//   - create: the real name is lower(prefix + "-" + requested); a taken name
//     (in any status, REMOVED included) gets a "-N" suffix instead of an error;
//   - removeBucket: always "success" with an optional text error: "Not found"
//     (never existed), "Already removed" (status REMOVED); otherwise the bucket
//     goes REMOVING and becomes REMOVED asynchronously.
package cmfake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

// Server is the fake. Zero value is not usable; call New.
type Server struct {
	pb.UnimplementedCloudServiceServer
	pb.UnimplementedCloudS3ServiceServer

	mu      sync.Mutex
	buckets []*pb.Bucket
	// removing counts the findAll calls left before a REMOVING bucket turns REMOVED.
	removing map[string]int

	// ScopesOR switches findAll to OR semantics between scopes, to prove the
	// client does not trust the server-side search area.
	ScopesOR bool
	// RemovalPolls is how many findAll calls observe REMOVING before REMOVED.
	RemovalPolls int

	// Hang* block the RPC until its context is done.
	HangCreate  bool
	HangFindAll bool
	HangRemove  bool

	// FindAllErrs are returned, one per call, before findAll answers normally.
	FindAllErrs []error
	// CreateErrs are returned, one per call, before create answers normally.
	CreateErrs []error
	// CreateError, when set, answers create with this s3 error.
	CreateError *pb.CreateError
	// LoseCreateResponses makes that many creates take effect and then answer
	// UNAVAILABLE, as a response lost on the way back.
	LoseCreateResponses int
	// RemoveMessage, when set, answers removeBucket with this text.
	RemoveMessage string
	// CreateDelay holds every create that long before it answers, as a slow
	// server does; the caller's deadline still cuts it.
	CreateDelay time.Duration
	// OnCreate, when set, runs inside every create before it answers (a test
	// moves its clock there: the call took that long).
	OnCreate func()
	// CreateOutlivesCaller makes a create go on after its caller has gone, as
	// cloud-manager does: past OnCreate it waits for the caller's context to
	// end (a cancel, a deadline) and only then commits the bucket; the answer
	// reaches no one.
	CreateOutlivesCaller bool
	// HideNewFindAlls hides a bucket a create makes from that many following
	// findAll calls: the row is committed, the listing does not show it yet.
	HideNewFindAlls int
	// hidden counts the findAll calls left before a new bucket is listed.
	hidden map[string]int

	Creates  int
	FindAlls int
	Removes  int
	// LastScopes is the scope list of the last findAll call.
	LastScopes []*pb.FindAllRequest_SearchScope
}

// New returns an empty fake that completes a removal after one observation.
func New() *Server {
	return &Server{removing: map[string]int{}, hidden: map[string]int{}, RemovalPolls: 1}
}

// Prefix is the per-customer prefix the fake prepends to requested names.
func Prefix(login string) string {
	sum := sha256.Sum256([]byte(login))
	return hex.EncodeToString(sum[:])[:12]
}

// Seed inserts a bucket as-is.
func (s *Server) Seed(b *pb.Bucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneBucket(b)
	s.buckets = append(s.buckets, cp)
}

// Get returns a copy of the named bucket, or nil.
func (s *Server) Get(name string) *pb.Bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.find(name); b != nil {
		return cloneBucket(b)
	}
	return nil
}

// Update mutates the named bucket in place; false when it does not exist.
func (s *Server) Update(name string, fn func(*pb.Bucket)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.find(name)
	if b == nil {
		return false
	}
	fn(b)
	return true
}

// Counters returns (creates, findAlls, removes) under the lock.
func (s *Server) Counters() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Creates, s.FindAlls, s.Removes
}

// Buckets returns copies of all buckets in insertion order.
func (s *Server) Buckets() []*pb.Bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*pb.Bucket, 0, len(s.buckets))
	for _, b := range s.buckets {
		out = append(out, cloneBucket(b))
	}
	return out
}

func (s *Server) find(name string) *pb.Bucket {
	for _, b := range s.buckets {
		if b.GetName() == name {
			return b
		}
	}
	return nil
}

var suffixRe = regexp.MustCompile(`-([0-9]+)$`)

// uniqName mirrors getUniqBucketName: while the name exists in any status,
// append "-1" or increment a trailing "-N".
func (s *Server) uniqName(name string) string {
	for s.find(name) != nil {
		if m := suffixRe.FindStringSubmatchIndex(name); m != nil {
			n, _ := strconv.Atoi(name[m[2]:m[3]])
			name = name[:m[0]] + "-" + strconv.Itoa(n+1)
			continue
		}
		name += "-1"
	}
	return name
}

func (s *Server) Create(ctx context.Context, req *pb.CreateRequest) (*pb.CreateResponse, error) {
	s.mu.Lock()
	s.Creates++
	hang := s.HangCreate
	var injected error
	if len(s.CreateErrs) > 0 {
		injected, s.CreateErrs = s.CreateErrs[0], s.CreateErrs[1:]
	}
	delay, onCreate, outlive := s.CreateDelay, s.OnCreate, s.CreateOutlivesCaller
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	if onCreate != nil {
		onCreate()
	}
	if outlive {
		<-ctx.Done()
	}
	if injected != nil {
		return nil, injected
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CreateError != nil {
		return &pb.CreateResponse{Result: &pb.CreateResponse_S3Error{S3Error: s.CreateError}}, nil
	}
	params := req.GetS3Params()
	login := req.GetCustomerIdentifier()
	name := s.uniqName(strings.ToLower(Prefix(login) + "-" + params.GetBucketName()))
	s.buckets = append(s.buckets, &pb.Bucket{
		Name:      name,
		CustLogin: login,
		AccessKey: "AK-" + name,
		SecretKey: "SK-" + name,
		Fqdn:      name + ".s3.example.test",
		Status:    pb.Status_RUNNING,
		ManagedBy: params.GetManagedBy(),
		Public:    params.GetPublic(),
	})
	if s.HideNewFindAlls > 0 {
		s.hidden[name] = s.HideNewFindAlls
	}
	if s.LoseCreateResponses > 0 {
		s.LoseCreateResponses--
		return nil, status.Error(codes.Unavailable, "cmfake: create response lost")
	}
	return &pb.CreateResponse{Result: &pb.CreateResponse_ServiceInfo{
		ServiceInfo: &pb.Service{Id: fmt.Sprintf("svc-%d", len(s.buckets)), Slug: name},
	}}, nil
}

func (s *Server) FindAll(ctx context.Context, req *pb.FindAllRequest) (*pb.FindAllResponse, error) {
	s.mu.Lock()
	s.FindAlls++
	s.LastScopes = req.GetScope()
	hang := s.HangFindAll
	var injected error
	if len(s.FindAllErrs) > 0 {
		injected, s.FindAllErrs = s.FindAllErrs[0], s.FindAllErrs[1:]
	}
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if injected != nil {
		return nil, injected
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	resp := &pb.FindAllResponse{}
	for _, b := range s.buckets {
		if s.hidden[b.GetName()] > 0 {
			continue
		}
		if s.matches(b, req.GetScope()) {
			resp.Bucket = append(resp.Bucket, cloneBucket(b))
		}
	}
	for name, left := range s.hidden {
		if left <= 1 {
			delete(s.hidden, name)
			continue
		}
		s.hidden[name] = left - 1
	}
	// Asynchronous completion: each findAll is one observation of REMOVING.
	for name, left := range s.removing {
		left--
		if left <= 0 {
			if b := s.find(name); b != nil {
				b.Status = pb.Status_REMOVED
			}
			delete(s.removing, name)
			continue
		}
		s.removing[name] = left
	}
	return resp, nil
}

func (s *Server) matches(b *pb.Bucket, scopes []*pb.FindAllRequest_SearchScope) bool {
	if len(scopes) == 0 {
		return true
	}
	anyHit := false
	for _, sc := range scopes {
		hit := false
		switch c := sc.GetCondition().(type) {
		case *pb.FindAllRequest_SearchScope_ByCustomer:
			hit = contains(c.ByCustomer.GetLogin(), b.GetCustLogin())
		case *pb.FindAllRequest_SearchScope_ByBucket:
			hit = contains(c.ByBucket.GetName(), b.GetName())
		}
		if s.ScopesOR {
			anyHit = anyHit || hit
			continue
		}
		if !hit {
			return false
		}
	}
	if s.ScopesOR {
		return anyHit
	}
	return true
}

func (s *Server) RemoveBucket(ctx context.Context, req *pb.RemoveBucketRequest) (*pb.RemoveBucketResponse, error) {
	s.mu.Lock()
	s.Removes++
	hang := s.HangRemove
	s.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RemoveMessage != "" {
		return removeErr(s.RemoveMessage), nil
	}
	b := s.find(req.GetBucketName())
	switch {
	case b == nil:
		return removeErr("Not found"), nil
	case b.GetStatus() == pb.Status_REMOVED:
		return removeErr("Already removed"), nil
	}
	b.Status = pb.Status_REMOVING
	polls := s.RemovalPolls
	if polls < 1 {
		polls = 1
	}
	s.removing[b.GetName()] = polls
	return &pb.RemoveBucketResponse{}, nil
}

func removeErr(msg string) *pb.RemoveBucketResponse {
	return &pb.RemoveBucketResponse{Error: &pb.RemoveBucketResponse_Error{Message: msg}}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func cloneBucket(b *pb.Bucket) *pb.Bucket {
	return &pb.Bucket{
		Public:    b.GetPublic(),
		Name:      b.GetName(),
		CustLogin: b.GetCustLogin(),
		AccessKey: b.GetAccessKey(),
		SecretKey: b.GetSecretKey(),
		Fqdn:      b.GetFqdn(),
		Status:    b.GetStatus(),
		Cname:     b.GetCname(),
		ManagedBy: b.GetManagedBy(),
	}
}

// Listener serves the fake over an in-memory connection.
type Listener struct {
	srv *grpc.Server
	lis *bufconn.Listener
}

// Serve starts s on a bufconn listener.
func Serve(s *Server) *Listener {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterCloudServiceServer(srv, s)
	pb.RegisterCloudS3ServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	return &Listener{srv: srv, lis: lis}
}

// Dial returns a client connection to the in-memory server.
func (l *Listener) Dial() (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///cmfake",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return l.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// Stop stops the server immediately.
func (l *Listener) Stop() {
	l.srv.Stop()
}
