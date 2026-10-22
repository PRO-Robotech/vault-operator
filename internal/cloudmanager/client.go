/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package cloudmanager wraps the cloud-manager gRPC S3 surface: create a bucket,
// fetch its credentials, remove it.
//
// Server semantics this client relies on (read from the cloud-manager sources):
// findAll scopes are ANDed and values inside one scope are ORed; findAll also
// returns REMOVED rows; create suffixes a taken name with "-N" instead of
// failing; removeBucket answers with a free-text error only. The client does
// not trust the server-side search area: every findAll result is filtered here
// by exact name and owner, so a different server semantics can only make a
// lookup miss, never hand out another login's bucket.
package cloudmanager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

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
	// ErrForeignBucket: a bucket with the exact name exists but reports another
	// owner login.
	ErrForeignBucket = errors.New("cloud-manager: bucket owned by another login")
	// ErrAlreadyRemoved: removeBucket answered "Already removed" (status REMOVED).
	ErrAlreadyRemoved = errors.New("cloud-manager: bucket already removed")
	// ErrRemoveFailed: removeBucket answered a text outside the known vocabulary.
	ErrRemoveFailed = errors.New("cloud-manager: remove failed")
	// ErrCreateRejected: create answered an error code outside the mapped set,
	// CODE_RESERVED (no code) included. The server may have done part of the
	// work: on system-test it answered "failed to create user: user already
	// exists" for a name whose user it had made without the bucket.
	ErrCreateRejected = errors.New("cloud-manager: create rejected")
)

// CreateRejectedError is a create answered with an error code outside the
// mapped set. Code is the enum name (a closed set); Message is the server's
// free text, for the log only.
type CreateRejectedError struct {
	Code    string
	Message string
}

func (e *CreateRejectedError) Error() string {
	return fmt.Sprintf("%s [%s]: %s", ErrCreateRejected, e.Code, e.Message)
}

// Is makes errors.Is(err, ErrCreateRejected) hold.
func (e *CreateRejectedError) Is(target error) bool { return target == ErrCreateRejected }

// removeBucket answers outside of success; the vocabulary is closed.
const (
	removeMsgNotFound       = "Not found"
	removeMsgAlreadyRemoved = "Already removed"
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
	// FindByBucket returns the bucket with exactly this server name in any
	// status. ErrBucketNotFound when absent, ErrForeignBucket when it reports
	// another non-empty owner; an empty owner is returned as is.
	FindByBucket(ctx context.Context, custLogin, bucketName string) (*Bucket, error)
	// FindByRequested returns the live (not REMOVING/REMOVED) buckets of exactly
	// custLogin whose server name is "<hex>-<requestedName>", plus
	// "<hex>-<requestedName>-<N>" when allowSuffix, sorted by name length.
	FindByRequested(ctx context.Context, custLogin, requestedName string, allowSuffix bool) ([]*Bucket, error)
	// NamesByRequested returns the server names of exactly custLogin matching
	// "<hex>-<requestedName>" or "<hex>-<requestedName>-<N>" in any status
	// (REMOVED included): the names a create of requestedName cannot get.
	NamesByRequested(ctx context.Context, custLogin, requestedName string) ([]string, error)
	// Remove asks to remove the bucket. nil means accepted (REMOVING);
	// ErrAlreadyRemoved and ErrBucketNotFound are the two terminal answers.
	Remove(ctx context.Context, bucketName string) error
}

// Options tune the transport. Zero values pick the defaults below.
type Options struct {
	// CallTimeout bounds findAll and removeBucket (default 15s).
	CallTimeout time.Duration
	// CreateTimeout bounds create (default 2m). A create is not idempotent on
	// the server: cut by the client it still runs there, and a retry of the
	// same name may meet its half-made state. It is therefore kept above the
	// server's create latency rather than at the read deadline.
	CreateTimeout time.Duration
	// Keepalive is the gRPC client ping interval while an RPC is active; 0
	// disables pings (the server's ping policy is unknown, and an aggressive
	// ping rate gets the connection closed with GOAWAY).
	Keepalive time.Duration
	// FindByBucket queries a known name with a ByBucket scope; false keeps the
	// previous ByCustomer query (a bucket of another login is then invisible
	// rather than reported as foreign). Results are filtered on the client
	// either way.
	FindByBucket bool
	// FindRetries is the number of extra findAll attempts on UNAVAILABLE.
	FindRetries int
	// QPS caps calls per second: 0 means DefaultQPS, a negative value
	// disables the limit. Burst 0 means DefaultBurst.
	QPS   float64
	Burst int
}

const (
	defaultCallTimeout = 15 * time.Second
	// defaultCreateTimeout: on system-test 2026-10-22 creates cut at 15s
	// finished on the server within ~75s (bucket listed on the next pass);
	// the previous release had no create deadline at all.
	defaultCreateTimeout = 2 * time.Minute
	findRetryDelay       = 200 * time.Millisecond
)

// The default limit sits well above what the default two workers issue (a
// handful of calls per pass), so a default deployment is never throttled.
const (
	DefaultQPS   = 20
	DefaultBurst = 40
)

// DefaultOptions returns the production defaults.
func DefaultOptions() Options {
	return Options{CallTimeout: defaultCallTimeout, CreateTimeout: defaultCreateTimeout, FindByBucket: true, FindRetries: 1}
}

// Client talks to cloud-manager over gRPC.
type Client struct {
	conn    *grpc.ClientConn
	cloud   pb.CloudServiceClient
	s3      pb.CloudS3ServiceClient
	opts    Options
	limiter *rate.Limiter
}

var _ BucketAPI = (*Client)(nil)

// New dials cloud-manager with the default options.
func New(addr string) (*Client, error) {
	return NewWithOptions(addr, DefaultOptions())
}

// NewWithOptions dials cloud-manager (plaintext, as before: TLS is out of scope).
func NewWithOptions(addr string, opts Options) (*Client, error) {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if opts.Keepalive > 0 {
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                opts.Keepalive,
			Timeout:             opts.callTimeout(),
			PermitWithoutStream: false,
		}))
	}
	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial cloud-manager: %w", err)
	}
	return NewFromConn(conn, opts), nil
}

// NewFromConn wraps an existing connection.
func NewFromConn(conn *grpc.ClientConn, opts Options) *Client {
	return &Client{
		conn:    conn,
		cloud:   pb.NewCloudServiceClient(conn),
		s3:      pb.NewCloudS3ServiceClient(conn),
		opts:    opts,
		limiter: opts.limiter(),
	}
}

// limiter is nil (no limit) for a negative QPS.
func (o Options) limiter() *rate.Limiter {
	if o.QPS < 0 {
		return nil
	}
	qps, burst := o.QPS, o.Burst
	if qps == 0 {
		qps = DefaultQPS
	}
	if burst <= 0 {
		burst = DefaultBurst
	}
	return rate.NewLimiter(rate.Limit(qps), burst)
}

// wait takes a call slot from the limiter.
func (c *Client) wait(ctx context.Context) error {
	if c.limiter == nil {
		return nil
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("cloud-manager rate limit: %w", err)
	}
	return nil
}

func (o Options) callTimeout() time.Duration {
	if o.CallTimeout > 0 {
		return o.CallTimeout
	}
	return defaultCallTimeout
}

// createTimeout is how long one create may run (CreateTimeout or its default).
func (o Options) createTimeout() time.Duration {
	if o.CreateTimeout > 0 {
		return o.CreateTimeout
	}
	return defaultCreateTimeout
}

// CreateDeadline is the deadline of one create: CreateTimeout or its default.
// The reconciler waits for it before repeating a create in flight.
func (o Options) CreateDeadline() time.Duration { return o.createTimeout() }

// CheckReconcileTimeout refuses a reconcile deadline that a pass which
// creates cannot finish its cloud-manager calls within: two findAll calls
// (each with its retries) before the create, then the create itself. A
// create cut by the reconcile deadline goes on on the server unseen, so a
// process is not started with such a pair. 0 means no reconcile deadline;
// rate-limit waits and the Kubernetes calls of the pass are not counted.
func (o Options) CheckReconcileTimeout(reconcile time.Duration) error {
	if reconcile <= 0 {
		return nil
	}
	attempts := max(1, 1+o.FindRetries)
	findAll := time.Duration(attempts)*o.callTimeout() + time.Duration(attempts-1)*findRetryDelay
	need := o.createTimeout() + 2*findAll
	if need >= reconcile {
		return fmt.Errorf("reconcile timeout %s does not exceed the cloud-manager calls of a creating pass, %s "+
			"(create %s, two findAll calls of %d attempt(s) of %s)", reconcile, need, o.createTimeout(), attempts, o.callTimeout())
	}
	return nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Create(ctx context.Context, in CreateInput) (string, error) {
	if err := c.wait(ctx); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.createTimeout())
	defer cancel()
	start := time.Now()
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
	observe("Create", start, err)
	if err != nil {
		return "", fmt.Errorf("cloud-manager create: %w", err)
	}
	if s3err := resp.GetS3Error(); s3err != nil {
		return "", mapCreateError(s3err)
	}
	return resp.GetServiceInfo().GetSlug(), nil
}

func (c *Client) FindByBucket(ctx context.Context, custLogin, bucketName string) (*Bucket, error) {
	// ByBucket alone: names are unique server-wide, the row comes back
	// whoever owns it, and the owner is judged here. ANDed with ByCustomer a
	// bucket of another login would be indistinguishable from an absent one.
	scopes := []*pb.FindAllRequest_SearchScope{byCustomerScope(custLogin)}
	if c.opts.FindByBucket {
		scopes = []*pb.FindAllRequest_SearchScope{{Condition: &pb.FindAllRequest_SearchScope_ByBucket{
			ByBucket: &pb.FindAllRequest_SearchScope_ByBucketName{Name: []string{bucketName}},
		}}}
	}
	resp, err := c.findAll(ctx, scopes)
	if err != nil {
		return nil, err
	}
	var foreign bool
	for _, b := range resp.GetBucket() {
		if b.GetName() != bucketName {
			continue
		}
		if owner := b.GetCustLogin(); owner != "" && owner != custLogin {
			foreign = true
			continue
		}
		return toDomain(b), nil
	}
	if foreign {
		return nil, fmt.Errorf("%w: %q", ErrForeignBucket, bucketName)
	}
	return nil, ErrBucketNotFound
}

func (c *Client) FindByRequested(ctx context.Context, custLogin, requestedName string, allowSuffix bool) ([]*Bucket, error) {
	resp, err := c.findAll(ctx, []*pb.FindAllRequest_SearchScope{byCustomerScope(custLogin)})
	if err != nil {
		return nil, err
	}
	re := requestedNameRe(requestedName, allowSuffix)
	out := make([]*Bucket, 0, len(resp.GetBucket()))
	for _, b := range resp.GetBucket() {
		if b.GetCustLogin() != custLogin || !re.MatchString(b.GetName()) {
			continue
		}
		if st := b.GetStatus(); st == pb.Status_REMOVED || st == pb.Status_REMOVING {
			continue
		}
		out = append(out, toDomain(b))
	}
	sortByNameLength(out)
	return out, nil
}

func (c *Client) NamesByRequested(ctx context.Context, custLogin, requestedName string) ([]string, error) {
	resp, err := c.findAll(ctx, []*pb.FindAllRequest_SearchScope{byCustomerScope(custLogin)})
	if err != nil {
		return nil, err
	}
	re := requestedNameRe(requestedName, true)
	var out []string
	for _, b := range resp.GetBucket() {
		if b.GetCustLogin() == custLogin && re.MatchString(b.GetName()) {
			out = append(out, b.GetName())
		}
	}
	slices.Sort(out)
	return out, nil
}

// requestedNameRe matches the server-assigned names for a requested name: the
// server prepends "<hex>-" and, on a taken name, appends "-<N>".
func requestedNameRe(requestedName string, allowSuffix bool) *regexp.Regexp {
	expr := `^[0-9a-f]+-` + regexp.QuoteMeta(strings.ToLower(requestedName))
	if allowSuffix {
		expr += `(-[0-9]+)?`
	}
	return regexp.MustCompile(expr + `$`)
}

// sortByNameLength orders the shortest (unsuffixed) name first, then by name.
func sortByNameLength(bs []*Bucket) {
	slices.SortFunc(bs, func(a, b *Bucket) int {
		if d := len(a.Name) - len(b.Name); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
}

func byCustomerScope(custLogin string) *pb.FindAllRequest_SearchScope {
	return &pb.FindAllRequest_SearchScope{Condition: &pb.FindAllRequest_SearchScope_ByCustomer{
		ByCustomer: &pb.FindAllRequest_SearchScope_ByCustomerLogin{Login: []string{custLogin}},
	}}
}

// findAll is read-only, so it alone is retried, and only on UNAVAILABLE.
func (c *Client) findAll(ctx context.Context, scopes []*pb.FindAllRequest_SearchScope) (*pb.FindAllResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= c.opts.FindRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("cloud-manager findAll: %w", lastErr)
			case <-time.After(findRetryDelay):
			}
		}
		if err := c.wait(ctx); err != nil {
			return nil, err
		}
		callCtx, cancel := context.WithTimeout(ctx, c.opts.callTimeout())
		start := time.Now()
		resp, err := c.s3.FindAll(callCtx, &pb.FindAllRequest{Scope: scopes})
		observe("FindAll", start, err)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if status.Code(err) != codes.Unavailable {
			break
		}
	}
	return nil, fmt.Errorf("cloud-manager findAll: %w", lastErr)
}

func (c *Client) Remove(ctx context.Context, bucketName string) error {
	if err := c.wait(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.opts.callTimeout())
	defer cancel()
	start := time.Now()
	resp, err := c.s3.RemoveBucket(ctx, &pb.RemoveBucketRequest{BucketName: bucketName})
	observe("RemoveBucket", start, err)
	if err != nil {
		return fmt.Errorf("cloud-manager removeBucket: %w", err)
	}
	return classifyRemove(resp.GetError().GetMessage())
}

// classifyRemove maps the free-text answer onto the closed vocabulary; any
// other text is a failure and is counted, so a new server wording shows up.
func classifyRemove(msg string) error {
	switch msg {
	case "":
		return nil
	case removeMsgNotFound:
		return ErrBucketNotFound
	case removeMsgAlreadyRemoved:
		return ErrAlreadyRemoved
	default:
		removeUnknownResponseCounter.Inc()
		return fmt.Errorf("%w: %s", ErrRemoveFailed, msg)
	}
}

func managedByEnum(s string) pb.S3BucketManagedBy {
	if s == ManagedByCustomer {
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
		createRejectedCounter.WithLabelValues(e.GetCode().String()).Inc()
		return &CreateRejectedError{Code: e.GetCode().String(), Message: e.GetMessage()}
	}
}
