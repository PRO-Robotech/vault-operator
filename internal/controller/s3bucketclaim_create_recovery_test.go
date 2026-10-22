/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
)

// userExists is what cloud-manager answered on system-test 2026-10-22 (×55)
// to creates of names it had half-provisioned: the S3 user exists, the bucket
// does not.
var userExists = &pb.CreateError{Code: pb.CreateError_CODE_RESERVED, Message: "failed to create user: user already exists"}

// A create whose outcome the operator did not see (deadline, lost answer,
// "user already exists") must neither lose the bucket it made nor hammer
// cloud-manager with blind re-creates.
var _ = Describe("S3BucketClaim create recovery", func() {
	var (
		srv      *cmfake.Server
		recon    *S3BucketClaimReconciler
		newRecon func() *S3BucketClaimReconciler
		clk      time.Time
	)
	// createTimeout is the create deadline of the client the reconciler talks
	// through (the tests leave Options.CreateTimeout at its default).
	createTimeout := cloudmanager.DefaultOptions().CreateTimeout

	reconcileOnce := func(name string) reconcile.Result {
		res, err := reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		return res
	}
	serverName := func(name string) string {
		return cmfake.Prefix(s3Cust) + "-" + bucketBaseName(s3Cust, name)
	}
	creates := func() int {
		n, _, _ := srv.Counters()
		return n
	}

	BeforeEach(func() {
		clk = time.Now()
		srv = cmfake.New()
		l := cmfake.Serve(srv)
		DeferCleanup(l.Stop)
		conn, err := l.Dial()
		Expect(err).NotTo(HaveOccurred())
		buckets := cloudmanager.NewFromConn(conn, cloudmanager.Options{CallTimeout: 5 * time.Second, FindByBucket: true})
		vaults := &fakeSecretVaultFactory{Client: newFakeSecretVault()}
		// A new reconciler is what a restarted (or newly elected) operator
		// runs: the same cluster state, nothing kept in memory, a fresh backoff.
		newRecon = func() *S3BucketClaimReconciler {
			return &S3BucketClaimReconciler{
				Client:                 k8sClient,
				Scheme:                 k8sClient.Scheme(),
				Recorder:               record.NewFakeRecorder(200),
				VaultFactory:           vaults,
				Buckets:                buckets,
				DefaultConfigurationID: "s3_v1",
				Now:                    func() time.Time { return clk },
			}
		}
		recon = newRecon()
	})

	// echoing is a client whose status patches go through while trim edits the
	// pendingCreate of the answer, as a structural schema without a field
	// prunes it.
	echoing := func(trim func(*vaultv1alpha1.PendingBucketCreate)) client.Client {
		ww, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		return interceptor.NewClient(ww, interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
				if err := c.Status().Patch(ctx, obj, p); err != nil {
					return err
				}
				if s3, ok := obj.(*vaultv1alpha1.S3BucketClaim); ok && s3.Status.PendingCreate != nil {
					trim(s3.Status.PendingCreate)
				}
				return nil
			},
		})
	}

	// cutByRestart runs one pass whose create the operator's shutdown cuts:
	// the pass context is cancelled while the create is on the server, the
	// server finishes it anyway, and the pass's final status write goes with
	// the cancelled context. It returns the decision time as persisted.
	cutByRestart := func(name string) time.Time {
		pass, stop := context.WithCancel(ctx)
		defer stop()
		srv.CreateOutlivesCaller = true
		srv.OnCreate = func() {
			clk = clk.Add(5 * time.Second) // SIGTERM 5s into the call
			stop()
		}
		decided := clk
		_, err := recon.Reconcile(pass, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: name}})
		Expect(err).NotTo(HaveOccurred())
		Expect(creates()).To(Equal(1))
		// The server commits the bucket after the caller has gone.
		Eventually(srv.Buckets).Should(HaveLen(1))
		srv.CreateOutlivesCaller, srv.OnCreate = false, nil

		pending := getS3(name).Status.PendingCreate
		Expect(pending).NotTo(BeNil())
		// Fixture check: what survived is the marker written before the call;
		// nothing the pass decided after the call reached the API server.
		Expect(pending.Since.Time).To(BeTemporally("~", decided, time.Second))
		return pending.Since.Time
	}

	It("records the bucket its first create made, even when it became visible only during a later attempt", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-late")
		// Pass 1: the create takes effect, its answer is lost, and the listing
		// shows the new bucket only from the second findAll on.
		srv.LoseCreateResponses = 1
		srv.HideNewFindAlls = 1
		makeS3BucketClaim(ctx, "s3late", "s3-cfg-late")
		reconcileOnce("s3late")
		Expect(creates()).To(Equal(1))
		Expect(getS3("s3late").Status.PendingCreate).NotTo(BeNil())

		// Pass 2, after the grace: the lookup still misses the bucket, a second
		// create is issued and cloud-manager answers "user already exists".
		srv.CreateError = userExists
		clk = clk.Add(2 * time.Minute)
		reconcileOnce("s3late")

		// Pass 3: the bucket is listed; it is the first create's.
		clk = clk.Add(2 * time.Minute)
		reconcileOnce("s3late")

		got := getS3("s3late")
		Expect(got.Status.BucketName).To(Equal(serverName("s3late")))
		Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
		Expect(got.Status.PendingCreate).To(BeNil())
	})

	It("names a create rejected without a code and backs off instead of re-creating every minute", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-rej")
		srv.CreateError = userExists
		makeS3BucketClaim(ctx, "s3rej", "s3-cfg-rej")

		res := reconcileOnce("s3rej")
		got := getS3("s3rej")
		c := findCond(got.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)
		Expect(c).NotTo(BeNil())
		Expect(c.Reason).To(Equal("CreateRejected"))
		Expect(c.Message).To(ContainSubstring("CODE_RESERVED"))
		// Status carries no raw cloud-manager text.
		Expect(c.Message).NotTo(ContainSubstring("user already exists"))
		Expect(got.Status.PendingCreate).NotTo(BeNil())
		Expect(res.RequeueAfter).To(Equal(bucketBackoffBase))

		clk = clk.Add(2 * time.Minute)
		res = reconcileOnce("s3rej")
		Expect(creates()).To(Equal(2))
		Expect(res.RequeueAfter).To(Equal(2 * bucketBackoffBase))
	})

	It("counts the grace of an unanswered create from the end of the call, not from its start", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-slowcall")
		// The call runs 90s and ends without an answer; nothing is created.
		srv.CreateErrs = []error{status.Error(codes.DeadlineExceeded, "cmfake: no answer in time")}
		srv.OnCreate = func() { clk = clk.Add(90 * time.Second) }
		makeS3BucketClaim(ctx, "s3slowcall", "s3-cfg-slowcall")
		reconcileOnce("s3slowcall")
		Expect(creates()).To(Equal(1))

		// 130s after the decision, 40s after the call ended: the server may
		// still be finishing, so no second create yet.
		srv.OnCreate = nil
		clk = clk.Add(40 * time.Second)
		reconcileOnce("s3slowcall")
		Expect(creates()).To(Equal(1))
		Expect(condReason(getS3("s3slowcall").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("Locating"))
	})

	It("does not repeat a create cut by a restart before its deadline and the grace have passed since its decision", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-restart")
		makeS3BucketClaim(ctx, "s3restart", "s3-cfg-restart")
		// The bucket the cut create made is listed only from the third findAll
		// after it is committed on.
		srv.HideNewFindAlls = 2
		since := cutByRestart("s3restart")

		// The new leader: lease taken, the claim reconciled after the grace,
		// while the server may still be finishing the first create.
		recon = newRecon()
		clk = since.Add(bucketCreateGrace + time.Second)
		reconcileOnce("s3restart")
		Expect(creates()).To(Equal(1))
		Expect(condReason(getS3("s3restart").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("Locating"))

		clk = since.Add(createTimeout + bucketCreateGrace - time.Second)
		reconcileOnce("s3restart")
		Expect(creates()).To(Equal(1))
		Expect(condReason(getS3("s3restart").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("Locating"))

		// Twin: past the wait the bucket is listed and recorded as this
		// claim's, made by its only create.
		clk = since.Add(createTimeout + bucketCreateGrace + time.Second)
		reconcileOnce("s3restart")
		got := getS3("s3restart")
		Expect(creates()).To(Equal(1))
		Expect(got.Status.BucketName).To(Equal(serverName("s3restart")))
		Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
		Expect(got.Status.PendingCreate).To(BeNil())
		Expect(condReason(got.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("Created"))
	})

	It("creates again once the deadline and the grace have passed since the decision of a create cut by a restart", func() {
		// Twin of the probe above, one fact apart: the clock. The bucket is
		// still not listed, and past the wait a create is issued.
		makeHealthyVaultConfig(ctx, "s3-cfg-restart2")
		makeS3BucketClaim(ctx, "s3restart2", "s3-cfg-restart2")
		srv.HideNewFindAlls = 2
		since := cutByRestart("s3restart2")

		recon = newRecon()
		clk = since.Add(createTimeout + bucketCreateGrace + time.Second)
		reconcileOnce("s3restart2")
		Expect(creates()).To(Equal(2))
	})

	It("does not create when the API server drops status.pendingCreate.existingNames", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-prunednames")
		// An earlier bucket of this cluster is REMOVED: the snapshot of names
		// taken before the create is not empty.
		srv.Seed(&pb.Bucket{Name: serverName("s3prunednames"), CustLogin: s3Cust, Status: pb.Status_REMOVED})
		makeS3BucketClaim(ctx, "s3prunednames", "s3-cfg-prunednames")
		recon.Client = echoing(func(p *vaultv1alpha1.PendingBucketCreate) { p.ExistingNames = nil })
		reconcileOnce("s3prunednames")

		Expect(creates()).To(Equal(0))
		Expect(condReason(getS3("s3prunednames").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("StatusSchemaOutdated"))
	})

	It("does not create when the API server drops status.pendingCreate.requestedName", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-prunedreq")
		makeS3BucketClaim(ctx, "s3prunedreq", "s3-cfg-prunedreq")
		recon.Client = echoing(func(p *vaultv1alpha1.PendingBucketCreate) { p.RequestedName = "" })
		reconcileOnce("s3prunedreq")

		Expect(creates()).To(Equal(0))
		Expect(condReason(getS3("s3prunedreq").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("StatusSchemaOutdated"))
	})

	It("creates when the API server keeps the whole pendingCreate", func() {
		// Twin of the two probes above, one fact apart: nothing is pruned.
		makeHealthyVaultConfig(ctx, "s3-cfg-keptnames")
		srv.Seed(&pb.Bucket{Name: serverName("s3keptnames"), CustLogin: s3Cust, Status: pb.Status_REMOVED})
		makeS3BucketClaim(ctx, "s3keptnames", "s3-cfg-keptnames")
		recon.Client = echoing(func(*vaultv1alpha1.PendingBucketCreate) {})
		reconcileOnce("s3keptnames")

		Expect(creates()).To(Equal(1))
		Expect(condReason(getS3("s3keptnames").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("Created"))
	})

	It("does not create when the API server drops status.pendingCreate (CRD older than the image)", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-pruned")
		makeS3BucketClaim(ctx, "s3pruned", "s3-cfg-pruned")
		ww, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		// The patch goes through; the answer lacks the field, as a structural
		// schema without it prunes it.
		recon.Client = interceptor.NewClient(ww, interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
				if err := c.Status().Patch(ctx, obj, p); err != nil {
					return err
				}
				if s3, ok := obj.(*vaultv1alpha1.S3BucketClaim); ok {
					s3.Status.PendingCreate = nil
				}
				return nil
			},
		})
		_, err = recon.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "s3pruned"}})
		Expect(err).NotTo(HaveOccurred())

		Expect(creates()).To(Equal(0))
		Expect(condReason(getS3("s3pruned").Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("StatusSchemaOutdated"))
	})
})
