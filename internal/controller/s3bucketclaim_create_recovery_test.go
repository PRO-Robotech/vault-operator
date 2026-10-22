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
		srv   *cmfake.Server
		recon *S3BucketClaimReconciler
		clk   time.Time
	)

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
		recon = &S3BucketClaimReconciler{
			Client:                 k8sClient,
			Scheme:                 k8sClient.Scheme(),
			Recorder:               record.NewFakeRecorder(200),
			VaultFactory:           &fakeSecretVaultFactory{Client: newFakeSecretVault()},
			Buckets:                cloudmanager.NewFromConn(conn, cloudmanager.Options{CallTimeout: 5 * time.Second, FindByBucket: true}),
			DefaultConfigurationID: "s3_v1",
			Now:                    func() time.Time { return clk },
		}
	})

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
