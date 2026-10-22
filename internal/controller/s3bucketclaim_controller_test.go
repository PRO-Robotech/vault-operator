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
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const (
	s3TestDest = "s3"
	// s3Foreign is a value written into the claim's leaf by someone else.
	s3Foreign = "theirs"
	s3Cust    = "cust1"
)

func reconcileBucketOnce(r *S3BucketClaimReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
}

func newS3BucketClaim(name, configName string) *vaultv1alpha1.S3BucketClaim {
	return &vaultv1alpha1.S3BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.S3BucketClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: name},
			CustomerLogin:  s3Cust,
			Region:         "ru1",
			Bucket:         vaultv1alpha1.S3BucketSpec{ManagedBy: cloudmanager.ManagedBySystem, ConfigurationID: "s3_v1"},
			Vault:          vaultv1alpha1.S3VaultSpec{SecretsPrefix: "clusters/" + name, DestinationPath: s3TestDest},
			DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
		},
	}
}

func makeS3BucketClaim(ctx context.Context, name, configName string) {
	Expect(k8sClient.Create(ctx, newS3BucketClaim(name, configName))).To(Succeed())
}

func getS3(name string) *vaultv1alpha1.S3BucketClaim {
	got := &vaultv1alpha1.S3BucketClaim{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, got)).To(Succeed())
	return got
}

func s3Gone(name string) bool {
	err := k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, &vaultv1alpha1.S3BucketClaim{})
	return apierrors.IsNotFound(err)
}

func s3Leaf(fsv *fakeSecretVaultClient, name, dest string) map[string]any {
	return fsv.store["secret|clusters/"+name+"/"+dest]
}

func reasonOf(conds []metav1.Condition, condType string) string {
	if c := findCond(conds, condType); c != nil {
		return c.Reason
	}
	return ""
}

var _ = Describe("S3BucketClaim Controller", func() {
	const cust = s3Cust
	var (
		fakeSV *fakeSecretVaultClient
		srv    *cmfake.Server
		recon  *S3BucketClaimReconciler
	)

	reconcileN := func(name string, n int) reconcile.Result {
		var res reconcile.Result
		for i := 0; i < n; i++ {
			var err error
			res, err = reconcileBucketOnce(recon, name)
			Expect(err).NotTo(HaveOccurred())
		}
		return res
	}
	serverName := func(name string) string {
		return cmfake.Prefix(cust) + "-" + bucketBaseName(cust, name)
	}
	readyClaim := func(cfgName, name string) *vaultv1alpha1.S3BucketClaim {
		makeHealthyVaultConfig(ctx, cfgName)
		makeS3BucketClaim(ctx, name, cfgName)
		reconcileN(name, 2)
		got := getS3(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		return got
	}
	deleteClaim := func(name string) {
		Expect(k8sClient.Delete(ctx, getS3(name))).To(Succeed())
	}

	BeforeEach(func() {
		fakeSV = newFakeSecretVault()
		srv = cmfake.New()
		l := cmfake.Serve(srv)
		DeferCleanup(l.Stop)
		conn, err := l.Dial()
		Expect(err).NotTo(HaveOccurred())
		recon = &S3BucketClaimReconciler{
			Client:                 k8sClient,
			Scheme:                 k8sClient.Scheme(),
			Recorder:               record.NewFakeRecorder(200),
			VaultFactory:           &fakeSecretVaultFactory{Client: fakeSV},
			Buckets:                cloudmanager.NewFromConn(conn, cloudmanager.Options{CallTimeout: 5 * time.Second, FindByBucket: true}),
			DefaultConfigurationID: "s3_v1",
		}
	})

	Context("provisioning", func() {
		It("creates a bucket, records Created ownership and the written path, reaches Ready", func() {
			got := readyClaim("s3-cfg-ready", "s3ready")

			Expect(got.Status.BucketName).To(Equal(serverName("s3ready")))
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
			Expect(got.Status.PendingCreate).To(BeNil())
			Expect(got.Status.WrittenPath).To(Equal(s3TestDest))
			Expect(got.Status.KeysWrittenHash).To(BeEmpty())
			Expect(got.Status.BucketStatus).To(Equal(cloudmanager.StatusRunning))
			Expect(srv.Creates).To(Equal(1))

			leaf := s3Leaf(fakeSV, "s3ready", s3TestDest)
			Expect(leaf).NotTo(BeNil())
			Expect(leaf["bucketName"]).To(Equal(serverName("s3ready")))
			Expect(leaf["accessKey"]).To(HavePrefix("AK-"))
			Expect(leaf["secretKey"]).To(HavePrefix("SK-"))
			Expect(leaf["endpoint"]).To(Equal("s3.ru1.storage.beget.cloud"))
			Expect(leaf["region"]).To(Equal("ru1"))
			Expect(leaf["s3ForcePathStyle"]).To(Equal("true"))
		})

		It("in steady state does one findAll per pass and no create or Vault write", func() {
			readyClaim("s3-cfg-idem", "s3idem")
			writes := fakeSV.writes
			_, finds, _ := srv.Counters()
			reconcileN("s3idem", 3)
			creates, finds2, _ := srv.Counters()
			Expect(creates).To(Equal(1))
			Expect(fakeSV.writes).To(Equal(writes))
			Expect(finds2 - finds).To(Equal(3))
		})

		It("adopts a bucket of its own login found before create, and does not create", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-adopt")
			srv.Seed(&pb.Bucket{Name: serverName("s3adopt"), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			makeS3BucketClaim(ctx, "s3adopt", "s3-cfg-adopt")
			reconcileN("s3adopt", 2)

			got := getS3("s3adopt")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(got.Status.BucketName).To(Equal(serverName("s3adopt")))
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipAdopted))
			Expect(srv.Creates).To(Equal(0))
		})

		It("does not adopt a same-named bucket of another login", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-foreignname")
			srv.Seed(&pb.Bucket{Name: serverName("s3foreignname"), CustLogin: "other", Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			makeS3BucketClaim(ctx, "s3foreignname", "s3-cfg-foreignname")
			reconcileN("s3foreignname", 2)

			got := getS3("s3foreignname")
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
			Expect(got.Status.BucketName).To(Equal(serverName("s3foreignname") + "-1"))
			Expect(srv.Creates).To(Equal(1))
		})

		It("survives a lost status patch after create without creating a second bucket", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-crash")
			makeS3BucketClaim(ctx, "s3crash", "s3-cfg-crash")

			// The first pass loses every status patch that would record the name.
			ww, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
			Expect(err).NotTo(HaveOccurred())
			crashing := &S3BucketClaimReconciler{
				Scheme: recon.Scheme, Recorder: recon.Recorder, VaultFactory: recon.VaultFactory,
				Buckets: recon.Buckets, DefaultConfigurationID: recon.DefaultConfigurationID,
			}
			crashing.Client = interceptor.NewClient(ww, interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, p client.Patch, opts ...client.SubResourcePatchOption) error {
					if s3, ok := obj.(*vaultv1alpha1.S3BucketClaim); ok && s3.Status.BucketName != "" {
						return errors.New("injected: status patch lost")
					}
					return c.Status().Patch(ctx, obj, p)
				},
			})
			_, _ = crashing.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "s3crash"}})
			Expect(srv.Creates).To(Equal(1))
			Expect(getS3("s3crash").Status.BucketName).To(BeEmpty())
			Expect(getS3("s3crash").Status.PendingCreate).NotTo(BeNil())

			reconcileN("s3crash", 2)
			got := getS3("s3crash")
			Expect(srv.Creates).To(Equal(1))
			Expect(got.Status.BucketName).To(Equal(serverName("s3crash")))
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
			Expect(got.Status.PendingCreate).To(BeNil())
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		})

		It("adopts an explicitly named bucket and never creates", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-named")
			srv.Seed(&pb.Bucket{Name: "ffff00-shared-bucket", CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			c := newS3BucketClaim("s3named", "s3-cfg-named")
			c.Spec.Bucket.Name = "ffff00-shared-bucket"
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			reconcileN("s3named", 2)

			got := getS3("s3named")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(got.Status.BucketName).To(Equal("ffff00-shared-bucket"))
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipAdopted))
			Expect(srv.Creates).To(Equal(0))
		})

		It("refuses an explicitly named bucket of another login, and retries later", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-namedforeign")
			srv.Seed(&pb.Bucket{Name: "ffff00-foreign-bucket", CustLogin: "other", Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			c := newS3BucketClaim("s3namedforeign", "s3-cfg-namedforeign")
			c.Spec.Bucket.Name = "ffff00-foreign-bucket"
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			res := reconcileN("s3namedforeign", 2)

			got := getS3("s3namedforeign")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
			Expect(reasonOf(got.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("ForeignBucket"))
			Expect(got.Status.BucketName).To(BeEmpty())
			Expect(res.RequeueAfter).To(Equal(bucketRequeueSpecError))
			Expect(srv.Creates).To(Equal(0))
		})

		It("fails a missing s3 configuration as a spec error that is retried", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-cnf")
			srv.CreateError = &pb.CreateError{Code: pb.CreateError_CONFIGURATION_NOT_FOUND, Message: "nope"}
			makeS3BucketClaim(ctx, "s3cnf", "s3-cfg-cnf")
			res := reconcileN("s3cnf", 2)

			got := getS3("s3cnf")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
			Expect(reasonOf(got.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(Equal("ConfigurationMissing"))
			Expect(got.Status.PendingCreate).To(BeNil())
			Expect(res.RequeueAfter).To(Equal(bucketRequeueSpecError))
		})

		It("loses the younger of two claims on the same (login, cluster) without creating for it", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-dup")
			makeS3BucketClaim(ctx, "s3dupa", "s3-cfg-dup")
			time.Sleep(1100 * time.Millisecond) // creationTimestamp has a one-second resolution
			b := newS3BucketClaim("s3dupb", "s3-cfg-dup")
			b.Spec.ClusterRef.Name = "s3dupa"
			b.Spec.Vault.SecretsPrefix = "clusters/s3dupb"
			Expect(k8sClient.Create(ctx, b)).To(Succeed())

			reconcileN("s3dupb", 2)
			reconcileN("s3dupa", 2)
			Expect(getS3("s3dupa").Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			got := getS3("s3dupb")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
			Expect(reasonOf(got.Status.Conditions, vaultv1alpha1.ConditionReady)).To(Equal("Conflict"))
			Expect(srv.Creates).To(Equal(1))
		})
		It("does not take a neighbour cluster's \"<name>-N\" bucket while recovering a create", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-nbr")
			// The neighbour claim's cluster is "s3nbr-1": its bucket looks like a
			// suffixed bucket of "s3nbr".
			nb := newS3BucketClaim("s3nbrb", "s3-cfg-nbr")
			nb.Spec.ClusterRef.Name = "s3nbr-1"
			Expect(k8sClient.Create(ctx, nb)).To(Succeed())
			srv.Seed(&pb.Bucket{Name: serverName("s3nbr-1"), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})

			makeS3BucketClaim(ctx, "s3nbr", "s3-cfg-nbr")
			got := getS3("s3nbr")
			got.Finalizers = []string{vaultv1alpha1.S3BucketClaimFinalizer}
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			// A create was in flight and lost: only the marker is recorded.
			got = getS3("s3nbr")
			got.Status.PendingCreate = &vaultv1alpha1.PendingBucketCreate{
				RequestedName: bucketBaseName(cust, "s3nbr"), Since: metav1.NewTime(time.Now().Add(-time.Hour)),
			}
			Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())

			reconcileN("s3nbr", 2)
			Expect(getS3("s3nbr").Status.BucketName).To(Equal(serverName("s3nbr")))
		})

		It("lets the older of two duplicate claims adopt its existing bucket", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-dupadopt")
			srv.Seed(&pb.Bucket{Name: serverName("s3dupadopt"), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			makeS3BucketClaim(ctx, "s3dupadopt", "s3-cfg-dupadopt")
			time.Sleep(1100 * time.Millisecond) // creationTimestamp has a one-second resolution
			b := newS3BucketClaim("s3dupadoptb", "s3-cfg-dupadopt")
			b.Spec.ClusterRef.Name = "s3dupadopt"
			b.Spec.Vault.SecretsPrefix = "clusters/s3dupadoptb"
			Expect(k8sClient.Create(ctx, b)).To(Succeed())

			reconcileN("s3dupadopt", 2)
			got := getS3("s3dupadopt")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(got.Status.BucketName).To(Equal(serverName("s3dupadopt")))
			Expect(srv.Creates).To(Equal(0))
		})
	})

	Context("state errors", func() {
		It("leaves Failed on its own: STOPPED backs off, RUNNING brings it back to Ready", func() {
			got := readyClaim("s3-cfg-stopped", "s3stopped")
			srv.Update(got.Status.BucketName, func(b *pb.Bucket) { b.Status = pb.Status_STOPPED })
			res := reconcileN("s3stopped", 1)
			Expect(getS3("s3stopped").Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
			Expect(res.RequeueAfter).To(Equal(bucketBackoffBase))
			res = reconcileN("s3stopped", 1)
			Expect(res.RequeueAfter).To(Equal(2 * bucketBackoffBase))

			srv.Update(got.Status.BucketName, func(b *pb.Bucket) { b.Status = pb.Status_RUNNING })
			res = reconcileN("s3stopped", 1)
			Expect(getS3("s3stopped").Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(res.RequeueAfter).To(Equal(bucketRequeueDriftRecheck))
		})
	})

	Context("Vault keys", func() {
		It("restores a key deleted outside the operator on the next pass", func() {
			readyClaim("s3-cfg-repair", "s3repair")
			delete(fakeSV.store["secret|clusters/s3repair/s3"], "secretKey")
			reconcileN("s3repair", 1)
			Expect(s3Leaf(fakeSV, "s3repair", s3TestDest)["secretKey"]).To(HavePrefix("SK-"))
		})

		It("keeps a sibling key that another writer adds between read and write", func() {
			readyClaim("s3-cfg-race", "s3race")
			delete(fakeSV.store["secret|clusters/s3race/s3"], "accessKey")
			injected := false
			fakeSV.beforeCASWrite = func(mount, path string) {
				if injected {
					return
				}
				injected = true
				d := cloneData(fakeSV.store[mount+"|"+path])
				d["registry"] = s3Foreign
				fakeSV.seed(mount, path, d)
			}
			reconcileN("s3race", 2)
			leaf := s3Leaf(fakeSV, "s3race", s3TestDest)
			Expect(leaf["registry"]).To(Equal(s3Foreign))
			Expect(leaf["accessKey"]).To(HavePrefix("AK-"))
		})

		It("moves its keys on a destinationPath change and leaves a foreign value in place", func() {
			got := readyClaim("s3-cfg-move", "s3move")
			fakeSV.store["secret|clusters/s3move/s3"]["registry"] = s3Foreign

			got.Spec.Vault.DestinationPath = "backup/s3"
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			reconcileN("s3move", 1)

			Expect(s3Leaf(fakeSV, "s3move", "backup/s3")["accessKey"]).To(HavePrefix("AK-"))
			old := s3Leaf(fakeSV, "s3move", s3TestDest)
			Expect(old).To(Equal(map[string]any{"registry": s3Foreign}))
			Expect(getS3("s3move").Status.WrittenPath).To(Equal("backup/s3"))
		})

		It("does not remove keys at the old path that hold another bucket's name", func() {
			got := readyClaim("s3-cfg-moveforeign", "s3moveforeign")
			fakeSV.store["secret|clusters/s3moveforeign/s3"]["bucketName"] = "someone-else"

			got.Spec.Vault.DestinationPath = "backup/s3"
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			reconcileN("s3moveforeign", 1)

			old := s3Leaf(fakeSV, "s3moveforeign", s3TestDest)
			Expect(old["bucketName"]).To(Equal("someone-else"))
			Expect(old["accessKey"]).To(HavePrefix("AK-"))
		})
	})

	Context("deletion with Purge", func() {
		It("removes its Created bucket, waits for REMOVED, then removes only its own keys", func() {
			readyClaim("s3-cfg-purge", "s3purge")
			fakeSV.store["secret|clusters/s3purge/s3"]["registry"] = s3Foreign
			deleteClaim("s3purge")

			reconcileN("s3purge", 1) // remove requested: REMOVING
			Expect(srv.Removes).To(Equal(1))
			Expect(s3Gone("s3purge")).To(BeFalse())
			Expect(s3Leaf(fakeSV, "s3purge", s3TestDest)["accessKey"]).NotTo(BeNil())

			reconcileN("s3purge", 1) // still REMOVING: finalizer held, no second remove
			Expect(srv.Removes).To(Equal(1))
			Expect(s3Gone("s3purge")).To(BeFalse())

			reconcileN("s3purge", 1) // REMOVED
			Expect(s3Gone("s3purge")).To(BeTrue())
			Expect(s3Leaf(fakeSV, "s3purge", s3TestDest)).To(Equal(map[string]any{"registry": s3Foreign}))
		})

		It("deletes the KV leaf when only its own keys were there", func() {
			readyClaim("s3-cfg-purgeleaf", "s3purgeleaf")
			deleteClaim("s3purgeleaf")
			reconcileN("s3purgeleaf", 3)
			Expect(s3Gone("s3purgeleaf")).To(BeTrue())
			Expect(s3Leaf(fakeSV, "s3purgeleaf", s3TestDest)).To(BeNil())
		})

		It("removes no bucket when status.bucketName is empty", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-nobucket")
			srv.CreateError = &pb.CreateError{Code: pb.CreateError_INVALID_BUCKET_NAME, Message: "bad"}
			srv.Seed(&pb.Bucket{Name: "beefbeef-unrelated", CustLogin: cust, Status: pb.Status_RUNNING})
			makeS3BucketClaim(ctx, "s3nobucket", "s3-cfg-nobucket")
			reconcileN("s3nobucket", 2)
			Expect(getS3("s3nobucket").Status.BucketName).To(BeEmpty())

			deleteClaim("s3nobucket")
			reconcileN("s3nobucket", 1)
			Expect(srv.Removes).To(Equal(0))
			Expect(s3Gone("s3nobucket")).To(BeTrue())
		})

		It("never falls back to the requested name when the recorded bucket is gone", func() {
			got := readyClaim("s3-cfg-nofallback", "s3nofallback")
			got.Status.BucketName = "abcdef-recorded-elsewhere"
			Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())
			deleteClaim("s3nofallback")
			reconcileN("s3nofallback", 1)
			Expect(srv.Removes).To(Equal(0))
			Expect(srv.Get(serverName("s3nofallback")).GetStatus()).To(Equal(pb.Status_RUNNING))
		})

		DescribeTable("blocks deletion of a bucket that is not provably its own",
			func(cfgName, name string, mutate func(b *pb.Bucket)) {
				got := readyClaim(cfgName, name)
				srv.Update(got.Status.BucketName, mutate)
				deleteClaim(name)
				reconcileN(name, 2)

				Expect(srv.Removes).To(Equal(0))
				Expect(s3Gone(name)).To(BeFalse())
				left := getS3(name)
				Expect(left.Status.Phase).To(Equal(vaultv1alpha1.PhaseDeleting))
				Expect(reasonOf(left.Status.Conditions, vaultv1alpha1.ConditionReady)).To(Equal("DeletionBlocked"))
				Expect(s3Leaf(fakeSV, name, s3TestDest)["accessKey"]).NotTo(BeNil())
			},
			Entry("another login", "s3-cfg-blk-login", "s3blklogin", func(b *pb.Bucket) { b.CustLogin = "other" }),
			Entry("an empty owner", "s3-cfg-blk-empty", "s3blkempty", func(b *pb.Bucket) { b.CustLogin = "" }),
			Entry("another managedBy", "s3-cfg-blk-mb", "s3blkmb", func(b *pb.Bucket) { b.ManagedBy = pb.S3BucketManagedBy_CUSTOMER }),
		)

		It("blocks an Adopted bucket until purgeAdopted is set", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-adoptpurge")
			srv.Seed(&pb.Bucket{Name: serverName("s3adoptpurge"), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			makeS3BucketClaim(ctx, "s3adoptpurge", "s3-cfg-adoptpurge")
			reconcileN("s3adoptpurge", 2)
			deleteClaim("s3adoptpurge")
			reconcileN("s3adoptpurge", 1)
			Expect(srv.Removes).To(Equal(0))
			Expect(reasonOf(getS3("s3adoptpurge").Status.Conditions, vaultv1alpha1.ConditionReady)).To(Equal("DeletionBlocked"))

			got := getS3("s3adoptpurge")
			got.Spec.Bucket.PurgeAdopted = true
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			reconcileN("s3adoptpurge", 3)
			Expect(srv.Removes).To(Equal(1))
			Expect(s3Gone("s3adoptpurge")).To(BeTrue())
		})

		It("treats Already removed as done", func() {
			readyClaim("s3-cfg-already", "s3already")
			srv.RemoveMessage = "Already removed"
			deleteClaim("s3already")
			reconcileN("s3already", 1)
			Expect(s3Gone("s3already")).To(BeTrue())
		})

		It("holds the finalizer with DeletionStuck while the bucket is in ERROR", func() {
			got := readyClaim("s3-cfg-err", "s3err")
			srv.Update(got.Status.BucketName, func(b *pb.Bucket) { b.Status = pb.Status_ERROR })
			deleteClaim("s3err")
			res := reconcileN("s3err", 1)
			Expect(srv.Removes).To(Equal(0))
			Expect(s3Gone("s3err")).To(BeFalse())
			Expect(reasonOf(getS3("s3err").Status.Conditions, vaultv1alpha1.ConditionReady)).To(Equal("DeletionStuck"))
			Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		})
	})

	Context("claims written by the previous release", func() {
		legacyClaim := func(cfgName, name, reason string) {
			makeHealthyVaultConfig(ctx, cfgName)
			srv.Seed(&pb.Bucket{Name: serverName(name), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-old", SecretKey: "SK-old"})
			makeS3BucketClaim(ctx, name, cfgName)
			got := getS3(name)
			got.Finalizers = []string{vaultv1alpha1.S3BucketClaimFinalizer}
			Expect(k8sClient.Update(ctx, got)).To(Succeed())
			got = getS3(name)
			got.Status = vaultv1alpha1.S3BucketClaimStatus{
				ObservedGeneration: got.Generation,
				Phase:              vaultv1alpha1.PhaseReady,
				BucketName:         serverName(name),
				BucketStatus:       cloudmanager.StatusRunning,
				Endpoint:           "s3.ru1.storage.beget.cloud",
				KeysWrittenHash:    "0123abcd",
				Conditions: []metav1.Condition{{
					Type: vaultv1alpha1.ConditionBucketProvisioned, Status: metav1.ConditionTrue, Reason: reason,
					Message: "bucket create accepted", LastTransitionTime: metav1.Now(), ObservedGeneration: got.Generation,
				}},
			}
			Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())
			fakeSV.seed("secret", "clusters/"+name+"/s3", map[string]any{
				"accessKey": "AK-old", "secretKey": "SK-old", "bucketName": serverName(name),
				"endpoint": "s3.ru1.storage.beget.cloud", "region": "ru1", "s3ForcePathStyle": "true",
			})
		}

		It("keeps Vault byte-for-byte, wipes the hash and backfills ownership and path", func() {
			legacyClaim("s3-cfg-legacy", "s3legacy", "Created")
			version := fakeSV.versions["secret|clusters/s3legacy/s3"]
			reconcileN("s3legacy", 3)

			got := getS3("s3legacy")
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(got.Status.KeysWrittenHash).To(BeEmpty())
			Expect(got.Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipCreated))
			Expect(got.Status.WrittenPath).To(Equal(s3TestDest))
			Expect(fakeSV.versions["secret|clusters/s3legacy/s3"]).To(Equal(version))
			Expect(fakeSV.writes).To(Equal(0))
			Expect(srv.Creates).To(Equal(0))

			deleteClaim("s3legacy")
			reconcileN("s3legacy", 3)
			Expect(srv.Removes).To(Equal(1))
			Expect(s3Gone("s3legacy")).To(BeTrue())
		})

		It("reads a legacy reason other than Created as Adopted", func() {
			legacyClaim("s3-cfg-legacyexists", "s3legacyexists", "Exists")
			reconcileN("s3legacyexists", 1)
			Expect(getS3("s3legacyexists").Status.BucketOwnership).To(Equal(vaultv1alpha1.BucketOwnershipAdopted))
			deleteClaim("s3legacyexists")
			reconcileN("s3legacyexists", 1)
			Expect(srv.Removes).To(Equal(0))
		})

		It("self-heals a status holding the requested (pre-prefix) name", func() {
			makeHealthyVaultConfig(ctx, "s3-cfg-heal")
			srv.Seed(&pb.Bucket{Name: serverName("s3heal"), CustLogin: cust, Status: pb.Status_RUNNING, AccessKey: "AK-x", SecretKey: "SK-x"})
			makeS3BucketClaim(ctx, "s3heal", "s3-cfg-heal")
			got := getS3("s3heal")
			got.Status.BucketName = bucketBaseName(cust, "s3heal")
			got.Status.Conditions = []metav1.Condition{{
				Type: vaultv1alpha1.ConditionBucketProvisioned, Status: metav1.ConditionTrue, Reason: "Created",
				Message: "x", LastTransitionTime: metav1.Now(),
			}}
			Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())

			reconcileN("s3heal", 2)
			got = getS3("s3heal")
			Expect(got.Status.BucketName).To(Equal(serverName("s3heal")))
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(srv.Creates).To(Equal(0))
		})
	})

	Context("schema", func() {
		It("rejects an absolute or escaping destinationPath and accepts a relative one", func() {
			for _, p := range []string{"/abs", "a/../b", ".."} {
				c := newS3BucketClaim("s3celbad", "x")
				c.Spec.Vault.DestinationPath = p
				Expect(k8sClient.Create(ctx, c)).NotTo(Succeed(), "destinationPath %q", p)
			}
			c := newS3BucketClaim("s3celok", "x")
			c.Spec.Vault.DestinationPath = "apps/registry"
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
		})

		It("keeps spec.bucket.name immutable", func() {
			c := newS3BucketClaim("s3celname", "x")
			c.Spec.Bucket.Name = "abc-one"
			Expect(k8sClient.Create(ctx, c)).To(Succeed())
			got := getS3("s3celname")
			got.Spec.Bucket.Name = "abc-two"
			Expect(k8sClient.Update(ctx, got)).NotTo(Succeed())
			got = getS3("s3celname")
			got.Spec.Bucket.Name = ""
			Expect(k8sClient.Update(ctx, got)).NotTo(Succeed())

			// Twin: a claim created without a name cannot get one later either.
			d := newS3BucketClaim("s3celnoname", "x")
			Expect(k8sClient.Create(ctx, d)).To(Succeed())
			gd := getS3("s3celnoname")
			gd.Spec.Bucket.Name = "abc-late"
			Expect(k8sClient.Update(ctx, gd)).NotTo(Succeed())
			gd = getS3("s3celnoname")
			gd.Spec.Bucket.PurgeAdopted = true
			Expect(k8sClient.Update(ctx, gd)).To(Succeed())
		})
	})
})

func findCond(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
