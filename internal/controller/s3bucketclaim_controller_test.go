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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

func reconcileBucketOnce(r *S3BucketClaimReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
}

func makeS3BucketClaim(ctx context.Context, name, configName, custLogin string) {
	claim := &vaultv1alpha1.S3BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.S3BucketClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: name},
			CustomerLogin:  custLogin,
			Region:         "ru1",
			Bucket:         vaultv1alpha1.S3BucketSpec{ManagedBy: cloudmanager.ManagedBySystem, ConfigurationID: "s3_v1"},
			Vault:          vaultv1alpha1.S3VaultSpec{SecretsPrefix: "clusters/" + name, DestinationPath: defaultS3DestinationPath},
			DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
		},
	}
	Expect(k8sClient.Create(ctx, claim)).To(Succeed())
}

var _ = Describe("S3BucketClaim Controller", func() {
	const ns = "default"
	var (
		fakeSV   *fakeSecretVaultClient
		buckets  *cloudmanager.FakeBucketAPI
		recon    *S3BucketClaimReconciler
		custName = "cust1"
	)

	BeforeEach(func() {
		fakeSV = newFakeSecretVault()
		buckets = cloudmanager.NewFakeBucketAPI()
		recon = &S3BucketClaimReconciler{
			Client:                 k8sClient,
			Scheme:                 k8sClient.Scheme(),
			Recorder:               record.NewFakeRecorder(50),
			VaultFactory:           &fakeSecretVaultFactory{Client: fakeSV},
			Buckets:                buckets,
			DefaultConfigurationID: "s3_v1",
		}
	})

	It("creates a bucket and writes credentials to Vault, reaching Ready", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-ready")
		makeS3BucketClaim(ctx, "s3ready", "s3-cfg-ready", custName)

		// First reconcile adds the finalizer (returns early on Update).
		_, err := reconcileBucketOnce(recon, "s3ready")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3ready")
		Expect(err).NotTo(HaveOccurred())

		realName := cloudmanager.FakePrefix + bucketBaseName(custName, "s3ready")
		got := &vaultv1alpha1.S3BucketClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3ready"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		// The stored/used name is the server-assigned real name, not the requested one.
		Expect(got.Status.BucketName).To(Equal(realName))
		Expect(got.Status.BucketStatus).To(Equal(cloudmanager.StatusRunning))
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionBucketRunning)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionKeysWritten)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReady)).To(BeTrue())
		Expect(buckets.Creates).To(Equal(1))

		vaultData := fakeSV.store["secret|clusters/s3ready/backup/s3"]
		Expect(vaultData).NotTo(BeNil())
		Expect(vaultData["bucketName"]).To(Equal(realName))
		Expect(vaultData["accessKey"]).To(HavePrefix("AK-"))
		Expect(vaultData["secretKey"]).To(HavePrefix("SK-"))
		Expect(vaultData["endpoint"]).To(Equal("https://s3.ru1.storage.beget.cloud"))
		Expect(vaultData["s3ForcePathStyle"]).To(Equal("true"))
	})

	It("is idempotent: a second reconcile does not re-create or re-write", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-idem")
		makeS3BucketClaim(ctx, "s3idem", "s3-cfg-idem", custName)

		for i := 0; i < 3; i++ {
			_, err := reconcileBucketOnce(recon, "s3idem")
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(buckets.Creates).To(Equal(1))
		Expect(fakeSV.writes).To(Equal(1))
	})

	It("fails terminally when the s3 configuration is missing", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-cnf")
		buckets.CreateHook = func(context.Context, cloudmanager.CreateInput) (string, error) {
			return "", cloudmanager.ErrConfigurationNotFound
		}
		makeS3BucketClaim(ctx, "s3cnf", "s3-cfg-cnf", custName)

		_, err := reconcileBucketOnce(recon, "s3cnf")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3cnf")
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.S3BucketClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3cnf"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		cond := findCond(got.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("ConfigurationMissing"))
	})

	It("adopts an existing bucket on AlreadyExists (crash between create and status write)", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-adopt")
		requested := bucketBaseName(custName, "s3adopt")
		realName := "c942bd41757d-" + requested
		buckets.Seed(cloudmanager.Bucket{
			Name: realName, CustLogin: custName, Status: cloudmanager.StatusRunning,
			AccessKey: "AK-x", SecretKey: "SK-x",
		})
		buckets.CreateHook = func(context.Context, cloudmanager.CreateInput) (string, error) {
			return "", cloudmanager.ErrBucketNameAlreadyExists
		}
		makeS3BucketClaim(ctx, "s3adopt", "s3-cfg-adopt", custName)

		_, err := reconcileBucketOnce(recon, "s3adopt")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3adopt")
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.S3BucketClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3adopt"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(got.Status.BucketName).To(Equal(realName))
	})

	It("self-heals a claim whose status holds the requested (pre-fix) name", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-heal")
		requested := bucketBaseName(custName, "s3heal")
		realName := "c942bd41757d-" + requested
		// Bucket already exists under the real (prefixed) name.
		buckets.Seed(cloudmanager.Bucket{
			Name: realName, CustLogin: custName, Status: cloudmanager.StatusRunning,
			AccessKey: "AK-x", SecretKey: "SK-x",
		})
		makeS3BucketClaim(ctx, "s3heal", "s3-cfg-heal", custName)

		// Simulate the stuck state: status.BucketName holds the requested name.
		got := &vaultv1alpha1.S3BucketClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3heal"}, got)).To(Succeed())
		got.Status.BucketName = requested
		Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())

		_, err := reconcileBucketOnce(recon, "s3heal")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3heal")
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3heal"}, got)).To(Succeed())
		Expect(got.Status.BucketName).To(Equal(realName))
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(buckets.Creates).To(Equal(0))
	})

	It("purges the bucket and Vault path on deletion", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-purge")
		makeS3BucketClaim(ctx, "s3purge", "s3-cfg-purge", custName)

		_, err := reconcileBucketOnce(recon, "s3purge")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3purge")
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeSV.store["secret|clusters/s3purge/backup/s3"]).NotTo(BeNil())

		got := &vaultv1alpha1.S3BucketClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3purge"}, got)).To(Succeed())
		Expect(k8sClient.Delete(ctx, got)).To(Succeed())

		_, err = reconcileBucketOnce(recon, "s3purge")
		Expect(err).NotTo(HaveOccurred())

		Expect(buckets.Removes).To(Equal(1))
		Expect(fakeSV.store["secret|clusters/s3purge/backup/s3"]).To(BeNil())

		err = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "s3purge"}, &vaultv1alpha1.S3BucketClaim{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
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
