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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider"
	"github.com/PRO-Robotech/vault-operator/internal/bucketprovider/beget"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

const testYandexProfile = "system-backups"

func reconcileBucketOnce(r *S3BucketClaimReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
}

func makeS3BucketClaim(ctx context.Context, name, configName, custLogin string) *vaultv1alpha1.S3BucketClaim {
	claim := newS3BucketClaim(name, configName, custLogin)
	Expect(k8sClient.Create(ctx, claim)).To(Succeed())
	return claim
}

func newS3BucketClaim(name, configName, custLogin string) *vaultv1alpha1.S3BucketClaim {
	return &vaultv1alpha1.S3BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.S3BucketClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: name},
			CustomerLogin:  custLogin,
			Region:         "ru1",
			Bucket:         vaultv1alpha1.S3BucketSpec{ManagedBy: vaultv1alpha1.S3ManagedBySystem, ConfigurationID: "s3_v1"},
			Vault:          vaultv1alpha1.S3VaultSpec{SecretsPrefix: "clusters/" + name, DestinationPath: defaultS3DestinationPath},
			DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
		},
	}
}

var _ = Describe("S3BucketClaim provider validation", func() {
	DescribeTable("validates provider and profile on create",
		func(name, provider, profile string, valid bool) {
			claim := newS3BucketClaim(name, "vault-bucket", "cust1")
			claim.Spec.Bucket.Provider = provider
			claim.Spec.Bucket.ProviderConfigRef = profile
			err := k8sClient.Create(ctx, claim)
			if valid {
				Expect(err).NotTo(HaveOccurred())
				if provider == "" {
					Expect(claim.Spec.Bucket.Provider).To(Equal(vaultv1alpha1.S3ProviderInternal))
				}
			} else {
				Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
			}
		},
		Entry("legacy claim", "legacy-bucket", "", "", true),
		Entry("explicit internal", "internal-bucket", "internal", "", true),
		Entry("Yandex profile", "yandex-bucket", "yandex", testYandexProfile, true),
		Entry("missing profile", "no-profile-bucket", "yandex", "", false),
		Entry("invalid profile", "invalid-profile-bucket", "yandex", " ", false),
		Entry("unknown provider", "unknown-provider-bucket", "other", "", false),
	)

	It("rejects changing the effective provider or Yandex profile", func() {
		internal := makeS3BucketClaim(ctx, "immutable-internal", "vault-bucket", "cust1")
		internal.Spec.Bucket.Provider = vaultv1alpha1.S3ProviderYandex
		internal.Spec.Bucket.ProviderConfigRef = testYandexProfile
		Expect(apierrors.IsInvalid(k8sClient.Update(ctx, internal))).To(BeTrue())

		claim := newS3BucketClaim("immutable-yandex", "vault-bucket", "cust1")
		claim.Spec.Bucket.Provider = vaultv1alpha1.S3ProviderYandex
		claim.Spec.Bucket.ProviderConfigRef = testYandexProfile
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		claim.Spec.Bucket.ProviderConfigRef = "other-backups"
		Expect(apierrors.IsInvalid(k8sClient.Update(ctx, claim))).To(BeTrue())
	})
})

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
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			Recorder:     record.NewFakeRecorder(50),
			VaultFactory: &fakeSecretVaultFactory{Client: fakeSV},
			Providers:    map[string]bucketprovider.BucketProvider{vaultv1alpha1.S3ProviderInternal: beget.New(buckets, "s3_v1")},
		}
	})

	It("creates a bucket and writes credentials to Vault, reaching Ready", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-ready")
		makeS3BucketClaim(ctx, "s3ready", "s3-cfg-ready", custName)

		_, err := reconcileBucketOnce(recon, "s3ready")
		Expect(err).NotTo(HaveOccurred())
		_, err = reconcileBucketOnce(recon, "s3ready")
		Expect(err).NotTo(HaveOccurred())

		realName := cloudmanager.FakePrefix + "k8s-cust1-s3ready"
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
		Expect(vaultData["endpoint"]).To(Equal("s3.ru1.storage.beget.cloud"))
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
		realName := "c942bd41757d-k8s-cust1-s3adopt"
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
		requested := "k8s-cust1-s3heal"
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

	It("records the real bucket name before credentials are available", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-creating")
		claim := makeS3BucketClaim(ctx, "s3creating", "s3-cfg-creating", custName)
		key := types.NamespacedName{Namespace: ns, Name: claim.Name}
		realName := cloudmanager.FakePrefix + "k8s-cust1-s3creating"
		buckets.FindHook = func(_ context.Context, login, name string) (*cloudmanager.Bucket, error) {
			Expect(login).To(Equal(custName))
			Expect(name).To(Equal(realName))
			return &cloudmanager.Bucket{Name: name, CustLogin: login, Status: cloudmanager.StatusCreating}, nil
		}

		result, err := reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(15 * time.Second))
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.BucketName).To(Equal(realName))
		Expect(claim.Status.BucketStatus).To(Equal(cloudmanager.StatusCreating))
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhasePending))
		Expect(isConditionTrue(claim.Status.Conditions, vaultv1alpha1.ConditionBucketProvisioned)).To(BeTrue())
		Expect(findCond(claim.Status.Conditions, vaultv1alpha1.ConditionBucketRunning).Reason).To(Equal("Creating"))
		Expect(fakeSV.writes).To(BeZero())

		buckets.FindHook = nil
		_, err = reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(buckets.Creates).To(Equal(1))
	})

	It("retains the bucket and Vault data when the claim is deleted with Retain", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-retain")
		claim := makeS3BucketClaim(ctx, "s3retain", "s3-cfg-retain", custName)
		claim.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
		Expect(k8sClient.Update(ctx, claim)).To(Succeed())

		_, err := reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
		_, err = reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())

		Expect(buckets.Creates).To(Equal(1))
		Expect(buckets.Removes).To(BeZero())
		Expect(fakeSV.store["secret|clusters/s3retain/backup/s3"]).NotTo(BeNil())
		err = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: claim.Name}, claim)
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("keeps the finalizer until Vault cleanup succeeds after bucket removal", func() {
		makeHealthyVaultConfig(ctx, "s3-cfg-purge-retry")
		claim := makeS3BucketClaim(ctx, "s3purgeretry", "s3-cfg-purge-retry", custName)
		key := types.NamespacedName{Namespace: ns, Name: claim.Name}
		_, err := reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		fakeSV.loginErr = errors.New("Vault unavailable")
		result, err := reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(bucketRequeueDeletionStuck))
		Expect(buckets.Removes).To(Equal(1))
		Expect(fakeSV.deletes).To(BeZero())
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)).To(BeTrue())

		fakeSV.loginErr = nil
		_, err = reconcileBucketOnce(recon, claim.Name)
		Expect(err).NotTo(HaveOccurred())
		Expect(buckets.Removes).To(Equal(1))
		Expect(fakeSV.deletes).To(Equal(1))
		Expect(fakeSV.store["secret|clusters/s3purgeretry/backup/s3"]).To(BeNil())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, claim))).To(BeTrue())
	})
})

type fakeBucketProvider struct {
	ensure func(bucketprovider.EnsureRequest) bucketprovider.EnsureResult
	remove func(bucketprovider.DeleteRequest) bucketprovider.DeleteResult
}

func (f *fakeBucketProvider) Ensure(_ context.Context, req bucketprovider.EnsureRequest) (bucketprovider.EnsureResult, error) {
	return f.ensure(req), nil
}

func (f *fakeBucketProvider) Delete(_ context.Context, req bucketprovider.DeleteRequest) (bucketprovider.DeleteResult, error) {
	return f.remove(req), nil
}

var _ = Describe("S3BucketClaim provider orchestration", func() {
	var (
		provider *fakeBucketProvider
		fakeSV   *fakeSecretVaultClient
		recon    *S3BucketClaimReconciler
	)

	BeforeEach(func() {
		provider = &fakeBucketProvider{}
		fakeSV = newFakeSecretVault()
		recon = &S3BucketClaimReconciler{
			Client:       k8sClient,
			Recorder:     record.NewFakeRecorder(50),
			VaultFactory: &fakeSecretVaultFactory{Client: fakeSV},
			Providers:    map[string]bucketprovider.BucketProvider{vaultv1alpha1.S3ProviderInternal: provider},
		}
	})

	It("uses the same Yandex provider and Vault paths for creation and purge", func() {
		const name = "s3provider-yandex"
		const vaultConfig = "s3-cfg-yandex"
		const path = "clusters/" + name + "/backup/s3"
		const endpoint = "storage.yandexcloud.net"
		makeHealthyVaultConfig(ctx, vaultConfig)
		recon.Providers[vaultv1alpha1.S3ProviderYandex] = provider
		claim := newS3BucketClaim(name, vaultConfig, "cust1")
		claim.Spec.Bucket.Provider = vaultv1alpha1.S3ProviderYandex
		claim.Spec.Bucket.ProviderConfigRef = testYandexProfile
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		uid := string(claim.UID)
		fakeSV.seed("providers/yandex/profiles/"+testYandexProfile, map[string]any{"folder_id": "system-folder"})
		provider.ensure = func(req bucketprovider.EnsureRequest) bucketprovider.EnsureResult {
			Expect(req.Claim.UID).To(Equal(uid))
			Expect(req.Claim.Profile).To(Equal(testYandexProfile))
			profile, found, err := req.Claim.Vault.ReadProfile(ctx, req.Claim.Profile)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeTrue())
			Expect(profile["folder_id"]).To(Equal("system-folder"))
			_, found, err = req.Claim.Vault.ReadPublished(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeFalse())
			return bucketprovider.EnsureResult{
				BucketName: "yandex-backups",
				Running:    bucketprovider.Stage{State: bucketprovider.Pending, Reason: "AwaitingAccessCheck"},
				RetryAfter: 15 * time.Second,
				Connection: &bucketprovider.Connection{
					BucketName: "yandex-backups", AccessKey: "access", SecretKey: "secret", Endpoint: endpoint,
					Region: "ru-central1", ForcePathStyle: true,
				},
			}
		}
		res, err := reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(15 * time.Second))
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: claim.Namespace, Name: name}, claim)).To(Succeed())
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhasePending))
		Expect(fakeSV.store["secret|"+path]["endpoint"]).To(Equal(endpoint))

		provider.remove = func(req bucketprovider.DeleteRequest) bucketprovider.DeleteResult {
			Expect(req.Claim.UID).To(Equal(uid))
			Expect(req.Claim.Profile).To(Equal(testYandexProfile))
			data, found, err := req.Claim.Vault.ReadPublished(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(BeTrue())
			Expect(data["bucketName"]).To(Equal("yandex-backups"))
			return bucketprovider.DeleteResult{Done: true}
		}
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
		_, err = reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeSV.store["secret|"+path]).To(BeNil())
	})

	It("preserves the bucket binding and ESO connection on a Yandex identity conflict", func() {
		const name = "s3provider-identity-conflict"
		const configName = "s3-cfg-identity-conflict"
		const bucketName = "security-root"
		const path = "clusters/" + name + "/backup/s3"
		makeHealthyVaultConfig(ctx, configName)
		recon.Providers[vaultv1alpha1.S3ProviderYandex] = provider
		claim := newS3BucketClaim(name, configName, "cust1")
		claim.Spec.Bucket.Provider = vaultv1alpha1.S3ProviderYandex
		claim.Spec.Bucket.ProviderConfigRef = testYandexProfile
		Expect(k8sClient.Create(ctx, claim)).To(Succeed())
		claim.Status = vaultv1alpha1.S3BucketClaimStatus{
			Phase: vaultv1alpha1.PhaseReady, BucketName: bucketName, KeysWrittenHash: "existing-hash",
		}
		Expect(k8sClient.Status().Update(ctx, claim)).To(Succeed())
		connection := map[string]any{
			"bucketName": bucketName, "accessKey": "existing-access", "secretKey": "existing-secret", "endpoint": "existing-host",
		}
		fakeSV.seed(path, connection)
		provider.ensure = func(req bucketprovider.EnsureRequest) bucketprovider.EnsureResult {
			Expect(req.BucketName).To(Equal(bucketName))
			return bucketprovider.EnsureResult{
				Provisioned: bucketprovider.Stage{State: bucketprovider.Failed, Reason: "ProviderOwnershipConflict"},
				RetryAfter:  15 * time.Second,
			}
		}
		_, err := reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		key := types.NamespacedName{Namespace: claim.Namespace, Name: name}
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.BucketName).To(Equal(bucketName))
		Expect(claim.Status.KeysWrittenHash).To(Equal("existing-hash"))
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		Expect(fakeSV.store["secret|"+path]).To(Equal(connection))
		Expect(fakeSV.writes).To(BeZero())

		provider.remove = func(req bucketprovider.DeleteRequest) bucketprovider.DeleteResult {
			Expect(req.BucketName).To(Equal(bucketName))
			return bucketprovider.DeleteResult{WarningReason: "ProviderOwnershipConflict", RetryAfter: 15 * time.Second}
		}
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
		_, err = reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.BucketName).To(Equal(bucketName))
		Expect(controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)).To(BeTrue())
		Expect(fakeSV.store["secret|"+path]).To(Equal(connection))
		Expect(fakeSV.deletes).To(BeZero())
	})

	It("persists partial observations and publishes the provider connection before Ready", func() {
		const name = "s3provider"
		const path = "clusters/" + name + "/backup/s3"
		makeHealthyVaultConfig(ctx, "s3-cfg-provider")
		claim := makeS3BucketClaim(ctx, name, "s3-cfg-provider", "cust1")
		key := types.NamespacedName{Namespace: claim.Namespace, Name: name}
		fakeSV.seed(path, map[string]any{"existing": "value"})

		provider.ensure = func(req bucketprovider.EnsureRequest) bucketprovider.EnsureResult {
			Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
			Expect(controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)).To(BeTrue())
			Expect(req.BucketName).To(BeEmpty())
			Expect(fakeSV.writes).To(BeZero())
			return bucketprovider.EnsureResult{
				BucketName:  "resolved-name",
				Provisioned: bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Created"},
				Running:     bucketprovider.Stage{State: bucketprovider.Pending, Reason: "Creating"},
				RetryAfter:  7 * time.Second,
			}
		}
		result, err := reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(7 * time.Second))
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.BucketName).To(Equal("resolved-name"))
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhasePending))
		Expect(fakeSV.writes).To(BeZero())

		conn := &bucketprovider.Connection{
			BucketName: "resolved-name", AccessKey: "access", SecretKey: "secret",
			Endpoint: "s3.ru2.storage.beget.cloud", Region: "ru2", ForcePathStyle: true, Cname: "cname",
		}
		provider.ensure = func(req bucketprovider.EnsureRequest) bucketprovider.EnsureResult {
			Expect(req.BucketName).To(Equal(conn.BucketName))
			return bucketprovider.EnsureResult{
				Running:    bucketprovider.Stage{State: bucketprovider.Succeeded, Reason: "Running"},
				Connection: conn,
			}
		}
		result, err = reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(10 * time.Minute))
		Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
		Expect(claim.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(claim.Status.Endpoint).To(Equal(conn.Endpoint))
		Expect(claim.Status.KeysWrittenHash).To(Equal(sha256Hex("access", "secret", "resolved-name", "s3.ru2.storage.beget.cloud")))
		Expect(fakeSV.store["secret|"+path]).To(Equal(map[string]any{
			"existing": "value", "bucketName": "resolved-name", "accessKey": "access", "secretKey": "secret",
			"endpoint": "s3.ru2.storage.beget.cloud", "region": "ru2", "s3ForcePathStyle": "true", "cname": "cname",
		}))

		_, err = reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeSV.writes).To(Equal(1))
		conn.SecretKey = "rotated"
		_, err = reconcileBucketOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeSV.writes).To(Equal(2))
		Expect(fakeSV.store["secret|"+path]["secretKey"]).To(Equal("rotated"))
	})

	DescribeTable("applies the claim deletion policy before cleaning up Vault",
		func(policy string) {
			name := "s3provider-" + strings.ToLower(policy)
			path := "clusters/" + name + "/backup/s3"
			makeHealthyVaultConfig(ctx, "s3-cfg-"+name)
			claim := makeS3BucketClaim(ctx, name, "s3-cfg-"+name, "cust1")
			key := types.NamespacedName{Namespace: claim.Namespace, Name: name}
			claim.Spec.DeletionPolicy = policy
			controllerutil.AddFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)
			Expect(k8sClient.Update(ctx, claim)).To(Succeed())
			fakeSV.seed(path, map[string]any{"bucketName": "existing-name"})
			Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

			calls := 0
			provider.remove = func(req bucketprovider.DeleteRequest) bucketprovider.DeleteResult {
				calls++
				Expect(req.ClusterName).To(Equal(name))
				Expect(fakeSV.deletes).To(BeZero())
				if calls == 1 {
					return bucketprovider.DeleteResult{BucketName: "existing-name", RetryAfter: time.Minute}
				}
				Expect(req.BucketName).To(Equal("existing-name"))
				return bucketprovider.DeleteResult{Done: true}
			}
			result, err := reconcileBucketOnce(recon, name)
			Expect(err).NotTo(HaveOccurred())
			if policy == vaultv1alpha1.DeletionPolicyPurge {
				Expect(result.RequeueAfter).To(Equal(time.Minute))
				Expect(k8sClient.Get(ctx, key, claim)).To(Succeed())
				Expect(controllerutil.ContainsFinalizer(claim, vaultv1alpha1.S3BucketClaimFinalizer)).To(BeTrue())
				_, err = reconcileBucketOnce(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(calls).To(Equal(2))
				Expect(fakeSV.store["secret|"+path]).To(BeNil())
			} else {
				Expect(calls).To(BeZero())
				Expect(fakeSV.store["secret|"+path]).NotTo(BeNil())
			}
			Expect(apierrors.IsNotFound(k8sClient.Get(ctx, key, claim))).To(BeTrue())
		},
		Entry("Purge waits for the provider", vaultv1alpha1.DeletionPolicyPurge),
		Entry("Retain leaves the provider and Vault alone", vaultv1alpha1.DeletionPolicyRetain),
	)
})

func findCond(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
