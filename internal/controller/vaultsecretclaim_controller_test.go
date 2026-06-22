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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

type fakeSecretVaultClient struct {
	store      map[string]map[string]any
	loginErr   error
	loginCalls int
	writes     int
	deletes    int
}

func newFakeSecretVault() *fakeSecretVaultClient {
	return &fakeSecretVaultClient{store: map[string]map[string]any{}}
}

func (f *fakeSecretVaultClient) seed(mount, path string, data map[string]any) {
	f.store[mount+"|"+path] = cloneData(data)
}

func (f *fakeSecretVaultClient) Login(context.Context) error { f.loginCalls++; return f.loginErr }
func (f *fakeSecretVaultClient) Token() string               { return "tok" }
func (f *fakeSecretVaultClient) ClearToken()                 {}

func (f *fakeSecretVaultClient) ReadKV(_ context.Context, mount, path string) (map[string]any, bool, error) {
	d, ok := f.store[mount+"|"+path]
	if !ok {
		return nil, false, nil
	}
	return cloneData(d), true, nil
}

func (f *fakeSecretVaultClient) WriteKV(_ context.Context, mount, path string, data map[string]any) error {
	f.store[mount+"|"+path] = cloneData(data)
	f.writes++
	return nil
}

func (f *fakeSecretVaultClient) KVMetadataExists(_ context.Context, mount, path string) (bool, error) {
	_, ok := f.store[mount+"|"+path]
	return ok, nil
}

func (f *fakeSecretVaultClient) DeleteKVMetadata(_ context.Context, mount, path string) error {
	delete(f.store, mount+"|"+path)
	f.deletes++
	return nil
}

type fakeSecretVaultFactory struct{ Client *fakeSecretVaultClient }

func (f *fakeSecretVaultFactory) For(context.Context, client.Client, *vaultv1alpha1.VaultConfig) (SecretVaultClient, error) {
	if f.Client == nil {
		return nil, errors.New("fakeSecretVaultFactory.Client not set")
	}
	return f.Client, nil
}

func (f *fakeSecretVaultFactory) Invalidate(string) {}

func reconcileSecretOnce(r *VaultSecretClaimReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
}

func genListItem() vaultv1alpha1.SecretListItem {
	return vaultv1alpha1.SecretListItem{
		Name:        "argocd-admin",
		Type:        vaultv1alpha1.SecretTypeGenerate,
		Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "admin.password", HashedKey: "admin.passwordBcrypt"},
		Generate:    &vaultv1alpha1.GenerateSpec{Length: 16, Hash: vaultv1alpha1.HashBcrypt},
	}
}

func copyListItem() vaultv1alpha1.SecretListItem {
	return vaultv1alpha1.SecretListItem{
		Name:        "grafana-oidc",
		Type:        vaultv1alpha1.SecretTypeCopy,
		Source:      &vaultv1alpha1.SourceSpec{Path: "system/dex", Key: "staticClient"},
		Destination: vaultv1alpha1.DestinationSpec{Path: "grafana", Key: "staticClient"},
	}
}

func makeVaultSecretClaim(ctx context.Context, name, configName, deletionPolicy string, items []vaultv1alpha1.SecretListItem) {
	claim := &vaultv1alpha1.VaultSecretClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.VaultSecretClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: name},
			SecretsPrefix:  "clusters/" + name,
			DeletionPolicy: deletionPolicy,
			SecretList:     items,
		},
	}
	Expect(k8sClient.Create(ctx, claim)).To(Succeed())
}

var _ = Describe("VaultSecretClaim Controller", func() {
	const ns = "default"
	var (
		fakeSV *fakeSecretVaultClient
		recon  *VaultSecretClaimReconciler
	)

	BeforeEach(func() {
		fakeSV = newFakeSecretVault()
		recon = &VaultSecretClaimReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			Recorder:     record.NewFakeRecorder(50),
			VaultFactory: &fakeSecretVaultFactory{Client: fakeSV},
			Now:          func() time.Time { return time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC) },
		}
	})

	It("applies generate and copy items and becomes Ready", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-ready")
		fakeSV.seed("secret", "system/dex", map[string]any{"staticClient": "abc123"})
		makeVaultSecretClaim(ctx, "vsready", "vsc-cfg-ready", vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem(), copyListItem()})

		_, err := reconcileSecretOnce(recon, "vsready")
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vsready"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionSourcesResolved)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionItemsApplied)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReady)).To(BeTrue())
		Expect(got.Status.Items).To(HaveLen(2))

		argocd := fakeSV.store["secret|clusters/vsready/argocd"]
		Expect(argocd["admin.password"]).To(HaveLen(16))
		Expect(argocd["admin.passwordBcrypt"].(string)).To(HavePrefix("$2a$"))
		grafana := fakeSV.store["secret|clusters/vsready/grafana"]
		Expect(grafana["staticClient"]).To(Equal("abc123"))
	})

	It("fails when a copy source is missing", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-missing")
		makeVaultSecretClaim(ctx, "vsmissing", "vsc-cfg-missing", vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{copyListItem()})

		_, err := reconcileSecretOnce(recon, "vsmissing")
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vsmissing"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionSourcesResolved)).To(Equal(metav1.ConditionFalse))
		Expect(fakeSV.store["secret|clusters/vsmissing/grafana"]).To(BeNil())
	})

	It("purges written keys on deletion when policy is Purge", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-purge")
		makeVaultSecretClaim(ctx, "vspurge", "vsc-cfg-purge", vaultv1alpha1.DeletionPolicyPurge,
			[]vaultv1alpha1.SecretListItem{genListItem()})

		_, err := reconcileSecretOnce(recon, "vspurge")
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeSV.store["secret|clusters/vspurge/argocd"]).NotTo(BeNil())

		claim := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vspurge"}, claim)).To(Succeed())
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		_, err = reconcileSecretOnce(recon, "vspurge")
		Expect(err).NotTo(HaveOccurred())

		Expect(fakeSV.store["secret|clusters/vspurge/argocd"]).To(BeNil())
		Expect(fakeSV.deletes).To(BeNumerically(">", 0))
		err = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vspurge"}, &vaultv1alpha1.VaultSecretClaim{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("retains written keys on deletion when policy is Retain", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-retain")
		makeVaultSecretClaim(ctx, "vsretain", "vsc-cfg-retain", vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem()})

		_, err := reconcileSecretOnce(recon, "vsretain")
		Expect(err).NotTo(HaveOccurred())

		claim := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vsretain"}, claim)).To(Succeed())
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		_, err = reconcileSecretOnce(recon, "vsretain")
		Expect(err).NotTo(HaveOccurred())

		Expect(fakeSV.store["secret|clusters/vsretain/argocd"]).NotTo(BeNil())
		Expect(fakeSV.deletes).To(Equal(0))
	})

	It("is create-once across a status reset", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-once")
		makeVaultSecretClaim(ctx, "vsonce", "vsc-cfg-once", vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem()})

		_, err := reconcileSecretOnce(recon, "vsonce")
		Expect(err).NotTo(HaveOccurred())
		first := fakeSV.store["secret|clusters/vsonce/argocd"]["admin.password"].(string)

		got := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vsonce"}, got)).To(Succeed())
		got.Status.Items = nil
		Expect(k8sClient.Status().Update(ctx, got)).To(Succeed())

		_, err = reconcileSecretOnce(recon, "vsonce")
		Expect(err).NotTo(HaveOccurred())

		second := fakeSV.store["secret|clusters/vsonce/argocd"]["admin.password"].(string)
		Expect(second).To(Equal(first), "create-once must not regenerate after status reset")
		Expect(strings.HasPrefix(second, "$2a$")).To(BeFalse())
	})

	It("fails on a duplicate destination path+key", func() {
		makeHealthyVaultConfig(ctx, "vsc-cfg-dup")
		dup := vaultv1alpha1.SecretListItem{
			Name:        "dup",
			Type:        vaultv1alpha1.SecretTypeGenerate,
			Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "admin.password"},
			Generate:    &vaultv1alpha1.GenerateSpec{Length: 12, Hash: vaultv1alpha1.HashNone},
		}
		makeVaultSecretClaim(ctx, "vsdup", "vsc-cfg-dup", vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem(), dup})

		_, err := reconcileSecretOnce(recon, "vsdup")
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "vsdup"}, got)).To(Succeed())
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionItemsApplied)).To(Equal(metav1.ConditionFalse))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionReady)).To(Equal(metav1.ConditionFalse))
	})
})
