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
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// vcCounter is used to mint unique names per spec — Ginkgo runs specs
// concurrently when --procs > 1 and we don't want name collisions.
var vcCounter int

func nextVaultConfigName() string {
	vcCounter++
	return fmt.Sprintf("vc-%d", vcCounter)
}

func reconcileOnce(r *VaultConfigReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
}

var _ = Describe("VaultConfig Controller", func() {
	var (
		fakeVC *fakeVaultClient
		recon  *VaultConfigReconciler
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		recon = &VaultConfigReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			VaultFactory: &fakeVaultFactory{Client: fakeVC},
		}
	})

	makeVC := func(name string) *vaultv1alpha1.VaultConfig {
		vc := &vaultv1alpha1.VaultConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: vaultv1alpha1.VaultConfigSpec{
				Address: "https://vault.example",
				ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
					Method:    vaultv1alpha1.AuthMethodKubernetes,
					MountPath: "kubernetes-mgmt",
					Role:      "vault-operator",
				},
				Storage: vaultv1alpha1.StorageSpec{
					KvMountPath: "secret",
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), vc)).To(Succeed())
		return vc
	}

	getVC := func(name string) *vaultv1alpha1.VaultConfig {
		vc := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, vc)).To(Succeed())
		return vc
	}

	It("sets Ready conditions and adds finalizer on a healthy Vault", func() {
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		// Single reconcile: adds finalizer, then runs the health probe in the
		// same pass (cfg.ResourceVersion is bumped by Update so Status().Update
		// on the same in-memory copy still succeeds).
		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())

		got := getVC(name)
		Expect(got.Finalizers).To(ContainElement(vaultv1alpha1.VaultConfigFinalizer))
		Expect(got.Status.SealStatus).NotTo(BeNil())
		Expect(got.Status.SealStatus.Sealed).To(BeFalse())
		Expect(got.Status.VaultVersion).To(Equal("1.17.6"))

		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReachable)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionVaultInitialized)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound)).To(BeTrue())
	})

	It("cascade conditions when Vault is sealed and skips login", func() {
		fakeVC.SealResp = &vault.SealStatus{Sealed: true, Initialized: true, T: 3, N: 5, Progress: 1, Version: "1.17.6"}
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		res, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueSealed))

		got := getVC(name)
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed)).To(Equal(metav1.ConditionFalse))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn)).To(Equal(metav1.ConditionFalse))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound)).To(Equal(metav1.ConditionFalse))
		Expect(fakeVC.LoginCalls).To(Equal(0), "login must be skipped when Vault is sealed")
		Expect(fakeVC.ClearCalls).To(Equal(1), "client token must be cleared on sealed")
	})

	It("reports Vault unreachable when seal-status itself fails", func() {
		fakeVC.SealErr = errors.New("network unreachable")
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		res, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueUnreachable))

		got := getVC(name)
		c := apimeta.FindStatusCondition(got.Status.Conditions, vaultv1alpha1.ConditionReachable)
		Expect(c).NotTo(BeNil())
		Expect(c.Status).To(Equal(metav1.ConditionFalse))
		Expect(c.Message).To(ContainSubstring("network unreachable"))
	})

	It("reports uninitialized when initialized=false", func() {
		fakeVC.SealResp = &vault.SealStatus{Sealed: true, Initialized: false}
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getVC(name)
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionVaultInitialized)).To(Equal(metav1.ConditionFalse))
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionVaultUnsealed)).To(Equal(metav1.ConditionFalse))
	})

	It("reports SharedMountFound=false when KV mount is missing", func() {
		fakeVC.SharedMountResp = false
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getVC(name)
		Expect(findConditionStatus(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound)).To(Equal(metav1.ConditionFalse))
	})

	It("reports SharedMountFound=false with Forbidden reason on 403", func() {
		fakeVC.SharedMountErr = &vault.APIError{Method: http.MethodGet, Path: "/v1/sys/mounts", StatusCode: http.StatusForbidden}
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getVC(name)
		c := apimeta.FindStatusCondition(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound)
		Expect(c).NotTo(BeNil())
		Expect(c.Status).To(Equal(metav1.ConditionFalse))
		Expect(c.Reason).To(Equal("Forbidden"))
	})

	It("tracks referencedBy via field indexer when VaultClaim points to it", func() {
		name := nextVaultConfigName()
		vc := makeVC(name)
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), vc) })

		// Create a VaultClaim that references this VaultConfig.
		claim := newVaultClaim("c-"+name, "default", name)
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), claim) })

		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getVC(name)
		Expect(got.Status.ReferencedBy).To(Equal(int32(1)))
	})

	It("blocks deletion while VaultClaim references the config", func() {
		name := nextVaultConfigName()
		vc := makeVC(name)

		claim := newVaultClaim("c-"+name, "default", name)
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), claim) })

		_, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Request deletion.
		Expect(k8sClient.Delete(context.Background(), vc)).To(Succeed())

		res, err := reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueDeletionBlocked))

		// Finalizer still present, object not gone.
		got := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, got)).To(Succeed())
		Expect(got.Finalizers).To(ContainElement(vaultv1alpha1.VaultConfigFinalizer))

		// Now remove the claim and re-reconcile — finalizer should drop.
		Expect(k8sClient.Delete(context.Background(), claim)).To(Succeed())

		// Wait until indexed cache sees the deletion (envtest's informer is eventually-consistent).
		Eventually(func() int32 {
			refs, _ := recon.countReferences(context.Background(), name)
			return refs
		}, 5*time.Second, 100*time.Millisecond).Should(Equal(int32(0)))

		_, err = reconcileOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, &vaultv1alpha1.VaultConfig{})
			return err != nil
		}, 5*time.Second, 100*time.Millisecond).Should(BeTrue(), "VaultConfig should be deleted after finalizer drop")
	})
})

// newVaultClaim builds a minimum-valid VaultClaim referencing a VaultConfig.
// Used by tests that exercise the cross-reference indexer.
func newVaultClaim(name, ns, configName string) *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: "c", KubeconfigSecret: "k"},
			SecretsPrefix:  "clusters/" + name,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath: "kubernetes-" + name,
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{
						Namespace: "beget-vault-system",
						Name:      "vault-token-reviewer",
					},
				},
			},
		},
	}
}
