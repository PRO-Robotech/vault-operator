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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func TestOwnerMatches(t *testing.T) {
	const secret = vaultv1alpha1.OwnerVaultSecretOperator
	const op = vaultv1alpha1.OwnerVaultOperator
	cases := []struct {
		label, owner string
		want         bool
	}{
		{"", "", true},
		{"", op, true},
		{op, "", true},
		{op, op, true},
		{secret, "", false},
		{secret, op, false},
		{secret, secret, true},
		{"", secret, false},
		{op, secret, false},
	}
	for _, c := range cases {
		if got := ownerMatches(c.label, c.owner); got != c.want {
			t.Errorf("ownerMatches(%q,%q) = %v, want %v", c.label, c.owner, got, c.want)
		}
	}
}

var _ = Describe("VaultConfig owner scoping", func() {
	makeOwnedConfig := func(name, owner string) {
		cfg := &vaultv1alpha1.VaultConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{vaultv1alpha1.LabelVaultConfigOwner: owner},
			},
			Spec: vaultv1alpha1.VaultConfigSpec{
				Address:     "https://vault.example",
				ManagerAuth: vaultv1alpha1.ManagerAuthSpec{Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-secret-operator"},
				Storage:     vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
			},
		}
		Expect(k8sClient.Create(ctx, cfg)).To(Succeed())
	}

	It("ignores a vault-secret-owned config in the vault-operator process", func() {
		name := nextVaultConfigName()
		makeOwnedConfig(name, vaultv1alpha1.OwnerVaultSecretOperator)

		r := &VaultConfigReconciler{
			Client:           k8sClient,
			Scheme:           k8sClient.Scheme(),
			VaultFactory:     &fakeVaultFactory{Client: &fakeVaultClient{SharedMountResp: true}},
			VaultConfigOwner: vaultv1alpha1.OwnerVaultOperator,
		}
		_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, got)).To(Succeed())
		Expect(controllerutil.ContainsFinalizer(got, vaultv1alpha1.VaultConfigFinalizer)).To(BeFalse())
		Expect(got.Status.Conditions).To(BeEmpty())
	})

	It("counts VaultSecretClaim references for the secret-owned config", func() {
		name := nextVaultConfigName()
		makeOwnedConfig(name, vaultv1alpha1.OwnerVaultSecretOperator)
		makeVaultSecretClaim(ctx, "scopeclaim", name, vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem()})

		r := &VaultConfigReconciler{
			Client:           k8sClient,
			Scheme:           k8sClient.Scheme(),
			VaultFactory:     &fakeVaultFactory{Client: &fakeVaultClient{SharedMountResp: true}},
			VaultConfigOwner: vaultv1alpha1.OwnerVaultSecretOperator,
		}
		_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())

		got := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, got)).To(Succeed())
		Expect(got.Status.ReferencedBy).To(Equal(int32(1)))
		Expect(controllerutil.ContainsFinalizer(got, vaultv1alpha1.VaultConfigFinalizer)).To(BeTrue())
	})
})
