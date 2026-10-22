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
	"crypto/tls"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// The VaultConfig probe runs against the real vault.Client and factory here:
// how many logins the probes cost, and which CA the client trusts, belong to
// them, not to a fake.
var _ = Describe("VaultConfig probe through the real client", func() {
	createConfig := func(name, addr string, tlsSpec *vaultv1alpha1.TLSSpec) {
		vc := &vaultv1alpha1.VaultConfig{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: vaultv1alpha1.VaultConfigSpec{
				Address: addr,
				ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
					Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-operator",
				},
				Storage: vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
				TLS:     tlsSpec,
			},
		}
		Expect(k8sClient.Create(context.Background(), vc)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultConfig{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})
	}
	probe := func(r *VaultConfigReconciler, name string) *vaultv1alpha1.VaultConfig {
		_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
		Expect(err).NotTo(HaveOccurred())
		got := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, got)).To(Succeed())
		return got
	}
	newProber := func() *VaultConfigReconciler {
		return &VaultConfigReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(),
			VaultFactory: &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("operator-jwt")},
		}
	}

	It("probes 200 times on one Vault login", func() {
		v := newHTTPVault().start()
		DeferCleanup(v.Close)
		name := "probe-" + nextClaimName()
		createConfig(name, v.URL, nil)
		r := newProber()

		for range 200 {
			got := probe(r, name)
			Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionManagerLoggedIn)).To(BeTrue())
		}
		Expect(v.logins.Load()).To(BeEquivalentTo(1), "every probe after the first reuses the token")
	})

	It("trusts a rotated CA bundle without a restart", func() {
		ca1, err := newTestCA("vault-ca-1")
		Expect(err).NotTo(HaveOccurred())
		ca2, err := newTestCA("vault-ca-2")
		Expect(err).NotTo(HaveOccurred())
		var cert atomic.Pointer[tls.Certificate]
		cert.Store(ca1.leaf)
		v := newHTTPVault().startTLS(&cert)
		DeferCleanup(v.Close)

		name := "ca-" + nextClaimName()
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Data:       map[string][]byte{"ca.crt": ca1.pem},
		}
		Expect(k8sClient.Create(context.Background(), secret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), secret) })
		createConfig(name, v.URL, &vaultv1alpha1.TLSSpec{
			CABundleSecretRef: &vaultv1alpha1.SecretKeySelector{Name: name, Namespace: vcNS, Key: "ca.crt"},
		})
		r := newProber()
		Expect(isConditionTrue(probe(r, name).Status.Conditions, vaultv1alpha1.ConditionReachable)).To(BeTrue())

		// Twin: Vault moves to a certificate of the new CA before the bundle
		// does; the old bundle does not trust it.
		cert.Store(ca2.leaf)
		v.CloseClientConnections()
		Expect(findConditionStatus(probe(r, name).Status.Conditions, vaultv1alpha1.ConditionReachable)).
			To(Equal(metav1.ConditionFalse))

		// The bundle is rotated: the next probe trusts the new CA.
		fresh := &corev1.Secret{}
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(secret), fresh)).To(Succeed())
		fresh.Data["ca.crt"] = ca2.pem
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		Expect(isConditionTrue(probe(r, name).Status.Conditions, vaultv1alpha1.ConditionReachable)).
			To(BeTrue(), "the cached client still trusts only the old CA")
		Expect(v.logins.Load()).To(BeEquivalentTo(1), "the client rebuilt for the new CA kept the token")
	})
})
