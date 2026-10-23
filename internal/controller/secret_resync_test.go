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
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientcache "k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// verifies https://github.com/PRO-Robotech/vault-operator/issues/13
var _ = DescribeTable("Secret metadata resync does not wake controllers",
	func(ca bool) {
		const selectorKey = "vault-operator-test/secret-resync"
		name := "resync-" + nextClaimName()
		selected := cache.ByObject{Label: labels.SelectorFromSet(labels.Set{selectorKey: name})}
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: k8sClient.Scheme(), Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
			Cache: cache.Options{SyncPeriod: ptr.To(2 * time.Second), ByObject: map[client.Object]cache.ByObject{
				&vaultv1alpha1.VaultConfig{}: selected, &vaultv1alpha1.VaultClaim{}: selected,
			}},
			Client:     client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}}}},
			Controller: config.Controller{SkipNameValidation: ptr.To(true)},
		})
		Expect(err).NotTo(HaveOccurred())
		controller := "vaultclaim"
		factory := &fakeVaultFactory{Client: &fakeVaultClient{SharedMountResp: true}}
		if ca {
			controller = "vaultconfig"
			Expect((&VaultConfigReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), VaultFactory: factory, WatchCABundleSecrets: true}).SetupWithManager(mgr)).To(Succeed())
		} else {
			Expect((&VaultClaimReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), VaultFactory: factory,
				TargetManager: &target.FakeManager{Err: errors.New("target cluster unreachable")},
			}).SetupWithManager(mgr)).To(Succeed())
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + kubeconfigSecretSuffix, Namespace: vcNS}, Data: map[string][]byte{kubeKey: []byte(stubKubecfg), "ca.crt": []byte("one")}}
		Expect(k8sClient.Create(context.Background(), secret)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(context.Background(), secret)).To(Succeed()) })
		vcfg := &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{selectorKey: name}}, Spec: vaultv1alpha1.VaultConfigSpec{
			Address: "https://vault.example", ManagerAuth: vaultv1alpha1.ManagerAuthSpec{Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-operator"}, Storage: vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
		}}
		if ca {
			vcfg.Spec.TLS = &vaultv1alpha1.TLSSpec{CABundleSecretRef: &vaultv1alpha1.SecretKeySelector{Name: secret.Name, Namespace: vcNS, Key: "ca.crt"}}
		}
		Expect(k8sClient.Create(context.Background(), vcfg)).To(Succeed())
		DeferCleanup(func() { removeVaultConfig(name) })
		if !ca {
			// Здоровый конфиг отделяет повторное событие Secret от ожидания готовности VaultConfig.
			vcfg.Status.Conditions = []metav1.Condition{
				{Type: vaultv1alpha1.ConditionReachable, Status: metav1.ConditionTrue, Reason: "Ok", LastTransitionTime: metav1.Now()},
				{Type: vaultv1alpha1.ConditionSharedMountFound, Status: metav1.ConditionTrue, Reason: "Found", LastTransitionTime: metav1.Now()},
			}
			Expect(k8sClient.Status().Update(context.Background(), vcfg)).To(Succeed())
			c := newClaim(name, name, secret.Name)
			c.Labels = map[string]string{selectorKey: name}
			createClaim(c)
		}
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
		informer, err := mgr.GetCache().GetInformer(context.Background(), metadata, cache.BlockUntilSynced(false))
		Expect(err).NotTo(HaveOccurred())
		var repeated atomic.Int64
		_, err = informer.AddEventHandler(clientcache.ResourceEventHandlerFuncs{UpdateFunc: func(oldObj, newObj interface{}) {
			oldMeta, oldOK := oldObj.(metav1.Object)
			newMeta, newOK := newObj.(metav1.Object)
			if oldOK && newOK && newMeta.GetNamespace() == vcNS && newMeta.GetName() == secret.Name && oldMeta.GetResourceVersion() == newMeta.GetResourceVersion() {
				repeated.Add(1)
			}
		}})
		Expect(err).NotTo(HaveOccurred())
		before := reconcileTotal(controller)
		startManager(mgr)
		Eventually(func() float64 { return reconcileTotal(controller) }, 30*time.Second, 50*time.Millisecond).Should(BeNumerically(">", before))
		baseline := settled(controller)
		initialEvents := repeated.Load()
		// Наблюдаем настоящую доставку повторов informer, а не предполагаем её по таймеру.
		Eventually(repeated.Load, 15*time.Second, 50*time.Millisecond).Should(BeNumerically(">=", initialEvents+2))
		Consistently(func() float64 { return reconcileTotal(controller) }, time.Second, 50*time.Millisecond).Should(Equal(baseline))
		fresh := &corev1.Secret{}
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(secret), fresh)).To(Succeed())
		Expect(fresh.ResourceVersion).To(Equal(secret.ResourceVersion))
		By("a real changed resourceVersion still wakes the controller")
		fresh.Data[kubeKey] = []byte(stubKubecfg + "\n")
		fresh.Data["ca.crt"] = []byte("two")
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		Expect(fresh.ResourceVersion).NotTo(Equal(secret.ResourceVersion))
		Eventually(func() float64 { return reconcileTotal(controller) }, 10*time.Second, 50*time.Millisecond).Should(BeNumerically(">", baseline))
	},
	Entry("kubeconfig watch", false),
	Entry("CA bundle watch", true),
)
