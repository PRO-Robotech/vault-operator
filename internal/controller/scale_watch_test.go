/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// reconcileTotal sums controller_runtime_reconcile_total over every result of
// the named controller.
func reconcileTotal(controllerName string) float64 {
	families, err := ctrlmetrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	var sum float64
	for _, f := range families {
		if f.GetName() != "controller_runtime_reconcile_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "controller" && l.GetValue() == controllerName {
					sum += m.GetCounter().GetValue()
				}
			}
		}
	}
	return sum
}

// settled waits until the counter holds still over a second.
func settled(controllerName string) float64 {
	last := -1.0
	Eventually(func() bool {
		cur := reconcileTotal(controllerName)
		ok := cur == last
		last = cur
		return ok
	}, 60*time.Second, time.Second).Should(BeTrue())
	return last
}

// startManager runs mgr until the spec ends.
func startManager(mgr ctrl.Manager) {
	mgrCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer GinkgoRecover()
		defer close(done)
		Expect(mgr.Start(mgrCtx)).To(Succeed())
	}()
	DeferCleanup(func() {
		stop()
		<-done
	})
}

// removeVaultConfig drops the finalizer a stopped controller cannot remove.
func removeVaultConfig(name string) {
	fresh := &vaultv1alpha1.VaultConfig{}
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name}, fresh); err == nil {
		fresh.Finalizers = nil
		_ = k8sClient.Update(context.Background(), fresh)
		_ = k8sClient.Delete(context.Background(), fresh)
	}
}

var _ = Describe("Load shape", func() {
	It("a claim's status write wakes no other claim; a Reachable transition wakes each claim once", func() {
		const claims = 50
		const selectorKey = "vault-operator-test/fan-out"
		selected := cache.ByObject{Label: labels.SelectorFromSet(labels.Set{selectorKey: "yes"})}
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 k8sClient.Scheme(),
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
				&vaultv1alpha1.VaultClaim{}:  selected,
				&vaultv1alpha1.VaultConfig{}: selected,
			}},
			Controller: config.Controller{SkipNameValidation: ptr.To(true)},
		})
		Expect(err).NotTo(HaveOccurred())

		fakeVC := &fakeVaultClient{SharedMountResp: true}
		Expect((&VaultConfigReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(), VaultFactory: &fakeVaultFactory{Client: fakeVC},
		}).SetupWithManager(mgr)).To(Succeed())
		Expect((&VaultClaimReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(), VaultFactory: &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Err: errors.New("target cluster unreachable")},
		}).SetupWithManager(mgr)).To(Succeed())

		base := nextClaimName()
		cfgName := "fan-" + base
		vcfg := &vaultv1alpha1.VaultConfig{
			ObjectMeta: metav1.ObjectMeta{Name: cfgName, Labels: map[string]string{selectorKey: "yes"}},
			Spec: vaultv1alpha1.VaultConfigSpec{
				Address:     "https://vault.example",
				ManagerAuth: vaultv1alpha1.ManagerAuthSpec{Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-operator"},
				Storage:     vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
			},
		}
		Expect(k8sClient.Create(context.Background(), vcfg)).To(Succeed())
		DeferCleanup(func() { removeVaultConfig(cfgName) })
		secretName := base + "-kc"
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		names := make([]string, 0, claims)
		for i := range claims {
			name := fmt.Sprintf("%s-fan-%d", base, i)
			c := newClaim(name, cfgName, secretName)
			c.Labels = map[string]string{selectorKey: "yes"}
			createClaim(c)
			names = append(names, name)
		}
		startManager(mgr)

		// Every claim has made its first pass before the baseline.
		Eventually(func() int {
			n := 0
			for _, name := range names {
				if claimNamed(name).Status.Phase != "" {
					n++
				}
			}
			return n
		}, 60*time.Second, 500*time.Millisecond).Should(Equal(claims))
		baseline := settled("vaultclaim")

		By("a status write of one claim")
		one := claimNamed(names[0])
		orig := one.DeepCopy()
		one.Status.Phase = vaultv1alpha1.PhasePending
		Expect(k8sClient.Status().Patch(context.Background(), one, client.MergeFrom(orig))).To(Succeed())
		Consistently(func() float64 { return reconcileTotal("vaultclaim") - baseline }, 5*time.Second, 250*time.Millisecond).
			Should(BeNumerically("<=", 1), "one claim's status write reconciled other claims")
		baseline = settled("vaultclaim")

		By("Vault becomes unreachable")
		fakeVC.mu.Lock()
		fakeVC.SealErr = errors.New("connection refused")
		fakeVC.mu.Unlock()
		fresh := &vaultv1alpha1.VaultConfig{}
		Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: cfgName}, fresh)).To(Succeed())
		fresh.Annotations = map[string]string{"vault-operator-test/poke": "1"}
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		Eventually(func() float64 { return reconcileTotal("vaultclaim") - baseline }, 20*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">=", claims))
		Consistently(func() float64 { return reconcileTotal("vaultclaim") - baseline }, 3*time.Second, 250*time.Millisecond).
			Should(Equal(float64(claims)), "the transition reached the claims more than once")
	})

	It("keeps Secret bodies out of memory; a kubeconfig change still wakes its claim", func() {
		const secrets = 2000
		const selectorKey = "vault-operator-test/heap"
		ns := "heap-" + nextClaimName()
		Expect(k8sClient.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.DeleteAllOf(context.Background(), &corev1.Secret{}, client.InNamespace(ns))
			_ = k8sClient.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
		})
		payload := bytes.Repeat([]byte("x"), 100<<10)
		work := make(chan int)
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := range work {
					s := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("bulk-%d", i), Namespace: ns},
						Data:       map[string][]byte{"blob": payload},
					}
					Expect(k8sClient.Create(context.Background(), s)).To(Succeed())
				}
			}()
		}
		for i := range secrets {
			work <- i
		}
		close(work)
		wg.Wait()

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 k8sClient.Scheme(),
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Cache: cache.Options{
				DefaultTransform: cache.TransformStripManagedFields(),
				ByObject: map[client.Object]cache.ByObject{
					&vaultv1alpha1.VaultClaim{}: {Label: labels.SelectorFromSet(labels.Set{selectorKey: "yes"})},
				},
			},
			Client:     client.Options{Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}}}},
			Controller: config.Controller{SkipNameValidation: ptr.To(true)},
		})
		Expect(err).NotTo(HaveOccurred())
		fakeVC := &fakeVaultClient{SharedMountResp: true}
		Expect((&VaultClaimReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(), VaultFactory: &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Err: errors.New("target cluster unreachable")},
		}).SetupWithManager(mgr)).To(Succeed())

		name := nextClaimName()
		cfgName, _ := fixture(name)
		kubeconfig := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name + kubeconfigSecretSuffix, Namespace: vcNS},
			Data:       map[string][]byte{kubeKey: []byte(stubKubecfg)},
		}
		Expect(k8sClient.Create(context.Background(), kubeconfig)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(context.Background(), kubeconfig) })
		c := newClaim(name, cfgName, "")
		c.Labels = map[string]string{selectorKey: "yes"}
		createClaim(c)

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		startManager(mgr)

		logins := func() int {
			fakeVC.mu.Lock()
			defer fakeVC.mu.Unlock()
			return fakeVC.LoginCalls
		}
		// A pass runs only after every watch of the controller has synced.
		Eventually(logins, 60*time.Second, 100*time.Millisecond).Should(BeNumerically(">=", 1))
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		Expect(grown).To(BeNumerically("<", 80<<20),
			"heap grew by %d MiB with %d Secrets of 100 KiB in the cluster", grown>>20, secrets)

		By("the kubeconfig changes")
		settledLogins := logins()
		fresh := &corev1.Secret{}
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(kubeconfig), fresh)).To(Succeed())
		fresh.Data[kubeKey] = []byte(stubKubecfg + "\n")
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		Eventually(logins, 10*time.Second, 100*time.Millisecond).Should(BeNumerically(">", settledLogins))
	})
})
