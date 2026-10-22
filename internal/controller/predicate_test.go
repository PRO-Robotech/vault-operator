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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// The controller runs under a real manager here: the property is about which
// watch events reach Reconcile, which calling Reconcile directly cannot show.
var _ = Describe("VaultClaim controller watches", func() {
	It("status and finalizer writes do not re-trigger a failing claim; deletion still runs at once", func() {
		const selectorKey = "vault-operator-test/watch"
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 k8sClient.Scheme(),
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
				&vaultv1alpha1.VaultClaim{}: {Label: labels.SelectorFromSet(labels.Set{selectorKey: "yes"})},
			}},
			Controller: config.Controller{SkipNameValidation: ptr.To(true)},
		})
		Expect(err).NotTo(HaveOccurred())

		fakeVC := &fakeVaultClient{SharedMountResp: true}
		fakeTarget := &target.FakeManager{Err: errors.New("dial tcp 192.0.2.10:6443: i/o timeout")}
		r := &VaultClaimReconciler{
			Client:        mgr.GetClient(),
			Scheme:        mgr.GetScheme(),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: fakeTarget,
		}
		Expect(r.SetupWithManager(mgr)).To(Succeed())

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

		name := nextClaimName()
		cfgName, secret := fixture(name)
		c := newClaim(name, cfgName, secret)
		c.Labels = map[string]string{selectorKey: "yes"}
		createClaim(c)

		Eventually(func() int {
			fakeVC.mu.Lock()
			defer fakeVC.mu.Unlock()
			return fakeVC.LoginCalls
		}, 10*time.Second, 50*time.Millisecond).Should(BeNumerically(">=", 1))
		// The pass added the finalizer and patched status; neither may start
		// another pass before the one-minute backoff.
		Consistently(func() int {
			fakeVC.mu.Lock()
			defer fakeVC.mu.Unlock()
			return fakeVC.LoginCalls
		}, 3*time.Second, 100*time.Millisecond).Should(Equal(1))

		fresh := &vaultv1alpha1.VaultClaim{}
		Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(c), fresh)).To(Succeed())
		Expect(k8sClient.Delete(context.Background(), fresh)).To(Succeed())
		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
			return apierrors.IsNotFound(err)
		}, 10*time.Second, 100*time.Millisecond).Should(BeTrue(), "deletion bumps generation and must reach the reverse pipeline")
	})
})
