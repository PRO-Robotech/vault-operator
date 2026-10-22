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
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

var _ = Describe("Target cluster issuer", func() {
	const discovered = "https://kubernetes.default.svc.cluster.local"
	var (
		fakeVC   *fakeVaultClient
		targetCS *target.ClientSet
		recon    *VaultClaimReconciler
	)
	BeforeEach(func() {
		fixedNow := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		targetCS = newTargetClientSetWithReactor(targetScheme(), "jwt", fixedNow.Add(24*time.Hour))
		recon = &VaultClaimReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: targetCS},
			Now:           func() time.Time { return fixedNow },
		}
	})

	It("records the discovered issuer and configures the mount with it", func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"issuer": discovered})
		}))
		DeferCleanup(srv.Close)
		targetCS.Host = srv.URL
		name := nextClaimName()
		cfgName, secretName := fixture(name)
		createClaim(newClaim(name, cfgName, secretName))

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(claimNamed(name).Status.Vault.Issuer).To(Equal(discovered))
		Expect(fakeVC.WrittenAuthCfgs).To(HaveLen(1))
		Expect(fakeVC.WrittenAuthCfgs[0].Issuer).To(Equal(discovered))
		Expect(fakeVC.WrittenAuthCfgs[0].DisableISSValidation).To(BeFalse())
	})

	It("keeps validating the issuer it recorded when discovery fails", func() {
		name := nextClaimName()
		cfgName, secretName := fixture(name)
		createClaim(newClaim(name, cfgName, secretName))
		c := claimNamed(name)
		base := c.DeepCopy()
		c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{Issuer: discovered}
		Expect(k8sClient.Status().Patch(context.Background(), c, client.MergeFrom(base))).To(Succeed())

		// The target set has no host: discovery fails this pass.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeVC.WrittenAuthCfgs).To(HaveLen(1))
		Expect(fakeVC.WrittenAuthCfgs[0].Issuer).To(Equal(discovered))
		Expect(fakeVC.WrittenAuthCfgs[0].DisableISSValidation).To(BeFalse(), "a failed discovery turned ISS validation off")
		Expect(claimNamed(name).Status.Vault.Issuer).To(Equal(discovered))
	})
})
