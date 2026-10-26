/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"net"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// conditionDegraded is spelled out: the property is the condition a reader
// of the claim sees, under the name the reader uses.
const conditionDegraded = "Degraded"

var _ = Describe("VaultClaim Degraded condition", func() {
	It("a failing pass sets Degraded and leaves the generation unobserved; the next success clears it", func() {
		fixedNow := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		fakeVC := &fakeVaultClient{
			SharedMountResp: true,
			LoginErr:        &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		}
		r := &VaultClaimReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", fixedNow.Add(24*time.Hour))},
			Now:           func() time.Time { return fixedNow },
		}
		name := nextClaimName()
		cfgName, secretName := fixture(name)
		createClaim(newClaim(name, cfgName, secretName))

		_, err := reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		got := claimNamed(name)
		cond := conditionOf(got, conditionDegraded)
		Expect(cond).NotTo(BeNil(), "a pass that failed leaves no Degraded condition")
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal(string(causeUnreachable)))
		Expect(cond.Message).To(Equal(causeText[causeUnreachable]))
		Expect(got.Status.ObservedGeneration).To(BeZero(), "a failed pass reported the generation as observed")

		fakeVC.mu.Lock()
		fakeVC.LoginErr = nil
		fakeVC.mu.Unlock()
		_, err = reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		got = claimNamed(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		cond = conditionOf(got, conditionDegraded)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
	})
})
