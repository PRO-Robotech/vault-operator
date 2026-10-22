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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/tools/record"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// A release before ownership checks configured whatever mount spec named and
// recorded it in status.vault.authMountPath. Such a claim keeps its mount
// whatever its description says; a claim this release has not accepted a
// mount for never gets that record, so the record cannot be earned by waiting.
var _ = Describe("A mount accepted by an earlier release stays accepted", func() {
	var (
		recon  *VaultClaimReconciler
		fakeVC *fakeVaultClient
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		recon = &VaultClaimReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: record.NewFakeRecorder(500),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", now.Add(24*time.Hour))},
			Now:           func() time.Time { return now },
		}
	})

	foreignMount := func(name, typ string) {
		fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": {Type: typ, Accessor: "auth_x", Description: "created by hand"}}
	}

	// legacyStatus is the status the earlier release leaves: the mount it
	// configured and the ledger, no ownership fact. observedGeneration 0 makes
	// the next pass a full one.
	legacyStatus := func(name, cfg, recorded string) {
		c := claimNamed(name)
		c.Status = vaultv1alpha1.VaultClaimStatus{
			Phase: vaultv1alpha1.PhaseReady,
			Vault: &vaultv1alpha1.VaultStatusSummary{
				ConfigName: cfg, AuthMountPath: recorded, SecretsPrefix: c.Spec.SecretsPrefix,
				AppliedPolicies: []string{name + "-p"}, AppliedRoles: []string{name + "-r"},
			},
		}
		Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())
	}

	newOwner := func(name, cfg, sec string) {
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p"))))
	}

	It("a legacy claim on a mount with a foreign description is Ready and the mount is left as it is", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		newOwner(name, cfg, sec)
		foreignMount(name, "kubernetes")
		fakeVC.WrittenPolicies = map[string]string{name + "-p": ownRules(name)}
		legacyStatus(name, cfg, "kubernetes-"+name)

		for i := 0; i < 3; i++ {
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			got := claimNamed(name)
			Expect(reasonOf(got, vaultv1alpha1.ConditionAuthMountReady)).NotTo(Equal(ReasonMountConflict))
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady), "pass %d, conditions %+v", i, got.Status.Conditions)
		}
		Expect(fakeVC.EnableAuthCalls + fakeVC.DisableAuthCalls).To(Equal(0))
		Expect(fakeVC.WriteConfigCalls).To(BeNumerically(">=", 1), "the earlier release wrote the config on every full pass")
		Expect(fakeVC.ListAuthMountsResp["kubernetes-"+name+"/"].Description).To(Equal("created by hand"))
		Expect(claimNamed(name).Status.Vault.AuthMountPath).To(Equal("kubernetes-" + name))

		// Deleting it never disables a mount sys/auth does not show as the claim's.
		deleteAndReconcile(recon, name)
		Expect(fakeVC.DisableAuthCalls).To(Equal(0))
	})

	It("twin: a new claim on the same mount is refused and never records the mount", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		newOwner(name, cfg, sec)
		foreignMount(name, "kubernetes")

		for i := 0; i < 3; i++ {
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			got := claimNamed(name)
			Expect(reasonOf(got, vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
			Expect(got.Status.Vault.AuthMountPath).To(BeEmpty(), "pass %d recorded a mount it refused", i)
		}
		Expect(fakeVC.WriteConfigCalls).To(Equal(0))
	})

	It("twin: a legacy record of another mount does not accept this one", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		newOwner(name, cfg, sec)
		foreignMount(name, "kubernetes")
		legacyStatus(name, cfg, "kubernetes-elsewhere")

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
		Expect(fakeVC.WriteConfigCalls).To(Equal(0))
	})

	It("twin: a legacy record does not accept a mount of another type", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		newOwner(name, cfg, sec)
		foreignMount(name, "approle")
		legacyStatus(name, cfg, "kubernetes-"+name)

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
		Expect(fakeVC.WriteConfigCalls).To(Equal(0))
	})
})
