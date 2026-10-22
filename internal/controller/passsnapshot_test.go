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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// A pass writes the spec CheckOwnership admitted, and only that spec: a spec
// edit landing while the pass persists an intent must not reach Vault in the
// same pass, and the pass must not report the edit as observed.
var _ = Describe("A pass works on the spec it admitted", func() {
	var (
		recon    *VaultClaimReconciler
		fakeVC   *fakeVaultClient
		fixedNow time.Time
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		fixedNow = time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		recon = &VaultClaimReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: record.NewFakeRecorder(500),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", fixedNow.Add(24*time.Hour))},
			Now:           func() time.Time { return fixedNow },
			Ownership: OwnershipPolicy{
				ReservedPolicyNames: []string{"vault-operator-admin"},
				ExternalPolicyNames: []string{"registry-guest"},
				ReservedRoleNames:   []string{"metrics-reader"},
			},
		}
	})

	// editOnIntent returns a client that, on the first intent patch matching
	// when, adds extra to the claim's spec through a second client — the way
	// a user's kubectl apply lands while the operator is mid-pass. With extra
	// nil it only counts, which makes it the twin.
	editOnIntent := func(name string, when func(*vaultv1alpha1.VaultClaim) bool, extra *vaultv1alpha1.RoleSpec, fired *bool) client.Client {
		return interceptor.NewClient(watchClient(), interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				vc := obj.(*vaultv1alpha1.VaultClaim)
				if !*fired && when(vc) {
					*fired = true
					if extra != nil {
						fresh := claimNamed(name)
						fresh.Spec.Roles = append(fresh.Spec.Roles, *extra)
						Expect(k8sClient.Update(ctx, fresh)).To(Succeed())
					}
				}
				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		})
	}
	rolesIntent := func(vc *vaultv1alpha1.VaultClaim) bool {
		return vc.Status.Vault != nil && len(vc.Status.Vault.AppliedRoles) > 0
	}
	anyIntent := func(*vaultv1alpha1.VaultClaim) bool { return true }

	guestOnOperatorMount := func() {
		fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{operatorMount + "/": {Type: "kubernetes", Accessor: "auth_kubernetes_mgmt", Description: "operator mount"}}
		fakeVC.AuthConfigs = map[string]vault.KubernetesAuthConfig{operatorMount: {KubernetesHost: "https://mgmt.invalid", TokenReviewerJWT: "owner-jwt"}}
		fakeVC.WrittenRoles = map[string]vault.KubernetesRole{"metrics-reader": {TokenPolicies: []string{"metrics"}}}
	}

	It("a reserved role added during the guest's roles intent is never written, and the edit is not observed", func() {
		name := nextClaimName()
		cfg, _ := fixture(name)
		guestOnOperatorMount()
		createClaim(newClaim(name, cfg, "", asGuest(operatorMount),
			withPolicies(policy(name+"-read", ownRules(name))), withRoles(role("zot-"+name, name+"-read"))))
		fired := false
		evil := role("metrics-reader", "vault-operator-admin")
		recon.Client = editOnIntent(name, rolesIntent, &evil, &fired)

		res, _ := reconcileClaim(recon, name)
		Expect(fired).To(BeTrue(), "the edit landed during the roles intent")
		Expect(fakeVC.WrittenRoles["metrics-reader"].TokenPolicies).To(Equal([]string{"metrics"}))
		Expect(fakeVC.PutRoleCalls).To(Equal(0), "the pass stopped at the intent that saw the edit")
		Expect(res.RequeueAfter).To(Equal(RequeueClaimSpecChanged))
		got := claimNamed(name)
		Expect(got.Generation).To(Equal(int64(2)))
		Expect(got.Status.ObservedGeneration).NotTo(Equal(got.Generation), "a pass that never applied generation 2 reported it observed")

		// The next pass judges the edit and refuses it; the role stays as it was.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonOwnershipConflict))
		Expect(fakeVC.WrittenRoles["metrics-reader"].TokenPolicies).To(Equal([]string{"metrics"}))
	})

	It("twin: the same guest pass without an edit writes its role and is observed", func() {
		name := nextClaimName()
		cfg, _ := fixture(name)
		guestOnOperatorMount()
		createClaim(newClaim(name, cfg, "", asGuest(operatorMount),
			withPolicies(policy(name+"-read", ownRules(name))), withRoles(role("zot-"+name, name+"-read"))))
		fired := false
		recon.Client = editOnIntent(name, rolesIntent, nil, &fired)

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fired).To(BeTrue())
		Expect(fakeVC.WrittenRoles).To(HaveKey("zot-" + name))
		got := claimNamed(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
	})

	It("an owner's role referencing a reserved policy, added during the first intent, is never written", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p"))))
		fired := false
		evil := role(name+"-evil", "vault-operator-admin")
		recon.Client = editOnIntent(name, anyIntent, &evil, &fired)

		_, _ = reconcileClaim(recon, name)
		Expect(fired).To(BeTrue())
		Expect(fakeVC.WrittenRoles).NotTo(HaveKey(name + "-evil"))
		Expect(fakeVC.EnableAuthCalls).To(Equal(0), "the pass stopped at the intent that saw the edit")
		got := claimNamed(name)
		Expect(got.Status.ObservedGeneration).NotTo(Equal(got.Generation))

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonPolicyReferenceForbidden))
		Expect(fakeVC.WrittenRoles).NotTo(HaveKey(name + "-evil"))
	})
})

// A full pass of a Ready claim whose spec did not change keeps the claim Ready
// on the API server from start to end: the ClusterClaim that owns it waits
// for Ready, so any other phase in between makes it flap.
var _ = Describe("A full pass of a Ready claim never shows another phase", func() {
	var (
		recon  *VaultClaimReconciler
		fakeVC *fakeVaultClient
		clock  time.Time
		start  time.Time
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		start = time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		clock = start
		recon = &VaultClaimReconciler{
			Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: record.NewFakeRecorder(500),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", start.Add(24*time.Hour))},
			Now:           func() time.Time { return clock },
		}
	})

	recordPhases := func(phases *[]string, ledgerPatches *int) client.Client {
		return interceptor.NewClient(watchClient(), interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				vc := obj.(*vaultv1alpha1.VaultClaim)
				*phases = append(*phases, vc.Status.Phase)
				if vc.Status.Vault != nil && len(vc.Status.Vault.AppliedRoles) > 0 {
					*ledgerPatches++
				}
				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		})
	}

	readyClaim := func() string {
		name := nextClaimName()
		cfg, sec := fixture(name)
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p"))))
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		return name
	}

	It("a reviewer-JWT rotation pass patches only Ready", func() {
		name := readyClaim()
		var phases []string
		ledger := 0
		recon.Client = recordPhases(&phases, &ledger)
		clock = start.Add(20 * time.Hour) // under 30% of the TTL left: full pass
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeVC.WriteConfigCalls).To(Equal(2), "the second pass was a full pass")
		Expect(phases).NotTo(BeEmpty())
		for _, p := range phases {
			Expect(p).To(Equal(vaultv1alpha1.PhaseReady), "phases patched: %v", phases)
		}
	})

	It("a rotation pass that must persist a ledger entry still patches only Ready", func() {
		name := readyClaim()
		// A ledger without the role — what a status written before the ledger
		// existed looks like — makes the roles step persist an intent.
		c := claimNamed(name)
		c.Status.Vault.AppliedRoles = nil
		Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())

		var phases []string
		ledger := 0
		recon.Client = recordPhases(&phases, &ledger)
		clock = start.Add(20 * time.Hour)
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(ledger).To(BeNumerically(">=", 1), "the roles intent was persisted")
		for _, p := range phases {
			Expect(p).To(Equal(vaultv1alpha1.PhaseReady), "phases patched: %v", phases)
		}
		Expect(claimNamed(name).Status.Vault.AppliedRoles).To(Equal([]string{name + "-r"}))
	})

	It("twin: a new claim still persists its intent before its first write", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name)))))
		putsAtFirstLedgerPatch := -1
		recon.Client = interceptor.NewClient(watchClient(), interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				vc := obj.(*vaultv1alpha1.VaultClaim)
				if putsAtFirstLedgerPatch < 0 && vc.Status.Vault != nil && len(vc.Status.Vault.AppliedPolicies) > 0 {
					putsAtFirstLedgerPatch = fakeVC.PutPolicyCalls
				}
				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		})
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(putsAtFirstLedgerPatch).To(Equal(0), "the ledger entry reached the API server before the policy reached Vault")
		Expect(fakeVC.PutPolicyCalls).To(Equal(1))
	})
})
