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
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// Vault lower-cases a policy name and trims its spaces before it looks the
// policy up, and stores kubernetes roles lower-cased: "Ext-Template" and
// " ext-template " name the same object as "ext-template". Every ownership
// comparison must see them as one name, in audit and in enforce alike.
var _ = Describe("Ownership compares names the way Vault resolves them", func() {
	for _, mode := range []policyguard.Mode{policyguard.ModeAudit, policyguard.ModeEnforce} {
		Context("policy guard "+string(mode), func() {
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
					PolicyGuard:   mode,
					Ownership: OwnershipPolicy{
						ReservedPolicyNames: []string{"vault-operator-admin"},
						ExternalPolicyNames: []string{"registry-guest", "ext-template"},
						ReservedRoleNames:   []string{"metrics-reader"},
					},
				}
			})

			for _, ref := range []string{"Vault-Operator-Admin", " vault-operator-admin ", "DEFAULT"} {
				It("a role referencing reserved policy "+ref+" is refused", func() {
					name := nextClaimName()
					cfg, sec := fixture(name)
					createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p", ref))))
					_, err := reconcileClaim(recon, name)
					Expect(err).NotTo(HaveOccurred())
					Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonPolicyReferenceForbidden))
					Expect(fakeVC.PutRoleCalls).To(Equal(0))
				})
			}

			for _, declared := range []string{"Ext-Template", " ext-template", "Vault-Operator-Admin"} {
				It("declaring protected policy "+declared+" is refused before any write", func() {
					name := nextClaimName()
					cfg, sec := fixture(name)
					createClaim(newClaim(name, cfg, sec, withPolicies(policy(declared, ownRules(name)))))
					_, err := reconcileClaim(recon, name)
					Expect(err).NotTo(HaveOccurred())
					Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
					Expect(fakeVC.PutPolicyCalls).To(Equal(0))
				})
			}

			It("protected names in the ledger in another case are never deleted", func() {
				name := nextClaimName()
				cfg, sec := fixture(name)
				c := newClaim(name, cfg, sec)
				createClaim(c)
				c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"Ext-Template", "Vault-Operator-Admin", name + "-gone"}}
				Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeVC.DeletedPolicies).To(Equal([]string{name + "-gone"}))
			})

			It("a name another claim holds, in the ledger in another case, is never deleted", func() {
				holder, name := nextClaimName(), nextClaimName()
				cfgH, secH := fixture(holder)
				cfg, sec := fixture(name)
				createClaim(newClaim(holder, cfgH, secH, withPolicies(policy(holder+"-shared", ownRules(holder)))))
				c := newClaim(name, cfg, sec)
				createClaim(c)
				c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"Claim-" + holder[len("claim-"):] + "-Shared"}}
				Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeVC.DeletedPolicies).To(BeEmpty())
			})

			It("a policy renamed only by case is written, not deleted", func() {
				name := nextClaimName()
				cfg, sec := fixture(name)
				c := newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))))
				createClaim(c)
				c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"Claim-" + name[len("claim-"):] + "-P"}}
				Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeVC.WrittenPolicies).To(HaveKey(name + "-p"))
				Expect(fakeVC.DeletedPolicies).To(BeEmpty())
				Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			})

			It("a reserved role on the operator mount in another case is refused", func() {
				name := nextClaimName()
				cfg, _ := fixture(name)
				fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{operatorMount + "/": {Type: "kubernetes", Description: "operator mount"}}
				fakeVC.AuthConfigs = map[string]vault.KubernetesAuthConfig{operatorMount: {KubernetesHost: "https://mgmt.invalid"}}
				createClaim(newClaim(name, cfg, "", asGuest(operatorMount), withRoles(role("Metrics-Reader", "registry-guest"), role("Vault-Operator", "registry-guest"))))
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonOwnershipConflict))
				Expect(fakeVC.PutRoleCalls).To(Equal(0))
			})

			It("the younger claim declaring an elder's policy in another case is refused", func() {
				elder, younger := nextClaimName(), nextClaimName()
				cfgE, secE := fixture(elder)
				cfgY, secY := fixture(younger)
				createClaim(newClaim(elder, cfgE, secE, withPolicies(policy("shared-x", ownRules(elder)))))
				time.Sleep(1100 * time.Millisecond) // creationTimestamp has one-second resolution
				createClaim(newClaim(younger, cfgY, secY, withPolicies(policy("Shared-X", ownRules(younger)))))
				_, err := reconcileClaim(recon, younger)
				Expect(err).NotTo(HaveOccurred())
				Expect(reasonOf(claimNamed(younger), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
				Expect(fakeVC.PutPolicyCalls).To(Equal(0))
			})

			It("a reference to the claim's own policy in another case is its own", func() {
				name := nextClaimName()
				cfg, sec := fixture(name)
				createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))),
					withRoles(role(name+"-r", "Claim-"+name[len("claim-"):]+"-P"))))
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				got := claimNamed(name)
				Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady), "conditions: %+v", got.Status.Conditions)
				Expect(fakeVC.WrittenRoles).To(HaveKey(name + "-r"))
			})

			It("twin: own lower-case names are written", func() {
				name := nextClaimName()
				cfg, sec := fixture(name)
				createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))),
					withRoles(role(name+"-r", name+"-p", "registry-guest"))))
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				got := claimNamed(name)
				Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady), "conditions: %+v", got.Status.Conditions)
				Expect(fakeVC.WrittenPolicies).To(HaveKey(name + "-p"))
				Expect(fakeVC.WrittenRoles).To(HaveKey(name + "-r"))
			})
		})
	}
})
