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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// operatorMount is the manager-auth mount makeHealthyVaultConfig declares.
const operatorMount = "kubernetes-mgmt"

// ownMountInfo is what sys/auth reports for a mount the operator created for
// the claim: the literal is repeated here on purpose, so a change of the
// production description cannot pass unnoticed.
func ownMountInfo(name string) vault.AuthMountInfo {
	return vault.AuthMountInfo{Type: "kubernetes", Accessor: "auth_kubernetes_" + name,
		Description: "vault-operator: per-cluster auth for " + vcNS + "/" + name}
}

type claimOpt func(*vaultv1alpha1.VaultClaim)

func withPolicies(p ...vaultv1alpha1.PolicySpec) claimOpt {
	return func(c *vaultv1alpha1.VaultClaim) { c.Spec.Policies = p }
}

func withRoles(r ...vaultv1alpha1.RoleSpec) claimOpt {
	return func(c *vaultv1alpha1.VaultClaim) { c.Spec.Roles = r }
}

func asGuest(mount string) claimOpt {
	return func(c *vaultv1alpha1.VaultClaim) {
		c.Spec.Auth = vaultv1alpha1.AuthSpec{
			MountPath:    mount,
			AutoCreate:   ptr.To(false),
			ManageConfig: ptr.To(false),
			RolePruning:  vaultv1alpha1.RolePruningOwned,
		}
		c.Spec.ClusterRef = vaultv1alpha1.ClusterRef{}
	}
}

func withTransitKey(name string) claimOpt {
	return func(c *vaultv1alpha1.VaultClaim) {
		c.Spec.Transit = &vaultv1alpha1.TransitSpec{MountPath: "transit", Keys: []vaultv1alpha1.TransitKeySpec{hardenedKey(name)}}
	}
}

func policy(name, rules string) vaultv1alpha1.PolicySpec {
	return vaultv1alpha1.PolicySpec{Name: name, Rules: rules}
}

func role(name string, policies ...string) vaultv1alpha1.RoleSpec {
	return vaultv1alpha1.RoleSpec{Name: name, BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "sa", Namespace: "ns"}, Policies: policies}
}

// ownRules is a policy body inside the claim's own KV prefix.
func ownRules(name string) string {
	return `path "secret/data/clusters/` + name + `/*" { capabilities = ["read"] }`
}

func newClaim(name, configName, secretName string, opts ...claimOpt) *vaultv1alpha1.VaultClaim {
	c := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
			SecretsPrefix:  "clusters/" + name,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath:  "kubernetes-" + name,
				AutoCreate: ptr.To(true),
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "vault-system", Name: "vault-token-reviewer", AutoCreate: true},
					TTL:            metav1.Duration{Duration: 24 * time.Hour},
				},
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func createClaim(c *vaultv1alpha1.VaultClaim) {
	Expect(k8sClient.Create(context.Background(), c)).To(Succeed())
	DeferCleanup(func() {
		fresh := &vaultv1alpha1.VaultClaim{}
		if err := k8sClient.Get(context.Background(), client.ObjectKeyFromObject(c), fresh); err == nil {
			fresh.Finalizers = nil
			_ = k8sClient.Update(context.Background(), fresh)
			_ = k8sClient.Delete(context.Background(), fresh)
		}
	})
}

func fixture(name string) (configName, secretName string) {
	configName, secretName = "cfg-"+name, name+"-kc"
	makeHealthyVaultConfig(context.Background(), configName)
	DeferCleanup(func() {
		_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
	})
	makeKubeconfigSecret(context.Background(), secretName, true)
	DeferCleanup(func() {
		_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
	})
	return configName, secretName
}

func claimNamed(name string) *vaultv1alpha1.VaultClaim {
	c := &vaultv1alpha1.VaultClaim{}
	Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, c)).To(Succeed())
	return c
}

func conditionOf(c *vaultv1alpha1.VaultClaim, t string) *metav1.Condition {
	return findCondition(c.Status.Conditions, t)
}

// reasonOf returns the condition's reason, or "<absent>" so a missing
// condition fails the assertion with a readable value instead of a panic.
func reasonOf(c *vaultv1alpha1.VaultClaim, t string) string {
	if cond := conditionOf(c, t); cond != nil {
		return cond.Reason
	}
	return "<absent>"
}

func deleteAndReconcile(r *VaultClaimReconciler, name string) {
	Expect(k8sClient.Delete(context.Background(), claimNamed(name))).To(Succeed())
	_, err := reconcileClaim(r, name)
	Expect(err).NotTo(HaveOccurred())
	Eventually(func() bool {
		err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
		return apierrors.IsNotFound(err)
	}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
}

// watchClient is a second envtest client; interceptor.NewClient needs a
// client.WithWatch, which the shared k8sClient is not.
func watchClient() client.WithWatch {
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
	Expect(err).NotTo(HaveOccurred())
	return c
}

func drainEvents(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

var _ = Describe("VaultClaim ledger, ownership and guest mode", func() {
	var (
		recon      *VaultClaimReconciler
		fakeVC     *fakeVaultClient
		fakeTarget *target.FakeManager
		recorder   *record.FakeRecorder
		fixedNow   time.Time
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		fixedNow = time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		fakeTarget = &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", fixedNow.Add(24*time.Hour))}
		recorder = record.NewFakeRecorder(500)
		recon = &VaultClaimReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			Recorder:      recorder,
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: fakeTarget,
			Now:           func() time.Time { return fixedNow },
			Ownership: OwnershipPolicy{
				ReservedPolicyNames: []string{"vault-operator-admin"},
				ExternalPolicyNames: []string{"registry-guest"},
				ReservedRoleNames:   []string{"metrics-reader"},
			},
		}
	})

	Describe("V1: deletion by ledger", func() {
		It("Owned keeps a role it never wrote; drift does not report it", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			c := newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p")))
			c.Spec.Auth.RolePruning = vaultv1alpha1.RolePruningOwned
			createClaim(c)
			fakeVC.ListRolesResp = []string{name + "-r", "zot-1"}

			for i := 0; i < 2; i++ {
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(fakeVC.DeletedRoles).NotTo(ContainElement("zot-1"))
			Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

			report, err := recon.detectDrift(context.Background(), fakeVC, claimNamed(name))
			Expect(err).NotTo(HaveOccurred())
			Expect(report.ExtraRoles).To(BeEmpty())
		})

		It("spec [a,b] → [c]: a and b are deleted after c is written, roles before policies", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			c := newClaim(name, cfg, sec,
				withPolicies(policy(name+"-a", ownRules(name)), policy(name+"-b", ownRules(name))),
				withRoles(role(name+"-ra", name+"-a"), role(name+"-rb", name+"-b")))
			c.Spec.Auth.RolePruning = vaultv1alpha1.RolePruningOwned
			createClaim(c)
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(claimNamed(name).Status.Vault.AppliedPolicies).To(ConsistOf(name+"-a", name+"-b"))

			fresh := claimNamed(name)
			fresh.Spec.Policies = []vaultv1alpha1.PolicySpec{policy(name+"-c", ownRules(name))}
			fresh.Spec.Roles = []vaultv1alpha1.RoleSpec{role(name+"-rc", name+"-c")}
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
			fakeVC.Ops = nil
			_, err = reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeVC.WrittenPolicies).To(HaveKey(name + "-c"))
			Expect(fakeVC.WrittenPolicies).NotTo(HaveKey(name + "-a"))
			Expect(fakeVC.WrittenPolicies).NotTo(HaveKey(name + "-b"))
			Expect(fakeVC.WrittenRoles).NotTo(HaveKey(name + "-ra"))
			var objectOps []string
			for _, op := range fakeVC.Ops {
				if strings.HasPrefix(op, "put-") || strings.HasPrefix(op, "delete-") {
					objectOps = append(objectOps, op)
				}
			}
			Expect(objectOps).To(Equal([]string{
				"put-policy:" + name + "-c",
				"put-role:" + name + "-rc",
				"delete-role:" + name + "-ra", "delete-role:" + name + "-rb",
				"delete-policy:" + name + "-a", "delete-policy:" + name + "-b",
			}))
			got := claimNamed(name)
			Expect(got.Status.Vault.AppliedPolicies).To(Equal([]string{name + "-c"}))
			Expect(got.Status.Vault.AppliedRoles).To(Equal([]string{name + "-rc"}))
		})

		It("spec [] deletes every policy in the ledger", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-a", ownRules(name)), policy(name+"-b", ownRules(name)))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())

			fresh := claimNamed(name)
			fresh.Spec.Policies = nil
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
			_, err = reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeVC.DeletedPolicies).To(ConsistOf(name+"-a", name+"-b"))
			Expect(claimNamed(name).Status.Vault.AppliedPolicies).To(BeEmpty())
		})

		It("a reserved name in the ledger is never deleted; the claim's own name is", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			c := newClaim(name, cfg, sec, withPolicies(policy(name+"-keep", ownRules(name))))
			createClaim(c)
			c.Status.Vault = &vaultv1alpha1.VaultStatusSummary{AppliedPolicies: []string{"vault-operator-admin", name + "-gone", name + "-keep"}}
			Expect(k8sClient.Status().Update(context.Background(), c)).To(Succeed())
			fakeVC.WrittenPolicies = map[string]string{"vault-operator-admin": "operator body", name + "-gone": ownRules(name), name + "-keep": ownRules(name)}

			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeVC.DeletedPolicies).To(Equal([]string{name + "-gone"}))
			Expect(fakeVC.WrittenPolicies["vault-operator-admin"]).To(Equal("operator body"))
			Expect(claimNamed(name).Status.Vault.AppliedPolicies).To(Equal([]string{name + "-keep"}))
		})
	})

	Describe("V2: intent before the write", func() {
		It("a failed intent patch writes nothing to Vault", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name))), withRoles(role(name+"-r", name+"-p"))))
			failing := interceptor.NewClient(watchClient(), interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					return errors.New("injected status patch failure")
				},
			})
			recon.Client = failing

			_, _ = reconcileClaim(recon, name)
			Expect(fakeVC.EnableAuthCalls).To(Equal(0))
			Expect(fakeVC.PutPolicyCalls).To(Equal(0))
			Expect(fakeVC.PutRoleCalls).To(Equal(0))
		})

		// The mount already carries this claim's description, so the first
		// ledger write of the pass is the one before the policy or role write:
		// each write must wait for its own entry.
		It("a failed intent patch before policies writes no policy", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name)))))
			fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": ownMountInfo(name)}
			recon.Client = interceptor.NewClient(watchClient(), interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					return errors.New("injected status patch failure")
				},
			})
			_, _ = reconcileClaim(recon, name)
			Expect(fakeVC.WriteConfigCalls).To(Equal(1), "the pass reached the policy step")
			Expect(fakeVC.PutPolicyCalls).To(Equal(0))
		})

		It("a failed intent patch before roles writes no role", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withRoles(role(name+"-r", "registry-guest"))))
			fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": ownMountInfo(name)}
			recon.Client = interceptor.NewClient(watchClient(), interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					return errors.New("injected status patch failure")
				},
			})
			_, _ = reconcileClaim(recon, name)
			Expect(fakeVC.WriteConfigCalls).To(Equal(1), "the pass reached the role step")
			Expect(fakeVC.PutRoleCalls).To(Equal(0))
		})

		It("a final status patch failure is returned, not swallowed", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec))
			calls := 0
			recon.Client = interceptor.NewClient(watchClient(), interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					calls++
					if calls == 1 {
						return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
					}
					return errors.New("injected final patch failure")
				},
			})
			_, err := reconcileClaim(recon, name)
			Expect(err).To(HaveOccurred())
		})

		It("a policy already in Vault and not in the ledger is refused and kept byte for byte", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name)))))
			fakeVC.WrittenPolicies = map[string]string{name + "-p": "foreign body"}

			for i := 0; i < 3; i++ {
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(fakeVC.WrittenPolicies[name+"-p"]).To(Equal("foreign body"))
			got := claimNamed(name)
			Expect(got.Status.Phase).NotTo(Equal(vaultv1alpha1.PhaseReady))
			Expect(reasonOf(got, vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(got.Status.Vault.AppliedPolicies).NotTo(ContainElement(name + "-p"))

			deleteAndReconcile(recon, name)
			Expect(fakeVC.WrittenPolicies[name+"-p"]).To(Equal("foreign body"))
		})

		It("POST sys/auth answering 400 for a mount with a foreign description is a conflict, not ownership", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec))
			fakeVC.EnableAuthErr = &vault.APIError{Method: "POST", Path: "/v1/sys/auth/kubernetes-" + name, StatusCode: 400, Errors: []string{"path is already in use"}}
			fakeVC.OnEnableAuth = func(f *fakeVaultClient) {
				f.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": {Type: "kubernetes", Description: "someone else"}}
			}

			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			got := claimNamed(name)
			Expect(reasonOf(got, vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
			Expect(got.Status.Vault.AuthMountOwned).To(BeFalse())
			Expect(fakeVC.WriteConfigCalls).To(Equal(0))
		})

		It("deletion removes only ledger names, never a spec name the claim was refused", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", ownRules(name)))))
			fakeVC.WrittenPolicies = map[string]string{name + "-p": "foreign body"}
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())

			deleteAndReconcile(recon, name)
			Expect(fakeVC.DeletedPolicies).NotTo(ContainElement(name + "-p"))
		})
	})

	Describe("V3: names have one owner", func() {
		It("the younger of two claims with one policy name is refused; deleting it keeps the policy", func() {
			elder, younger := nextClaimName(), nextClaimName()
			cfgE, secE := fixture(elder)
			cfgY, secY := fixture(younger)
			createClaim(newClaim(elder, cfgE, secE, withPolicies(policy("shared-p", ownRules(elder)))))
			_, err := reconcileClaim(recon, elder)
			Expect(err).NotTo(HaveOccurred())
			Expect(claimNamed(elder).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

			time.Sleep(1100 * time.Millisecond) // creationTimestamp has one-second resolution
			createClaim(newClaim(younger, cfgY, secY, withPolicies(policy("shared-p", ownRules(younger)))))
			_, err = reconcileClaim(recon, younger)
			Expect(err).NotTo(HaveOccurred())
			got := claimNamed(younger)
			Expect(reasonOf(got, vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.WrittenPolicies["shared-p"]).To(Equal(ownRules(elder)))

			deleteAndReconcile(recon, younger)
			Expect(fakeVC.DeletedPolicies).NotTo(ContainElement("shared-p"))
			Expect(fakeVC.WrittenPolicies["shared-p"]).To(Equal(ownRules(elder)))
		})

		It("an owner claim on an operator mount is refused before any Vault write", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			c := newClaim(name, cfg, sec, withRoles(role(name+"-r", name+"-p")), withPolicies(policy(name+"-p", ownRules(name))))
			c.Spec.Auth.MountPath = operatorMount
			createClaim(c)
			fakeVC.ListRolesResp = []string{"vault-operator", "s3-bucket-operator", "vault-secret-operator"}

			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
			Expect(fakeVC.Ops).To(BeEmpty())
		})

		It("a reserved policy name is refused; the twin with an own name proceeds", func() {
			name, twin := nextClaimName(), nextClaimName()
			cfg, sec := fixture(name)
			cfgT, secT := fixture(twin)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy("vault-operator-admin", ownRules(name)))))
			createClaim(newClaim(twin, cfgT, secT, withPolicies(policy(twin+"-admin", ownRules(twin)))))
			for _, n := range []string{name, twin} {
				_, err := reconcileClaim(recon, n)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.WrittenPolicies).NotTo(HaveKey("vault-operator-admin"))
			Expect(claimNamed(twin).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		})

		It("a role referencing a reserved policy is refused even in audit mode", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withRoles(role(name+"-r", "vault-operator-admin"))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonPolicyReferenceForbidden))
			Expect(fakeVC.PutRoleCalls).To(Equal(0))
		})

		It("a role referencing an undeclared policy is refused under enforce; the external allow-list passes", func() {
			recon.PolicyGuard = policyguard.ModeEnforce
			name, twin := nextClaimName(), nextClaimName()
			cfg, sec := fixture(name)
			cfgT, secT := fixture(twin)
			createClaim(newClaim(name, cfg, sec, withRoles(role(name+"-r", "someone-elses-policy"))))
			createClaim(newClaim(twin, cfgT, secT, withRoles(role(twin+"-r", "registry-guest"))))
			for _, n := range []string{name, twin} {
				_, err := reconcileClaim(recon, n)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonPolicyReferenceForbidden))
			Expect(fakeVC.WrittenRoles).NotTo(HaveKey(name + "-r"))
			Expect(claimNamed(twin).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(fakeVC.WrittenRoles).To(HaveKey(twin + "-r"))
		})

		It("the younger of two claims with one transit key is refused and never configures it", func() {
			elder, younger := nextClaimName(), nextClaimName()
			cfgE, secE := fixture(elder)
			cfgY, secY := fixture(younger)
			fakeVC.MountExistsResp = map[string]bool{"transit": true}
			createClaim(newClaim(elder, cfgE, secE, withTransitKey("shared-key")))
			_, err := reconcileClaim(recon, elder)
			Expect(err).NotTo(HaveOccurred())
			Expect(claimNamed(elder).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

			time.Sleep(1100 * time.Millisecond)
			c := newClaim(younger, cfgY, secY, withTransitKey("shared-key"))
			c.Spec.Transit.Keys[0].Exportable = true
			createClaim(c)
			before := fakeVC.UpdateTransitCfgCalls
			_, err = reconcileClaim(recon, younger)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(younger), vaultv1alpha1.ConditionTransitKeysReady)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.UpdateTransitCfgCalls).To(Equal(before))
			Expect(fakeVC.TransitKeys["transit/shared-key"].Exportable).To(BeFalse())
		})

		It("an adopted key is never made exportable", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			fakeVC.MountExistsResp = map[string]bool{"transit": true}
			fakeVC.TransitKeys = map[string]*vault.TransitKey{"transit/platform-key": {Name: "platform-key", Type: "aes256-gcm96", LatestVersion: 3}}
			c := newClaim(name, cfg, sec, withTransitKey("platform-key"))
			c.Spec.Transit.Keys[0].Exportable = true
			createClaim(c)
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeVC.TransitKeys["transit/platform-key"].Exportable).To(BeFalse())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionTransitKeysReady)).To(Equal("KeyAdoptionRestricted"))
		})

		It("overlapping secretsPrefix is refused for the younger claim", func() {
			elder, younger := nextClaimName(), nextClaimName()
			cfgE, secE := fixture(elder)
			cfgY, secY := fixture(younger)
			createClaim(newClaim(elder, cfgE, secE))
			_, err := reconcileClaim(recon, elder)
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(1100 * time.Millisecond)
			c := newClaim(younger, cfgY, secY)
			c.Spec.SecretsPrefix = "clusters/" + elder + "/nested"
			createClaim(c)
			_, err = reconcileClaim(recon, younger)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(younger), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.opsWithPrefix("enable-auth:kubernetes-" + younger)).To(BeEmpty())
		})
	})

	Describe("V4: guest claims", func() {
		guestMount := func() {
			fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{operatorMount + "/": {Type: "kubernetes", Accessor: "auth_kubernetes_mgmt", Description: "operator mount"}}
			fakeVC.AuthConfigs = map[string]vault.KubernetesAuthConfig{operatorMount: {KubernetesHost: "https://mgmt.invalid", TokenReviewerJWT: "owner-jwt"}}
		}

		It("a guest never writes the mount or touches the target cluster, and keeps operator roles", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			guestMount()
			fakeVC.ListRolesResp = []string{"vault-operator", "s3-bucket-operator", "vault-secret-operator"}
			fakeVC.WrittenRoles = map[string]vault.KubernetesRole{"s3-bucket-operator": {TokenPolicies: []string{"s3-bucket-operator"}}}
			createClaim(newClaim(name, cfg, "", asGuest(operatorMount),
				withPolicies(policy(name+"-read", ownRules(name))), withRoles(role("zot-"+name, name+"-read", "registry-guest"))))

			for i := 0; i < 3; i++ {
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
			}
			got := claimNamed(name)
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			Expect(fakeVC.EnableAuthCalls + fakeVC.DisableAuthCalls + fakeVC.WriteConfigCalls).To(Equal(0))
			Expect(fakeTarget.GetCalls).To(Equal(0))
			Expect(fakeVC.DeletedRoles).To(BeEmpty())
			Expect(fakeVC.WrittenRoles).To(HaveKey("zot-" + name))

			deleteAndReconcile(recon, name)
			Expect(fakeVC.DeletedRoles).To(Equal([]string{"zot-" + name}))
			Expect(fakeVC.DisableAuthCalls).To(Equal(0))
			Expect(fakeVC.WrittenRoles["s3-bucket-operator"].TokenPolicies).To(Equal([]string{"s3-bucket-operator"}))
			Expect(fakeTarget.GetCalls).To(Equal(0))
		})

		It("a guest role that already exists on the mount is refused byte for byte", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			guestMount()
			fakeVC.WrittenRoles = map[string]vault.KubernetesRole{"s3-bucket-operator": {TokenPolicies: []string{"s3-bucket-operator"}}}
			createClaim(newClaim(name, cfg, "", asGuest(operatorMount),
				withPolicies(policy(name+"-read", ownRules(name))), withRoles(role("s3-bucket-operator", name+"-read"))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.WrittenRoles["s3-bucket-operator"].TokenPolicies).To(Equal([]string{"s3-bucket-operator"}))
		})

		It("a reserved role name on the operator mount is refused", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			guestMount()
			createClaim(newClaim(name, cfg, "", asGuest(operatorMount), withRoles(role("metrics-reader", "registry-guest"))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionRolesApplied)).To(Equal(ReasonOwnershipConflict))
			Expect(fakeVC.PutRoleCalls).To(Equal(0))
		})

		It("a guest waits while its host mount has no kubernetes_host", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{operatorMount + "/": {Type: "kubernetes"}}
			createClaim(newClaim(name, cfg, "", asGuest(operatorMount), withRoles(role("zot-"+name, "registry-guest"))))
			res, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RequeueAfter).To(BeNumerically(">", 0))
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountNotConfigured))
			Expect(fakeVC.PutRoleCalls).To(Equal(0))
		})

		It("a guest on a mount that is neither an operator mount nor allow-listed is refused", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			createClaim(newClaim(name, cfg, "", asGuest("kubernetes-someone"), withRoles(role("zot-"+name, "registry-guest"))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
			Expect(fakeVC.Ops).To(BeEmpty())
		})

		It("a guest's policies are judged in enforce mode even when the operator runs audit", func() {
			name := nextClaimName()
			cfg, _ := fixture(name)
			guestMount()
			createClaim(newClaim(name, cfg, "", asGuest(operatorMount),
				withPolicies(policy(name+"-read", `path "sys/policies/acl/*" { capabilities = ["update"] }`)), withRoles(role("zot-"+name, name+"-read"))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonPolicyGuardViolation))
			Expect(fakeVC.PutPolicyCalls).To(Equal(0))
		})

		It("a claim that waited on its kubeconfig does not adopt a foreign mount", func() {
			name := nextClaimName()
			cfg := "cfg-" + name
			makeHealthyVaultConfig(context.Background(), cfg)
			DeferCleanup(func() {
				_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: cfg}})
			})
			fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": {Type: "kubernetes", Description: "created by hand"}}
			createClaim(newClaim(name, cfg, name+"-kc"))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			waited := claimNamed(name)
			Expect(reasonOf(waited, vaultv1alpha1.ConditionKubeconfigAvailable)).To(Equal("NotFound"))
			// The wait records no mount: a record is what accepts one.
			Expect(waited.Status.Vault.AuthMountPath).To(BeEmpty())

			makeKubeconfigSecret(context.Background(), name+"-kc", true)
			DeferCleanup(func() {
				_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-kc", Namespace: vcNS}})
			})
			_, err = reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionAuthMountReady)).To(Equal(ReasonMountConflict))
			Expect(fakeVC.WriteConfigCalls).To(Equal(0))

			deleteAndReconcile(recon, name)
			Expect(fakeVC.DisableAuthCalls).To(Equal(0))
			Expect(strings.Join(drainEvents(recorder), "\n")).To(ContainSubstring(ReasonMountNotOwned))
		})

		It("the CRD enforces the guest shape and keeps manageConfig immutable", func() {
			name := nextClaimName()
			c := newClaim(name, "cfg", "", asGuest(operatorMount))
			c.Spec.Auth.AutoCreate = ptr.To(true)
			Expect(k8sClient.Create(context.Background(), c)).NotTo(Succeed())

			c = newClaim(name, "cfg", "", asGuest(operatorMount))
			c.Spec.Auth.RolePruning = vaultv1alpha1.RolePruningExclusive
			Expect(k8sClient.Create(context.Background(), c)).NotTo(Succeed())

			c = newClaim(name, "cfg", "")
			c.Spec.ClusterRef = vaultv1alpha1.ClusterRef{}
			Expect(k8sClient.Create(context.Background(), c)).NotTo(Succeed(), "an owner claim needs clusterRef")

			c = newClaim(name, "cfg", "")
			c.Spec.Auth.TokenReviewer = vaultv1alpha1.TokenReviewerSpec{}
			Expect(k8sClient.Create(context.Background(), c)).NotTo(Succeed(), "an owner claim needs tokenReviewer")

			guest := newClaim(name, "cfg", "", asGuest(operatorMount))
			createClaim(guest)
			fresh := claimNamed(name)
			fresh.Spec.Auth.ManageConfig = ptr.To(true)
			Expect(k8sClient.Update(context.Background(), fresh)).NotTo(Succeed())

			owner := nextClaimName()
			createClaim(newClaim(owner, "cfg", ""))
			got := claimNamed(owner)
			Expect(got.Spec.Auth.ManagesConfig()).To(BeTrue(), "existing objects default to owner")
			Expect(got.Spec.Auth.RolePruningMode()).To(Equal(vaultv1alpha1.RolePruningExclusive))
		})
	})

	Describe("V5: policy guard", func() {
		It("enforce refuses a policy outside the claim and writes nothing; the twin is written", func() {
			recon.PolicyGuard = policyguard.ModeEnforce
			name, twin := nextClaimName(), nextClaimName()
			cfg, sec := fixture(name)
			cfgT, secT := fixture(twin)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", `path "sys/policies/acl/x" { capabilities = ["update"] }`))))
			createClaim(newClaim(twin, cfgT, secT, withPolicies(policy(twin+"-p", ownRules(twin)))))
			for _, n := range []string{name, twin} {
				_, err := reconcileClaim(recon, n)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(reasonOf(claimNamed(name), vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(ReasonPolicyGuardViolation))
			Expect(fakeVC.WrittenPolicies).NotTo(HaveKey(name + "-p"))
			Expect(claimNamed(name).Status.Vault.AppliedPolicies).NotTo(ContainElement(name + "-p"))
			Expect(fakeVC.WrittenPolicies).To(HaveKey(twin + "-p"))
		})

		It("audit writes the policy and reports the violation", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", `path "sys/policies/acl/x" { capabilities = ["update"] }`))))
			_, err := reconcileClaim(recon, name)
			Expect(err).NotTo(HaveOccurred())
			Expect(fakeVC.WrittenPolicies).To(HaveKey(name + "-p"))
			Expect(strings.Join(drainEvents(recorder), "\n")).To(ContainSubstring(ReasonPolicyGuardViolation))
		})
	})

	Describe("V13: closed failure texts", func() {
		hungVault := func(timeout time.Duration) error {
			srv := newHungServer()
			DeferCleanup(srv.Close)
			c, err := vault.New(vault.Config{Address: srv.URL, AuthPath: "kubernetes-mgmt", Role: "vault-operator",
				JWTSource: vault.StaticJWTSource("jwt"), Timeout: timeout})
			Expect(err).NotTo(HaveOccurred())
			ctx := context.Background()
			if timeout == 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
				defer cancel()
			}
			loginErr := c.Login(ctx)
			Expect(loginErr).To(HaveOccurred())
			return loginErr
		}

		It("both real timeout texts give one reason and one message without an address", func() {
			var messages []string
			for _, loginErr := range []error{hungVault(200 * time.Millisecond), hungVault(0)} {
				name := nextClaimName()
				cfg, sec := fixture(name)
				createClaim(newClaim(name, cfg, sec))
				fakeVC.LoginErr = loginErr
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				cond := conditionOf(claimNamed(name), vaultv1alpha1.ConditionVaultReachable)
				Expect(cond).NotTo(BeNil())
				Expect(cond.Reason).To(Equal(ReasonLoginFailed))
				Expect(cond.Message).To(Equal("Vault login failed: the remote endpoint did not answer in time"))
				messages = append(messages, cond.Message)
				for _, e := range drainEvents(recorder) {
					Expect(e).NotTo(ContainSubstring("127.0.0.1"))
				}
			}
			Expect(messages[0]).To(Equal(messages[1]))
			Expect(messages[0]).NotTo(ContainSubstring("127.0.0.1"))
		})

		It("the Ready event is emitted on the transition only", func() {
			name := nextClaimName()
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec))
			// Each pass follows a spec change, so each one is a full pass that
			// ends Ready; only the first is a transition into Ready.
			for i := 0; i < 3; i++ {
				fresh := claimNamed(name)
				fresh.Spec.Policies = append(fresh.Spec.Policies, policy(fmt.Sprintf("%s-p%d", name, i), ownRules(name)))
				Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
				_, err := reconcileClaim(recon, name)
				Expect(err).NotTo(HaveOccurred())
				Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
			}
			ready := 0
			for _, e := range drainEvents(recorder) {
				if strings.Contains(e, "VaultClaimReady") {
					ready++
				}
			}
			Expect(ready).To(Equal(1))
		})
	})
})

type hungServer struct {
	*httptest.Server
	release chan struct{}
}

// newHungServer accepts connections and never answers, like a Vault behind a
// dead load balancer.
func newHungServer() *hungServer {
	h := &hungServer{release: make(chan struct{})}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-h.release:
		case <-r.Context().Done():
		}
	}))
	return h
}

func (h *hungServer) Close() {
	close(h.release)
	h.Server.Close()
}
