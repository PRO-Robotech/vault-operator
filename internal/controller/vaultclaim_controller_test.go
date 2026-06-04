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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
	"github.com/PRO-Robotech/vault-operator/internal/vault"

	"k8s.io/client-go/kubernetes/fake"
)

const (
	vcNS        = "default"
	kubeKey     = "value"
	stubKubecfg = `apiVersion: v1
kind: Config
clusters:
- cluster: {server: https://example.invalid:6443, insecure-skip-tls-verify: true}
  name: t
contexts:
- context: {cluster: t, user: u}
  name: t
current-context: t
users:
- name: u
  user: {token: bogus}
`
)

var claimCounter int

func nextClaimName() string {
	claimCounter++
	return fmt.Sprintf("claim-%d", claimCounter)
}

func reconcileClaim(r *VaultClaimReconciler, name string) (reconcile.Result, error) {
	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: vcNS},
	})
}

// newTargetClientSetWithReactor builds a target.ClientSet whose components
// satisfy what Steps 3 + 4 need:
//   - Client: controller-runtime fake with SSA support (v0.22+).
//   - Kubernetes: client-go fake with a CreateToken reactor returning the
//     supplied token + expiration.
func newTargetClientSetWithReactor(scheme *runtime.Scheme, token string, expiresAt time.Time) *target.ClientSet {
	cr := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
	kc := fake.NewClientset()
	kc.PrependReactor("create", "serviceaccounts/token", func(action ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(ktesting.CreateAction)
		if !ok {
			return false, nil, errors.New("unexpected action type")
		}
		tr, ok := ca.GetObject().(*authenticationv1.TokenRequest)
		if !ok {
			return false, nil, errors.New("unexpected object type")
		}
		out := tr.DeepCopy()
		out.Status.Token = token
		out.Status.ExpirationTimestamp = metav1.NewTime(expiresAt)
		return true, out, nil
	})
	return &target.ClientSet{Client: cr, Kubernetes: kc}
}

// makeHealthyVaultConfig creates a VaultConfig in envtest and primes its
// status with Reachable+SharedMountFound=True so Step 1 proceeds. Returns the
// VaultConfig name.
func makeHealthyVaultConfig(ctx context.Context, name string) {
	vc := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address: "https://vault.example",
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
				Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-operator",
			},
			Storage: vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
		},
	}
	Expect(k8sClient.Create(ctx, vc)).To(Succeed())
	// Status subresource update.
	vc.Status.Conditions = []metav1.Condition{
		{Type: vaultv1alpha1.ConditionReachable, Status: metav1.ConditionTrue, Reason: "Ok", LastTransitionTime: metav1.Now()},
		{Type: vaultv1alpha1.ConditionSharedMountFound, Status: metav1.ConditionTrue, Reason: "Found", LastTransitionTime: metav1.Now()},
	}
	Expect(k8sClient.Status().Update(ctx, vc)).To(Succeed())
}

func makeUnhealthyVaultConfig(ctx context.Context, name string, reachable bool) {
	vc := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address:     "https://vault.example",
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: "kubernetes-mgmt", Role: "vault-operator"},
			Storage:     vaultv1alpha1.StorageSpec{KvMountPath: "secret"},
		},
	}
	Expect(k8sClient.Create(ctx, vc)).To(Succeed())
	st := metav1.ConditionFalse
	if reachable {
		st = metav1.ConditionTrue
	}
	vc.Status.Conditions = []metav1.Condition{
		{Type: vaultv1alpha1.ConditionReachable, Status: st, Reason: "Test", LastTransitionTime: metav1.Now()},
		{Type: vaultv1alpha1.ConditionSharedMountFound, Status: metav1.ConditionFalse, Reason: "Test", LastTransitionTime: metav1.Now()},
	}
	Expect(k8sClient.Status().Update(ctx, vc)).To(Succeed())
}

func makeKubeconfigSecret(ctx context.Context, name string, withValue bool) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
		Data:       map[string][]byte{},
	}
	if withValue {
		s.Data[kubeKey] = []byte(stubKubecfg)
	} else {
		s.Data["other"] = []byte("x")
	}
	Expect(k8sClient.Create(ctx, s)).To(Succeed())
}

func makeVaultClaim(ctx context.Context, name, configName, secretName string) *vaultv1alpha1.VaultClaim {
	claim := &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
			SecretsPrefix:  "clusters/" + name,
			Auth: vaultv1alpha1.AuthSpec{
				MountPath:  "kubernetes-" + name,
				AutoCreate: true,
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{
						Namespace:  "beget-vault-system",
						Name:       "vault-token-reviewer",
						AutoCreate: true,
					},
					TTL: metav1.Duration{Duration: 24 * time.Hour},
				},
			},
		},
	}
	Expect(k8sClient.Create(ctx, claim)).To(Succeed())
	return claim
}

// targetScheme is the scheme used by per-test target.ClientSet fakes — it
// only needs the core APIs we apply (NS/SA/CRB).
func targetScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(s)).To(Succeed())
	return s
}

var _ = Describe("VaultClaim Controller — Steps 1-4", func() {
	var (
		recon       *VaultClaimReconciler
		fakeVC      *fakeVaultClient
		fakeTarget  *target.FakeManager
		targetCS    *target.ClientSet
		fixedNow    time.Time
		issuedToken string
	)

	BeforeEach(func() {
		fakeVC = &fakeVaultClient{SharedMountResp: true}
		fixedNow = time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		issuedToken = "issued-reviewer-jwt"
		targetCS = newTargetClientSetWithReactor(targetScheme(), issuedToken, fixedNow.Add(24*time.Hour))
		fakeTarget = &target.FakeManager{Set: targetCS}
		recon = &VaultClaimReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: fakeTarget,
			Now:           func() time.Time { return fixedNow },
		}
	})

	getClaim := func(name string) *vaultv1alpha1.VaultClaim {
		c := &vaultv1alpha1.VaultClaim{}
		Expect(k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, c)).To(Succeed())
		return c
	}

	It("happy path: all seven steps succeed, Phase=Ready, all conditions True", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		res, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueClaimDriftReady))

		got := getClaim(name)
		Expect(got.Finalizers).To(ContainElement(vaultv1alpha1.VaultClaimFinalizer))
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionConfigResolved)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionVaultReachable)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionRolesApplied)).To(BeTrue())
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReady)).To(BeTrue())

		Expect(got.Status.Vault).NotTo(BeNil())
		Expect(got.Status.Vault.ConfigName).To(Equal(configName))
		Expect(got.Status.Vault.AuthMountPath).To(Equal("kubernetes-" + name))
		Expect(got.Status.Vault.SecretsPrefix).To(Equal("clusters/" + name))
		Expect(got.Status.Vault.TokenReviewerJWT).NotTo(BeNil())
		Expect(got.Status.Vault.TokenReviewerJWT.IssuedAt).NotTo(BeNil())
		Expect(got.Status.Vault.TokenReviewerJWT.ExpiresAt).NotTo(BeNil())
		Expect(got.Status.Vault.TokenReviewerJWT.LastRotated).NotTo(BeNil())
		Expect(got.Status.Vault.LastReconcileAt).NotTo(BeNil())

		// Vault.Login was called (Step 1 verifies token).
		Expect(fakeVC.LoginCalls).To(Equal(1))

		// Target SA + CRB were created in the (fake) target cluster.
		sa := &corev1.ServiceAccount{}
		Expect(targetCS.Client.Get(context.Background(), client.ObjectKey{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, sa)).To(Succeed())
		crb := &rbacv1.ClusterRoleBinding{}
		Expect(targetCS.Client.Get(context.Background(), client.ObjectKey{Name: "vault-token-reviewer" + target.CRBSuffix}, crb)).To(Succeed())

		// Step 5: auth method enabled and configured.
		Expect(fakeVC.EnableAuthCalls).To(Equal(1))
		Expect(fakeVC.EnabledAuthPaths).To(ContainElement("kubernetes-" + name))
		Expect(fakeVC.WriteConfigCalls).To(Equal(1))
		Expect(fakeVC.WrittenAuthCfgs).To(HaveLen(1))
		Expect(fakeVC.WrittenAuthCfgs[0].TokenReviewerJWT).To(Equal(issuedToken))
		Expect(fakeVC.WrittenAuthCfgs[0].DisableISSValidation).To(BeTrue()) // no spec issuer + fake discovery fails

		// Step 6/7 had no spec policies/roles → no-op but conditions set True.
		Expect(fakeVC.PutPolicyCalls).To(Equal(0))
		Expect(fakeVC.PutRoleCalls).To(Equal(0))
	})

	It("Step 5: idempotent when auth method already exists (400 from Vault)", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		fakeVC.EnableAuthErr = &vault.APIError{Method: "POST", Path: "/v1/sys/auth/kubernetes-" + name, StatusCode: 400, Errors: []string{"path is already in use"}}

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		got := getClaim(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionAuthMountReady)).To(BeTrue())
		Expect(fakeVC.WriteConfigCalls).To(Equal(1), "config write must still happen after 'already exists'")
	})

	It("Step 5: skips token_reviewer_jwt write when Step 4 didn't rotate", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Pre-populate status so Step 4 short-circuits (JWT is fresh).
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{
			TokenReviewerJWT: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(fixedNow.Add(-time.Hour)),
				ExpiresAt: ptrTime(fixedNow.Add(23 * time.Hour)),
			},
		}
		Expect(k8sClient.Status().Update(context.Background(), claim)).To(Succeed())

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Auth config still written but without JWT (existing one in Vault is fine).
		Expect(fakeVC.WriteConfigCalls).To(Equal(1))
		Expect(fakeVC.WrittenAuthCfgs[0].TokenReviewerJWT).To(BeEmpty())
		// And TokenRequest API was NOT called (kc actions empty).
		kc := targetCS.Kubernetes.(*fake.Clientset)
		Expect(kc.Actions()).To(BeEmpty())
	})

	It("Step 6: lazy accessor fetch when policy uses {{ .AuthMountAccessor }}", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		// Mint a claim with a templated policy AND a non-templated one to
		// prove that GetAuthMountAccessor is called exactly once.
		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath:  "kubernetes-" + name,
					AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{
							Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true,
						},
						TTL: metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Policies: []vaultv1alpha1.PolicySpec{
					{Name: name + "-static", Rules: `path "secret/data/clusters/x/*" { capabilities = ["read"] }`},
					{Name: name + "-templated", Rules: `path "secret/data/clusters/{{` + " .AuthMountAccessor " + `}}/*" { capabilities = ["read"] }`},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		fakeVC.AccessorResp = "auth_kubernetes_abc1234"

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		Expect(fakeVC.AccessorCalls).To(Equal(1), "accessor must be fetched exactly once (lazy)")
		Expect(fakeVC.PutPolicyCalls).To(Equal(2))
		// Templated policy got the accessor substituted.
		Expect(fakeVC.WrittenPolicies[name+"-templated"]).To(ContainSubstring("auth_kubernetes_abc1234"))
		// Static policy left intact.
		Expect(fakeVC.WrittenPolicies[name+"-static"]).To(ContainSubstring(`secret/data/clusters/x/*`))

		got := getClaim(name)
		Expect(got.Status.Vault.AuthMountAccessor).To(Equal("auth_kubernetes_abc1234"))
		Expect(got.Status.Vault.AppliedPolicies).To(Equal([]string{name + "-static", name + "-templated"}))
	})

	It("Step 6: no accessor fetch when no template references it", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath: "kubernetes-" + name, AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Policies: []vaultv1alpha1.PolicySpec{
					{Name: name + "-static", Rules: `path "secret/*" { capabilities = ["read"] }`},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(fakeVC.AccessorCalls).To(Equal(0), "accessor MUST NOT be fetched when no template uses it")
		Expect(fakeVC.PutPolicyCalls).To(Equal(1))
	})

	It("Step 7: soft-purges roles present in Vault but not in spec", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath: "kubernetes-" + name, AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Roles: []vaultv1alpha1.RoleSpec{
					{
						Name:                 "vmauth-reader",
						BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "vmauth", Namespace: "monitoring"},
						Policies:             []string{name + "-vmauth-reader"},
					},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Vault reports two existing roles; one matches spec, the other is stale.
		fakeVC.ListRolesResp = []string{"vmauth-reader", "stale-role"}

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		Expect(fakeVC.PutRoleCalls).To(Equal(1))
		Expect(fakeVC.WrittenRoles).To(HaveKey("vmauth-reader"))
		Expect(fakeVC.DeletedRoles).To(Equal([]string{"stale-role"}))

		got := getClaim(name)
		Expect(got.Status.Vault.AppliedRoles).To(Equal([]string{"vmauth-reader"}))
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionRolesApplied)).To(BeTrue())
	})

	It("Step 1 waits when VaultConfig is missing", func() {
		name := nextClaimName()
		secretName := name + "-kc"
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, "missing", secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		res, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueClaimVaultError))

		got := getClaim(name)
		c := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionConfigResolved)
		Expect(c).NotTo(BeNil())
		Expect(c.Status).To(Equal(metav1.ConditionFalse))
		Expect(c.Reason).To(Equal("NotFound"))

		// Downstream conditions never set (the pipeline stopped at Step 1).
		Expect(findCondition(got.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable)).To(BeNil())
		Expect(fakeVC.LoginCalls).To(Equal(0))
		Expect(fakeTarget.GetCalls).To(Equal(0))
	})

	It("Step 1 waits when VaultConfig is Reachable=False", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		makeUnhealthyVaultConfig(context.Background(), configName, false)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		secretName := name + "-kc"
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		got := getClaim(name)
		c := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionConfigResolved)
		Expect(c).NotTo(BeNil())
		Expect(c.Reason).To(Equal("VaultUnreachable"))
		// VaultReachable cascade-False
		vr := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionVaultReachable)
		Expect(vr).NotTo(BeNil())
		Expect(vr.Status).To(Equal(metav1.ConditionFalse))
		Expect(fakeVC.LoginCalls).To(Equal(0))
	})

	It("Step 2 waits when kubeconfig Secret is missing", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, name+"-kc")
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		res, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueClaimKubeconfigWait))

		got := getClaim(name)
		Expect(isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionConfigResolved)).To(BeTrue())
		c := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable)
		Expect(c).NotTo(BeNil())
		Expect(c.Reason).To(Equal("NotFound"))
		Expect(fakeTarget.GetCalls).To(Equal(0))
	})

	It("Step 2 waits when kubeconfig Secret has no 'value' entry", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		secretName := name + "-kc"
		makeKubeconfigSecret(context.Background(), secretName, false /* without value */)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getClaim(name)
		c := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionKubeconfigAvailable)
		Expect(c).NotTo(BeNil())
		Expect(c.Reason).To(Equal("InvalidSecret"))
	})

	It("Step 4 skips re-issue when reviewer JWT is still fresh", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Prime the status with a fresh JWT (issued 1h ago, expires in 23h →
		// way above the 30% threshold).
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{
			TokenReviewerJWT: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(fixedNow.Add(-time.Hour)),
				ExpiresAt: ptrTime(fixedNow.Add(23 * time.Hour)),
			},
		}
		Expect(k8sClient.Status().Update(context.Background(), claim)).To(Succeed())

		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		got := getClaim(name)
		c := findCondition(got.Status.Conditions, vaultv1alpha1.ConditionTokenReviewerJWTFresh)
		Expect(c).NotTo(BeNil())
		Expect(c.Reason).To(Equal("NoRotationNeeded"))

		// No new token issued — kc.Actions empty for token creation.
		kc := targetCS.Kubernetes.(*fake.Clientset)
		Expect(kc.Actions()).To(BeEmpty(), "TokenRequest must be skipped when JWT is fresh")

		// IssuedAt unchanged, ExpiresAt unchanged. Use BeTemporally because
		// metav1.Time round-trips through local zone (DeepEqual mismatches).
		Expect(got.Status.Vault.TokenReviewerJWT.IssuedAt.Time).To(BeTemporally("==", fixedNow.Add(-time.Hour)))
		Expect(got.Status.Vault.TokenReviewerJWT.ExpiresAt.Time).To(BeTemporally("==", fixedNow.Add(23*time.Hour)))
		// LastRotationAttempt updated (we always touch it).
		Expect(got.Status.Vault.TokenReviewerJWT.LastRotationAttempt).NotTo(BeNil())
		Expect(got.Status.Vault.TokenReviewerJWT.LastRotationAttempt.Time).To(BeTemporally("==", fixedNow))
	})

	It("removes finalizer on deletion (Story 007 will implement reverse pipeline)", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		_ = claim

		// First reconcile: adds finalizer + runs pipeline.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(getClaim(name).Finalizers).To(ContainElement(vaultv1alpha1.VaultClaimFinalizer))

		// Delete request.
		Expect(k8sClient.Delete(context.Background(), getClaim(name))).To(Succeed())
		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Verify the object is gone.
		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
			return apierrors.IsNotFound(err)
		}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
	})

	It("Drift: no drift when claim was Ready → short-circuits, skips Steps 2-7", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// First reconcile drives to Ready (all Steps 2-7 run, ObservedGeneration set).
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(getClaim(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

		// Counters before the second reconcile.
		fakeVC.mu.Lock()
		beforeWriteConfig := fakeVC.WriteConfigCalls
		beforePutRole := fakeVC.PutRoleCalls
		fakeVC.mu.Unlock()

		// Prime Vault to report "no drift".
		fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": {Type: "kubernetes"}}
		fakeVC.ListPoliciesResp = nil // spec has no policies
		fakeVC.ListRolesResp = nil    // spec has no roles

		// Second reconcile: drift hook should short-circuit.
		res, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueClaimDriftReady))

		got := getClaim(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(got.Status.Vault.LastDriftCheckAt).NotTo(BeNil(), "drift check timestamp must be set")

		// Steps 5-7 were skipped → write counters unchanged.
		Expect(fakeVC.WriteConfigCalls).To(Equal(beforeWriteConfig), "Step 5 must be skipped on no-drift")
		Expect(fakeVC.PutRoleCalls).To(Equal(beforePutRole), "Step 7 must be skipped on no-drift")
		Expect(fakeVC.ListAuthMountsCalls).To(Equal(1))
	})

	It("Drift: missing auth mount in Vault → falls through, Step 5 re-enables", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})
		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Drive to Ready.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		beforeEnable := fakeVC.EnableAuthCalls
		beforeWriteConfig := fakeVC.WriteConfigCalls

		// Vault reports the mount is gone (e.g. someone deleted it manually).
		fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{}
		fakeVC.ListPoliciesResp = nil
		fakeVC.ListRolesResp = nil

		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Step 5 ran again — auth mount re-enabled and config re-written.
		Expect(fakeVC.EnableAuthCalls).To(Equal(beforeEnable + 1))
		Expect(fakeVC.WriteConfigCalls).To(Equal(beforeWriteConfig + 1))
		Expect(getClaim(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
	})

	It("Deletion: full reverse pipeline — roles, policies, auth method, target SA", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		// Build a claim with both policies and roles so reverse pipeline has work.
		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath: "kubernetes-" + name, AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Policies: []vaultv1alpha1.PolicySpec{
					{Name: name + "-p1", Rules: `path "x" { capabilities = ["read"] }`},
				},
				Roles: []vaultv1alpha1.RoleSpec{
					{Name: "r1", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "sa", Namespace: "ns"}, Policies: []string{name + "-p1"}},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// First reconcile drives to Ready and populates appliedRoles/Policies.
		fakeVC.ListRolesResp = []string{"r1"}
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getClaim(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(got.Status.Vault.AppliedRoles).To(ContainElement("r1"))
		Expect(got.Status.Vault.AppliedPolicies).To(ContainElement(name + "-p1"))

		// Verify the target SA was created (happy-side-effect of the first reconcile).
		sa := &corev1.ServiceAccount{}
		Expect(targetCS.Client.Get(context.Background(), client.ObjectKey{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, sa)).To(Succeed())

		// Delete request — handleDeletion should run reverse pipeline.
		Expect(k8sClient.Delete(context.Background(), getClaim(name))).To(Succeed())

		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Object gone (finalizer dropped).
		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
			return apierrors.IsNotFound(err)
		}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())

		// Vault objects deleted (DeleteKubernetesRole/DeletePolicy/DisableAuthMethod called).
		Expect(fakeVC.DeletedRoles).To(ContainElement("r1"))
		Expect(fakeVC.DeletedPolicies).To(ContainElement(name + "-p1"))
		Expect(fakeVC.DisabledAuthPaths).To(ContainElement("kubernetes-" + name))

		// Target SA gone from infra cluster (best-effort cleanup ran).
		err = targetCS.Client.Get(context.Background(), client.ObjectKey{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, &corev1.ServiceAccount{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "target SA should be deleted")
	})

	It("Deletion: Vault returns error → keeps finalizer, requeues, emits DeletionStuck event", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath: "kubernetes-" + name, AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Roles: []vaultv1alpha1.RoleSpec{
					{Name: "r1", BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "sa", Namespace: "ns"}, Policies: []string{"p"}},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Drive to Ready.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Now make Vault refuse DeleteKubernetesRole.
		fakeVC.DeleteRoleErr = errors.New("vault down")

		// Delete request.
		Expect(k8sClient.Delete(context.Background(), getClaim(name))).To(Succeed())

		res, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(Equal(RequeueDeletionStuck))

		// Object still present, finalizer still there.
		got := getClaim(name)
		Expect(got.Finalizers).To(ContainElement(vaultv1alpha1.VaultClaimFinalizer))
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseDeleting))

		// Auth method NOT disabled — we stopped at the first failing step.
		Expect(fakeVC.DisableAuthCalls).To(Equal(0))
	})

	It("Deletion: kubeconfig Secret missing → Vault cleaned, target step skipped, finalizer dropped", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		// NOTE: no DeferCleanup of the secret here — we'll explicitly delete it below.

		claim := makeVaultClaim(context.Background(), name, configName, secretName)
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// Drive to Ready (target SA created in fake cluster).
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Simulate the kubeconfig being deleted ahead of the VaultClaim
		// (e.g. ClusterClaim was already torn down).
		Expect(k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})).To(Succeed())

		// Delete the VaultClaim.
		Expect(k8sClient.Delete(context.Background(), getClaim(name))).To(Succeed())

		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Vault cleanup proceeded (DisableAuthMethod called).
		Expect(fakeVC.DisableAuthCalls).To(BeNumerically(">=", 1))

		// Finalizer dropped — claim gone.
		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
			return apierrors.IsNotFound(err)
		}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
	})

	It("Deletion: claim never reached AuthMountReady → fast finalizer drop, no Vault calls", func() {
		name := nextClaimName()
		// Don't create a VaultConfig — Step 1 will wait. Then we delete.

		makeKubeconfigSecret(context.Background(), name+"-kc", true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name + "-kc", Namespace: vcNS}})
		})

		claim := makeVaultClaim(context.Background(), name, "missing-config", name+"-kc")
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// One reconcile — Step 1 waits because VaultConfig is missing; finalizer
		// is added, no Vault objects touched.
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(getClaim(name).Finalizers).To(ContainElement(vaultv1alpha1.VaultClaimFinalizer))
		Expect(getClaim(name).Status.Vault.AuthMountPath).To(BeEmpty())

		beforeDisable := fakeVC.DisableAuthCalls

		// Delete it.
		Expect(k8sClient.Delete(context.Background(), getClaim(name))).To(Succeed())
		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Fast finalizer drop — no Vault delete calls because AuthMountPath
		// was never populated (everCreatedAuth=false).
		Expect(fakeVC.DisableAuthCalls).To(Equal(beforeDisable))

		Eventually(func() bool {
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: vcNS}, &vaultv1alpha1.VaultClaim{})
			return apierrors.IsNotFound(err)
		}, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
	})

	It("Drift: extra role in Vault → soft-purged on second pass", func() {
		name := nextClaimName()
		configName := "cfg-" + name
		secretName := name + "-kc"

		makeHealthyVaultConfig(context.Background(), configName)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: configName}})
		})
		makeKubeconfigSecret(context.Background(), secretName, true)
		DeferCleanup(func() {
			_ = k8sClient.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: vcNS}})
		})

		// Claim with one role so we have a deterministic "extra" comparison.
		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: vcNS},
			Spec: vaultv1alpha1.VaultClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
				ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: secretName},
				SecretsPrefix:  "clusters/" + name,
				Auth: vaultv1alpha1.AuthSpec{
					MountPath: "kubernetes-" + name, AutoCreate: true,
					TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
						ServiceAccount: vaultv1alpha1.ServiceAccountRef{Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true},
						TTL:            metav1.Duration{Duration: 24 * time.Hour},
					},
				},
				Roles: []vaultv1alpha1.RoleSpec{
					{
						Name:                 "wanted-role",
						BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "sa", Namespace: "ns"},
						Policies:             []string{"p"},
					},
				},
			},
		}
		Expect(k8sClient.Create(context.Background(), claim)).To(Succeed())
		DeferCleanup(func() {
			fresh := &vaultv1alpha1.VaultClaim{}
			if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(context.Background(), fresh)
				_ = k8sClient.Delete(context.Background(), fresh)
			}
		})

		// First reconcile to Ready — Vault still has only the desired role.
		fakeVC.ListRolesResp = []string{"wanted-role"}
		_, err := reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(getClaim(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))

		// Simulate someone adding a rogue role directly in Vault.
		fakeVC.ListAuthMountsResp = map[string]vault.AuthMountInfo{"kubernetes-" + name + "/": {Type: "kubernetes"}}
		fakeVC.ListRolesResp = []string{"wanted-role", "rogue-role"}

		_, err = reconcileClaim(recon, name)
		Expect(err).NotTo(HaveOccurred())

		// Drift detector saw the extra role → fell through → Step 7 purged it.
		Expect(fakeVC.DeletedRoles).To(ContainElement("rogue-role"))
		Expect(getClaim(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
	})
})

// findCondition is a thin wrapper used in tests to assert on individual
// conditions without scanning the list inline every time.
func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
