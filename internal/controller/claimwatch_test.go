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
	"net"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// vaultAddr is the address a transport error names; status must never show it.
const vaultAddr = "192.0.2.10"

// unreachableVault is the error a dial to a Vault that refuses connections
// returns: its text carries the address.
func unreachableVault() error {
	return &net.OpError{Op: "dial", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(vaultAddr), Port: 8200}, Err: syscall.ECONNREFUSED}
}

// selectedManager runs controllers whose cache sees only the given kinds
// labelled selectorKey=yes, so claims of other specs never reach them.
func selectedManager(selectorKey string, kinds ...client.Object) ctrl.Manager {
	sel := cache.ByObject{Label: labels.SelectorFromSet(labels.Set{selectorKey: "yes"})}
	byObject := make(map[client.Object]cache.ByObject, len(kinds))
	for _, k := range kinds {
		byObject[k] = sel
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 k8sClient.Scheme(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Cache:                  cache.Options{ByObject: byObject},
		Controller:             config.Controller{SkipNameValidation: ptr.To(true)},
	})
	Expect(err).NotTo(HaveOccurred())
	return mgr
}

// deleteWatched deletes obj and drops the finalizers a controller without a
// VaultConfig cannot remove.
func deleteWatched(obj client.Object) {
	key := client.ObjectKeyFromObject(obj)
	_ = k8sClient.Delete(context.Background(), obj)
	Eventually(func() bool {
		if err := k8sClient.Get(context.Background(), key, obj); apierrors.IsNotFound(err) {
			return true
		}
		obj.SetFinalizers(nil)
		_ = k8sClient.Update(context.Background(), obj)
		return false
	}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
}

// expectNoPass expects the controller to start no pass after baseline.
func expectNoPass(controllerName string, baseline float64, why string) {
	Consistently(func() float64 { return reconcileTotal(controllerName) - baseline }, 3*time.Second, 100*time.Millisecond).
		Should(BeZero(), why)
}

// addHoldFinalizer adds a test finalizer, a metadata write that changes no
// generation, label or annotation. A conflict means another writer changed
// the claim in between; the write is retried on the fresh copy, and whether a
// pass ran is judged by the pass count, not by the conflict.
func addHoldFinalizer(get func() client.Object) {
	Eventually(func() error {
		fresh := get()
		fresh.SetFinalizers(append(fresh.GetFinalizers(), "vault-operator-test/hold"))
		return k8sClient.Update(context.Background(), fresh)
	}, 10*time.Second, 100*time.Millisecond).Should(Succeed())
}

// expectWakes applies edit and expects the controller to start a pass.
func expectWakes(controllerName string, edit func()) {
	baseline := settled(controllerName)
	edit()
	Eventually(func() float64 { return reconcileTotal(controllerName) - baseline }, 10*time.Second, 50*time.Millisecond).
		Should(BeNumerically(">", 0))
}

// The controllers run under a real manager: which watch events reach
// Reconcile cannot be seen by calling Reconcile directly. The claims point at
// a VaultConfig that does not exist, so every pass stops at the first step and
// asks for a requeue a minute later: any pass inside the window below comes
// from a watch event.
var _ = Describe("S3BucketClaim and VaultSecretClaim watches", func() {
	It("S3BucketClaim: status and finalizer writes start no pass; spec, label and annotation changes do", func() {
		const selectorKey = "vault-operator-test/s3-watch"
		const controllerName = "s3bucketclaim"
		mgr := selectedManager(selectorKey, &vaultv1alpha1.S3BucketClaim{})
		Expect((&S3BucketClaimReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr)).To(Succeed())
		startManager(mgr)

		name := "s3w-" + nextClaimName()
		c := newS3BucketClaim(name, "absent-"+name)
		c.Labels = map[string]string{selectorKey: "yes"}
		Expect(k8sClient.Create(context.Background(), c)).To(Succeed())
		DeferCleanup(func() {
			deleteWatched(&vaultv1alpha1.S3BucketClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}})
		})
		Eventually(func() string { return getS3(name).Status.Phase }, 10*time.Second, 50*time.Millisecond).
			Should(Equal(vaultv1alpha1.PhasePending))
		baseline := settled(controllerName)

		fresh := getS3(name)
		base := fresh.DeepCopy()
		fresh.Status.Phase = vaultv1alpha1.PhaseReady
		Expect(k8sClient.Status().Patch(context.Background(), fresh, client.MergeFrom(base))).To(Succeed())
		expectNoPass(controllerName, baseline, "a status write of the claim started a pass")
		addHoldFinalizer(func() client.Object { return getS3(name) })
		expectNoPass(controllerName, baseline, "a finalizer write of the claim started a pass")

		expectWakes(controllerName, func() {
			fresh := getS3(name)
			fresh.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyRetain
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
		expectWakes(controllerName, func() {
			fresh := getS3(name)
			fresh.Labels["vault-operator-test/poke"] = "1"
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
		expectWakes(controllerName, func() {
			fresh := getS3(name)
			fresh.Annotations = map[string]string{"vault-operator-test/poke": "1"}
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
	})

	It("VaultSecretClaim: status and finalizer writes start no pass; spec, label and annotation changes do", func() {
		const selectorKey = "vault-operator-test/vsc-watch"
		const controllerName = "vaultsecretclaim"
		mgr := selectedManager(selectorKey, &vaultv1alpha1.VaultSecretClaim{})
		Expect((&VaultSecretClaimReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr)).To(Succeed())
		startManager(mgr)

		name := "vscw-" + nextClaimName()
		c := &vaultv1alpha1.VaultSecretClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: map[string]string{selectorKey: "yes"}},
			Spec: vaultv1alpha1.VaultSecretClaimSpec{
				VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "absent-" + name},
				ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: name},
				SecretsPrefix:  "clusters/" + name,
				DeletionPolicy: vaultv1alpha1.DeletionPolicyRetain,
				SecretList:     []vaultv1alpha1.SecretListItem{genListItem()},
			},
		}
		Expect(k8sClient.Create(context.Background(), c)).To(Succeed())
		DeferCleanup(func() {
			deleteWatched(&vaultv1alpha1.VaultSecretClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}})
		})
		get := func() *vaultv1alpha1.VaultSecretClaim {
			got := &vaultv1alpha1.VaultSecretClaim{}
			Expect(k8sClient.Get(context.Background(), client.ObjectKeyFromObject(c), got)).To(Succeed())
			return got
		}
		Eventually(func() string { return get().Status.Phase }, 10*time.Second, 50*time.Millisecond).
			Should(Equal(vaultv1alpha1.PhasePending))
		baseline := settled(controllerName)

		fresh := get()
		base := fresh.DeepCopy()
		fresh.Status.Phase = vaultv1alpha1.PhaseReady
		Expect(k8sClient.Status().Patch(context.Background(), fresh, client.MergeFrom(base))).To(Succeed())
		expectNoPass(controllerName, baseline, "a status write of the claim started a pass")
		addHoldFinalizer(func() client.Object { return get() })
		expectNoPass(controllerName, baseline, "a finalizer write of the claim started a pass")

		expectWakes(controllerName, func() {
			fresh := get()
			fresh.Spec.DeletionPolicy = vaultv1alpha1.DeletionPolicyPurge
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
		expectWakes(controllerName, func() {
			fresh := get()
			fresh.Labels["vault-operator-test/poke"] = "1"
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
		expectWakes(controllerName, func() {
			fresh := get()
			fresh.Annotations = map[string]string{"vault-operator-test/poke": "1"}
			Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		})
	})
})

// errSecretFactory fails every client build with err.
type errSecretFactory struct{ err error }

func (f *errSecretFactory) For(context.Context, client.Client, *vaultv1alpha1.VaultConfig) (SecretVaultClient, error) {
	return nil, f.err
}

func (f *errSecretFactory) Invalidate(string) {}

// expectNoAddress fails when a condition, an item message or an event names
// the Vault address.
func expectNoAddress(conds []metav1.Condition, rec *record.FakeRecorder, extra ...string) {
	for _, c := range conds {
		Expect(c.Message).NotTo(ContainSubstring(vaultAddr), "condition %s", c.Type)
	}
	for _, m := range extra {
		Expect(m).NotTo(ContainSubstring(vaultAddr))
	}
	for _, e := range drainEvents(rec) {
		Expect(e).NotTo(ContainSubstring(vaultAddr))
	}
}

var _ = Describe("S3BucketClaim and VaultSecretClaim status texts", func() {
	var (
		fakeSV   *fakeSecretVaultClient
		recorder *record.FakeRecorder
	)
	BeforeEach(func() {
		fakeSV = newFakeSecretVault()
		recorder = record.NewFakeRecorder(100)
	})

	It("S3BucketClaim: a client build error is its cause text", func() {
		name := "s3txt-f-" + nextClaimName()
		makeHealthyVaultConfig(ctx, name)
		makeS3BucketClaim(ctx, name, name)
		r := &S3BucketClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: recorder,
			VaultFactory: &errSecretFactory{err: unreachableVault()}}
		res, err := reconcileBucketOnce(r, name)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		got := getS3(name)
		cond := findCond(got.Status.Conditions, vaultv1alpha1.ConditionVaultReachable)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("FactoryError"))
		Expect(cond.Message).To(Equal("building the Vault client failed: the remote endpoint is unreachable"))
		expectNoAddress(got.Status.Conditions, recorder)
	})

	It("S3BucketClaim: a login error is its cause text", func() {
		name := "s3txt-l-" + nextClaimName()
		makeHealthyVaultConfig(ctx, name)
		makeS3BucketClaim(ctx, name, name)
		fakeSV.loginErr = unreachableVault()
		r := &S3BucketClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: recorder,
			VaultFactory: &fakeSecretVaultFactory{Client: fakeSV}}
		_, err := reconcileBucketOnce(r, name)
		Expect(err).NotTo(HaveOccurred())
		got := getS3(name)
		cond := findCond(got.Status.Conditions, vaultv1alpha1.ConditionVaultReachable)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal(ReasonLoginFailed))
		Expect(cond.Message).To(Equal("Vault login failed: the remote endpoint is unreachable"))
		expectNoAddress(got.Status.Conditions, recorder)
	})

	newSecretRecon := func(f SecretVaultClientFactory) *VaultSecretClaimReconciler {
		return &VaultSecretClaimReconciler{Client: k8sClient, Scheme: k8sClient.Scheme(), Recorder: recorder, VaultFactory: f,
			Now: func() time.Time { return time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC) }}
	}
	getVSC := func(name string) *vaultv1alpha1.VaultSecretClaim {
		got := &vaultv1alpha1.VaultSecretClaim{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: name}, got)).To(Succeed())
		return got
	}

	It("VaultSecretClaim: client build and login errors are their cause texts", func() {
		name := "vsctxt-l-" + nextClaimName()
		makeHealthyVaultConfig(ctx, name)
		makeVaultSecretClaim(ctx, name, name, vaultv1alpha1.DeletionPolicyRetain, []vaultv1alpha1.SecretListItem{genListItem()})

		_, err := reconcileSecretOnce(newSecretRecon(&errSecretFactory{err: unreachableVault()}), name)
		Expect(err).NotTo(HaveOccurred())
		cond := findCond(getVSC(name).Status.Conditions, vaultv1alpha1.ConditionVaultReachable)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("FactoryError"))
		Expect(cond.Message).To(Equal("building the Vault client failed: the remote endpoint is unreachable"))

		fakeSV.loginErr = unreachableVault()
		_, err = reconcileSecretOnce(newSecretRecon(&fakeSecretVaultFactory{Client: fakeSV}), name)
		Expect(err).NotTo(HaveOccurred())
		got := getVSC(name)
		cond = findCond(got.Status.Conditions, vaultv1alpha1.ConditionVaultReachable)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal(ReasonLoginFailed))
		Expect(cond.Message).To(Equal("Vault login failed: the remote endpoint is unreachable"))
		expectNoAddress(got.Status.Conditions, recorder)
	})

	It("VaultSecretClaim: a source Vault cannot read is a cause text; a missing source keeps its spec text", func() {
		name := "vsctxt-s-" + nextClaimName()
		makeHealthyVaultConfig(ctx, name)
		makeVaultSecretClaim(ctx, name, name, vaultv1alpha1.DeletionPolicyRetain, []vaultv1alpha1.SecretListItem{copyListItem()})
		recon := newSecretRecon(&fakeSecretVaultFactory{Client: fakeSV})

		// Twin: the source is absent. The message is built from the spec alone.
		_, err := reconcileSecretOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		cond := findCond(getVSC(name).Status.Conditions, vaultv1alpha1.ConditionSourcesResolved)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal("MissingSource"))
		Expect(cond.Message).To(Equal(`item "grafana-oidc": source secret/system/dex#staticClient not found`))
		drainEvents(recorder)

		fakeSV.readErr = map[string]error{"secret|system/dex": unreachableVault()}
		_, err = reconcileSecretOnce(recon, name)
		Expect(err).NotTo(HaveOccurred())
		got := getVSC(name)
		cond = findCond(got.Status.Conditions, vaultv1alpha1.ConditionSourcesResolved)
		Expect(cond).NotTo(BeNil())
		Expect(cond.Message).NotTo(ContainSubstring(vaultAddr))
		Expect(cond.Reason).To(Equal("MissingSource"))
		Expect(cond.Message).To(Equal(`item "grafana-oidc": reading source secret/system/dex failed: the remote endpoint is unreachable`))
		expectNoAddress(got.Status.Conditions, recorder)
	})

	It("VaultSecretClaim: an item Vault fails is a cause text; a spec error of an item keeps its spec text", func() {
		name := "vsctxt-i-" + nextClaimName()
		makeHealthyVaultConfig(ctx, name)
		noHashedKey := genListItem()
		noHashedKey.Name = "no-hashed-key"
		noHashedKey.Destination = vaultv1alpha1.DestinationSpec{Path: "other", Key: "password"}
		makeVaultSecretClaim(ctx, name, name, vaultv1alpha1.DeletionPolicyRetain,
			[]vaultv1alpha1.SecretListItem{genListItem(), noHashedKey})
		fakeSV.readErr = map[string]error{"secret|clusters/" + name + "/argocd": unreachableVault()}

		_, err := reconcileSecretOnce(newSecretRecon(&fakeSecretVaultFactory{Client: fakeSV}), name)
		Expect(err).NotTo(HaveOccurred())
		got := getVSC(name)
		Expect(got.Status.Items).To(HaveLen(2))
		byName := map[string]vaultv1alpha1.SecretItemStatus{}
		for _, it := range got.Status.Items {
			byName[it.Name] = it
		}
		Expect(byName["argocd-admin"].State).To(Equal(vaultv1alpha1.ItemStateFailed))
		Expect(byName["argocd-admin"].Message).To(Equal("the remote endpoint is unreachable"))
		// Twin: the item's own spec is wrong; the message says what to fix.
		Expect(byName["no-hashed-key"].State).To(Equal(vaultv1alpha1.ItemStateFailed))
		Expect(byName["no-hashed-key"].Message).To(Equal(`item "no-hashed-key": generate.hash=bcrypt requires destination.hashedKey`))
		expectNoAddress(got.Status.Conditions, recorder, byName["argocd-admin"].Message)
	})
})
