/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package target

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func newTargetTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	return s
}

func newSampleClaim() *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			Auth: vaultv1alpha1.AuthSpec{
				MountPath: "kubernetes-ec8a00",
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{
					ServiceAccount: vaultv1alpha1.ServiceAccountRef{
						Namespace:  "beget-vault-system",
						Name:       "vault-token-reviewer",
						AutoCreate: true,
					},
				},
			},
		},
	}
}

func TestEnsureTokenReviewerSA_CreatesNamespaceSAAndCRB(t *testing.T) {
	scheme := newTargetTestScheme(t)
	ctrlClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
	cs := &ClientSet{Client: ctrlClient}

	claim := newSampleClaim()
	if err := EnsureTokenReviewerSA(context.Background(), cs, claim); err != nil {
		t.Fatalf("EnsureTokenReviewerSA: %v", err)
	}

	// Namespace must exist.
	ns := &corev1.Namespace{}
	if err := ctrlClient.Get(context.Background(), types.NamespacedName{Name: "beget-vault-system"}, ns); err != nil {
		t.Fatalf("get Namespace: %v", err)
	}
	if ns.Labels[vaultv1alpha1.LabelClaimName] != "ec8a00" {
		t.Errorf("namespace missing LabelClaimName, got %v", ns.Labels)
	}

	// ServiceAccount.
	sa := &corev1.ServiceAccount{}
	if err := ctrlClient.Get(context.Background(), types.NamespacedName{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, sa); err != nil {
		t.Fatalf("get SA: %v", err)
	}
	if sa.Labels[vaultv1alpha1.LabelClaimNamespace] != "dlputi1u" {
		t.Errorf("SA missing LabelClaimNamespace, got %v", sa.Labels)
	}

	// ClusterRoleBinding.
	crb := &rbacv1.ClusterRoleBinding{}
	if err := ctrlClient.Get(context.Background(), types.NamespacedName{Name: "vault-token-reviewer" + CRBSuffix}, crb); err != nil {
		t.Fatalf("get CRB: %v", err)
	}
	if crb.RoleRef.Name != ClusterRoleAuthDelegator {
		t.Errorf("CRB roleRef = %q, want %q", crb.RoleRef.Name, ClusterRoleAuthDelegator)
	}
	if len(crb.Subjects) != 1 || crb.Subjects[0].Name != "vault-token-reviewer" {
		t.Errorf("CRB subjects = %+v", crb.Subjects)
	}
}

func TestEnsureTokenReviewerSA_IsIdempotent(t *testing.T) {
	scheme := newTargetTestScheme(t)
	ctrlClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
	cs := &ClientSet{Client: ctrlClient}

	claim := newSampleClaim()
	if err := EnsureTokenReviewerSA(context.Background(), cs, claim); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call must succeed and not duplicate resources.
	if err := EnsureTokenReviewerSA(context.Background(), cs, claim); err != nil {
		t.Fatalf("second call: %v", err)
	}

	saList := &corev1.ServiceAccountList{}
	if err := ctrlClient.List(context.Background(), saList, client.InNamespace("beget-vault-system")); err != nil {
		t.Fatalf("list SAs: %v", err)
	}
	if got := len(saList.Items); got != 1 {
		t.Errorf("got %d ServiceAccounts after two applies, want 1", got)
	}
}

func TestEnsureTokenReviewerSA_RejectsMissingRef(t *testing.T) {
	scheme := newTargetTestScheme(t)
	ctrlClient := fakeclient.NewClientBuilder().WithScheme(scheme).Build()
	cs := &ClientSet{Client: ctrlClient}

	claim := newSampleClaim()
	claim.Spec.Auth.TokenReviewer.ServiceAccount.Name = ""
	if err := EnsureTokenReviewerSA(context.Background(), cs, claim); err == nil {
		t.Fatal("expected error when SA name empty")
	}
}

func TestDeleteTokenReviewerSA_RemovesSAAndCRBIgnoreMissing(t *testing.T) {
	scheme := newTargetTestScheme(t)
	claim := newSampleClaim()
	ctrlClient := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: ownLabels(claim)}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "vault-token-reviewer" + CRBSuffix, Labels: ownLabels(claim)}},
		).Build()
	cs := &ClientSet{Client: ctrlClient}

	if err := DeleteTokenReviewerSA(context.Background(), cs, claim); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if err := ctrlClient.Get(context.Background(), types.NamespacedName{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, &corev1.ServiceAccount{}); !apierrors.IsNotFound(err) {
		t.Errorf("SA still present: err=%v", err)
	}
	if err := ctrlClient.Get(context.Background(), types.NamespacedName{Name: "vault-token-reviewer" + CRBSuffix}, &rbacv1.ClusterRoleBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("CRB still present: err=%v", err)
	}

	// Second delete must not fail (idempotent).
	if err := DeleteTokenReviewerSA(context.Background(), cs, claim); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func ownLabels(claim *vaultv1alpha1.VaultClaim) map[string]string {
	return map[string]string{vaultv1alpha1.LabelClaimName: claim.Name, vaultv1alpha1.LabelClaimNamespace: claim.Namespace}
}

// patchRecorder counts the writes a client receives and whether any forced
// ownership.
type patchRecorder struct {
	patches map[string]int
	forced  int
	deletes []client.DeleteOptions
}

func recordingClient(t *testing.T, objs ...client.Object) (client.Client, *patchRecorder) {
	t.Helper()
	rec := &patchRecorder{patches: map[string]int{}}
	c := fakeclient.NewClientBuilder().WithScheme(newTargetTestScheme(t)).WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				rec.patches[fmt.Sprintf("%T", obj)]++
				po := &client.PatchOptions{}
				po.ApplyOptions(opts)
				if po.Force != nil && *po.Force {
					rec.forced++
				}
				return c.Patch(ctx, obj, patch, opts...)
			},
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				rec.patches[fmt.Sprintf("%T", obj)]++
				return c.Create(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				do := client.DeleteOptions{}
				do.ApplyOptions(opts)
				rec.deletes = append(rec.deletes, do)
				return c.Delete(ctx, obj, opts...)
			},
		}).Build()
	return c, rec
}

// A reviewer ServiceAccount or binding labelled for another claim, or not
// labelled at all, is not this claim's: nothing is written to it and the
// refusal is typed. The twin labelled for this claim is applied, never forced.
func TestEnsureTokenReviewerSA_RefusesAForeignReviewer(t *testing.T) {
	claim := newSampleClaim()
	other := map[string]string{vaultv1alpha1.LabelClaimName: "zz0001", vaultv1alpha1.LabelClaimNamespace: claim.Namespace}
	for name, objs := range map[string][]client.Object{
		"SA of another claim": {&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: other}}},
		"unlabelled SA":       {&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}}},
		"binding of another claim": {
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: ownLabels(claim)}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "vault-token-reviewer" + CRBSuffix, Labels: other},
				RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "cluster-admin"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := recordingClient(t, objs...)
			err := EnsureTokenReviewerSA(context.Background(), &ClientSet{Client: c}, claim)
			if !IsForeignReviewer(err) {
				t.Fatalf("err = %v, want a foreign-reviewer refusal", err)
			}
			if rec.forced != 0 {
				t.Fatalf("%d writes forced ownership", rec.forced)
			}
			sa := &corev1.ServiceAccount{}
			if err := c.Get(context.Background(), types.NamespacedName{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, sa); err != nil {
				t.Fatal(err)
			}
			if want := objs[0].GetLabels(); !equalLabels(sa.Labels, want) {
				t.Fatalf("SA labels rewritten: %v", sa.Labels)
			}
			crb := &rbacv1.ClusterRoleBinding{}
			err = c.Get(context.Background(), types.NamespacedName{Name: "vault-token-reviewer" + CRBSuffix}, crb)
			switch {
			case len(objs) == 1 && !apierrors.IsNotFound(err):
				t.Fatalf("a binding was written for a foreign SA: %v", err)
			case len(objs) > 1 && (err != nil || crb.RoleRef.Name != "cluster-admin" || !equalLabels(crb.Labels, other) || len(crb.Subjects) != 0):
				t.Fatalf("foreign binding rewritten: %v %+v", err, crb)
			}
		})
	}

	t.Run("own objects", func(t *testing.T) {
		c, rec := recordingClient(t,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "beget-vault-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: ownLabels(claim)}},
		)
		if err := EnsureTokenReviewerSA(context.Background(), &ClientSet{Client: c}, claim); err != nil {
			t.Fatalf("own reviewer refused: %v", err)
		}
		if rec.forced != 0 {
			t.Fatalf("%d writes forced ownership", rec.forced)
		}
		if n := rec.patches["*v1.Namespace"]; n != 0 {
			t.Fatalf("an existing namespace was written %d times", n)
		}
		if err := c.Get(context.Background(), types.NamespacedName{Name: "vault-token-reviewer" + CRBSuffix}, &rbacv1.ClusterRoleBinding{}); err != nil {
			t.Fatalf("binding not created: %v", err)
		}
	})
}

// Deletion removes only objects labelled for this claim, each under a
// precondition on the UID and resource version it read; a foreign object is
// left and reported.
func TestDeleteTokenReviewerSA_DeletesOnlyItsOwn(t *testing.T) {
	claim := newSampleClaim()
	c, rec := recordingClient(t,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: ownLabels(claim), UID: "sa-uid"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "vault-token-reviewer" + CRBSuffix, UID: "crb-uid"},
			RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: ClusterRoleAuthDelegator}},
	)
	err := DeleteTokenReviewerSA(context.Background(), &ClientSet{Client: c}, claim)
	if !IsForeignReviewer(err) {
		t.Fatalf("err = %v, want the unlabelled binding reported", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}, &corev1.ServiceAccount{}); !apierrors.IsNotFound(err) {
		t.Fatalf("own SA not deleted: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "vault-token-reviewer" + CRBSuffix}, &rbacv1.ClusterRoleBinding{}); err != nil {
		t.Fatalf("foreign binding deleted: %v", err)
	}
	if len(rec.deletes) != 1 {
		t.Fatalf("%d deletes sent, want 1", len(rec.deletes))
	}
	pre := rec.deletes[0].Preconditions
	if pre == nil || pre.UID == nil || *pre.UID != "sa-uid" || pre.ResourceVersion == nil || *pre.ResourceVersion == "" {
		t.Fatalf("delete preconditions = %+v, want the UID and resource version read", pre)
	}
}

func equalLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
