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
	ctrlClient := fakeclient.NewClientBuilder().WithScheme(scheme).
		WithObjects(
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "vault-token-reviewer" + CRBSuffix}},
		).Build()
	cs := &ClientSet{Client: ctrlClient}

	claim := newSampleClaim()
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
