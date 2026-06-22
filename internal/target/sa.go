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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// ClusterRoleAuthDelegator grants TokenReview API access — what Vault needs
// to validate pod tokens against the target cluster.
const ClusterRoleAuthDelegator = "system:auth-delegator"

const CRBSuffix = "-auth-delegator"

// EnsureTokenReviewerSA applies (server-side) the namespace, ServiceAccount,
// and ClusterRoleBinding required for Vault to call TokenReview. Resources
// carry LabelClaimName / LabelClaimNamespace so artefacts can be traced back
// to the originating VaultClaim. Idempotent via SSA.
func EnsureTokenReviewerSA(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim) error {
	ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
	if ref.Namespace == "" || ref.Name == "" {
		return fmt.Errorf("tokenReviewer.serviceAccount.namespace and .name are required")
	}

	labels := map[string]string{
		vaultv1alpha1.LabelClaimName:      claim.Name,
		vaultv1alpha1.LabelClaimNamespace: claim.Namespace,
	}

	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   ref.Namespace,
			Labels: labels,
		},
	}
	if err := cs.Client.Patch(ctx, ns, client.Apply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply namespace %s: %w", ref.Namespace, err)
	}

	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
			Labels:    labels,
		},
	}
	if err := cs.Client.Patch(ctx, sa, client.Apply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply ServiceAccount %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	crbName := ref.Name + CRBSuffix
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   crbName,
			Labels: labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ClusterRoleAuthDelegator,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Namespace: ref.Namespace,
			Name:      ref.Name,
		}},
	}
	if err := cs.Client.Patch(ctx, crb, client.Apply, client.FieldOwner(FieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("apply ClusterRoleBinding %s: %w", crbName, err)
	}

	return nil
}

// DeleteTokenReviewerSA removes the SA and CRB; the namespace is left alone
// because it may host other resources. Best-effort: NotFound is fine.
func DeleteTokenReviewerSA(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim) error {
	ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
	if ref.Namespace == "" || ref.Name == "" {
		return nil
	}

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name}}
	if err := cs.Client.Delete(ctx, sa); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete ServiceAccount %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: ref.Name + CRBSuffix}}
	if err := cs.Client.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete ClusterRoleBinding %s: %w", crb.Name, err)
	}
	return nil
}
