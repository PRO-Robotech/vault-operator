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
	"errors"
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

// ForeignReviewerError: the reviewer ServiceAccount or its ClusterRoleBinding
// exists in the target cluster without this claim's labels. The operator
// neither writes nor deletes it. Kind and Name come from the claim's spec.
type ForeignReviewerError struct {
	Kind string
	Name string
}

func (e *ForeignReviewerError) Error() string {
	return fmt.Sprintf("%s %s exists and is not labelled for this claim", e.Kind, e.Name)
}

// IsForeignReviewer reports whether err, or an error it wraps or joins, is a
// ForeignReviewerError.
func IsForeignReviewer(err error) bool {
	var f *ForeignReviewerError
	return errors.As(err, &f)
}

func claimLabels(claim *vaultv1alpha1.VaultClaim) map[string]string {
	return map[string]string{
		vaultv1alpha1.LabelClaimName:      claim.Name,
		vaultv1alpha1.LabelClaimNamespace: claim.Namespace,
	}
}

// labelledFor: an object is this claim's only when it carries both claim
// labels with this claim's name and namespace. Objects the operator creates
// carry them; an unlabelled one was made by someone else.
func labelledFor(obj client.Object, claim *vaultv1alpha1.VaultClaim) bool {
	l := obj.GetLabels()
	return l[vaultv1alpha1.LabelClaimName] == claim.Name && l[vaultv1alpha1.LabelClaimNamespace] == claim.Namespace
}

// existing reads obj by key: found reports whether it exists, and an object
// that exists but is not labelled for claim is a ForeignReviewerError.
func existing(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim, key client.ObjectKey, obj client.Object, kind string) (bool, error) {
	if err := cs.Client.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("get %s %s: %w", kind, key, err)
	}
	if !labelledFor(obj, claim) {
		return true, &ForeignReviewerError{Kind: kind, Name: key.String()}
	}
	return true, nil
}

// EnsureTokenReviewerSA makes the ServiceAccount and ClusterRoleBinding
// (system:auth-delegator) Vault needs to call TokenReview, labelled with the
// claim they belong to. Both are judged before anything is written: one that
// exists without this claim's labels is a ForeignReviewerError and is left as
// it is. A missing object is created — a create fails on a name someone took
// meanwhile, where an apply would merge into it; an own object is applied
// without forcing ownership and only as it was read. The namespace is created when missing and never
// written when it exists: it may host anything.
func EnsureTokenReviewerSA(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim) error {
	ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
	if ref.Namespace == "" || ref.Name == "" {
		return fmt.Errorf("tokenReviewer.serviceAccount.namespace and .name are required")
	}
	labels := claimLabels(claim)
	crbName := ref.Name + CRBSuffix

	readSA, readCRB := &corev1.ServiceAccount{}, &rbacv1.ClusterRoleBinding{}
	saFound, err := existing(ctx, cs, claim, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, readSA, "ServiceAccount")
	if err != nil {
		return err
	}
	crbFound, err := existing(ctx, cs, claim, client.ObjectKey{Name: crbName}, readCRB, "ClusterRoleBinding")
	if err != nil {
		return err
	}

	if err := cs.Client.Get(ctx, client.ObjectKey{Name: ref.Namespace}, &corev1.Namespace{}); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get namespace %s: %w", ref.Namespace, err)
		}
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ref.Namespace, Labels: labels}}
		if err := cs.Client.Create(ctx, ns, client.FieldOwner(FieldManager)); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create namespace %s: %w", ref.Namespace, err)
		}
	}

	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
			Labels:    labels,
		},
	}
	if err := put(ctx, cs, sa, readSA, saFound); err != nil {
		return fmt.Errorf("apply ServiceAccount %s/%s: %w", ref.Namespace, ref.Name, err)
	}

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
	if err := put(ctx, cs, crb, readCRB, crbFound); err != nil {
		return fmt.Errorf("apply ClusterRoleBinding %s: %w", crbName, err)
	}
	return nil
}

// put creates obj, or applies it over read, the claim's own object, without
// forcing ownership: a field another manager holds is a conflict, not a
// takeover. The apply carries the UID and resource version of read, so an
// object changed or made anew since it was judged the claim's is refused by
// the apiserver instead of written; the next pass judges it again.
func put(ctx context.Context, cs *ClientSet, obj, read client.Object, found bool) error {
	if !found {
		return cs.Client.Create(ctx, obj, client.FieldOwner(FieldManager))
	}
	obj.SetUID(read.GetUID())
	obj.SetResourceVersion(read.GetResourceVersion())
	return cs.Client.Patch(ctx, obj, client.Apply, client.FieldOwner(FieldManager))
}

// DeleteTokenReviewerSA removes the claim's own SA and CRB; the namespace is
// left alone because it may host other resources. Each delete carries the UID
// and resource version it read, so an object replaced since is not removed.
// An object without this claim's labels is left and reported as a
// ForeignReviewerError; NotFound is fine.
func DeleteTokenReviewerSA(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim) error {
	ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
	if ref.Namespace == "" || ref.Name == "" {
		return nil
	}
	errs := make([]error, 0, 2)
	for _, o := range []struct {
		kind string
		key  client.ObjectKey
		obj  client.Object
	}{
		{"ServiceAccount", client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &corev1.ServiceAccount{}},
		{"ClusterRoleBinding", client.ObjectKey{Name: ref.Name + CRBSuffix}, &rbacv1.ClusterRoleBinding{}},
	} {
		found, err := existing(ctx, cs, claim, o.key, o.obj, o.kind)
		if err != nil || !found {
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		uid, rv := o.obj.GetUID(), o.obj.GetResourceVersion()
		if err := cs.Client.Delete(ctx, o.obj, client.Preconditions{UID: &uid, ResourceVersion: &rv}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %s %s: %w", o.kind, o.key, err))
		}
	}
	return errors.Join(errs...)
}
