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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

func raceClaim(name string) *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: vaultv1alpha1.VaultClaimSpec{Auth: vaultv1alpha1.AuthSpec{
			MountPath: "kubernetes-" + name,
			TokenReviewer: vaultv1alpha1.TokenReviewerSpec{ServiceAccount: vaultv1alpha1.ServiceAccountRef{
				Namespace: "reviewer-" + name, Name: "vault-token-reviewer", AutoCreate: true,
			}},
		}},
	}
}

func raceLabels(c *vaultv1alpha1.VaultClaim) map[string]string {
	return map[string]string{vaultv1alpha1.LabelClaimName: c.Name, vaultv1alpha1.LabelClaimNamespace: c.Namespace}
}

func raceSA(c *vaultv1alpha1.VaultClaim, labels map[string]string) *corev1.ServiceAccount {
	ref := c.Spec.Auth.TokenReviewer.ServiceAccount
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name, Labels: labels}}
}

func raceCRB(c *vaultv1alpha1.VaultClaim, labels map[string]string) *rbacv1.ClusterRoleBinding {
	ref := c.Spec.Auth.TokenReviewer.ServiceAccount
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: ref.Name + target.CRBSuffix, Labels: labels},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: target.ClusterRoleAuthDelegator},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ref.Namespace, Name: ref.Name}},
	}
}

// The reviewer objects judged the claim's by their labels are written only as
// they were read: an object deleted and made again without the labels in
// between keeps its labels, the write fails, and the next pass reports it as
// foreign. A real apiserver judges the write; the replacement happens at the
// moment the write is sent. The twin with nothing replaced is written.
var _ = Describe("Reviewer objects replaced between the read and the write", func() {
	DescribeTable("on a real apiserver",
		func(name, kind string, replace bool) {
			ctx := context.Background()
			claim := raceClaim(name)
			// The binding name carries the claim name so that the
			// cluster-scoped objects of the entries do not meet.
			claim.Spec.Auth.TokenReviewer.ServiceAccount.Name = "vault-token-reviewer-" + name
			ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
			Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ref.Namespace}})).To(Succeed())
			Expect(k8sClient.Create(ctx, raceSA(claim, raceLabels(claim)))).To(Succeed())
			crbName := ref.Name + target.CRBSuffix
			Expect(k8sClient.Create(ctx, raceCRB(claim, raceLabels(claim)))).To(Succeed())

			watching, err := client.NewWithWatch(cfg, client.Options{Scheme: k8sClient.Scheme()})
			Expect(err).NotTo(HaveOccurred())
			var replacedUID string
			swap := func(ctx context.Context, c client.WithWatch, obj client.Object) {
				if !replace || replacedUID != "" {
					return
				}
				var fresh client.Object
				switch obj.(type) {
				case *corev1.ServiceAccount:
					if kind != "ServiceAccount" {
						return
					}
					fresh = raceSA(claim, nil)
				case *rbacv1.ClusterRoleBinding:
					if kind != "ClusterRoleBinding" {
						return
					}
					fresh = raceCRB(claim, nil)
				default:
					return
				}
				Expect(c.Delete(ctx, fresh.DeepCopyObject().(client.Object))).To(Succeed())
				Expect(c.Create(ctx, fresh)).To(Succeed())
				replacedUID = string(fresh.GetUID())
			}
			intercepted := interceptor.NewClient(watching, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					swap(ctx, c, obj)
					return c.Patch(ctx, obj, patch, opts...)
				},
				Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					swap(ctx, c, obj)
					return c.Update(ctx, obj, opts...)
				},
			})

			err = target.EnsureTokenReviewerSA(ctx, &target.ClientSet{Client: intercepted}, claim)
			if !replace {
				Expect(err).NotTo(HaveOccurred())
				return
			}
			Expect(replacedUID).NotTo(BeEmpty(), "no write reached the %s", kind)
			Expect(err).To(HaveOccurred(), "the %s replaced after the read was written", kind)

			var got client.Object = &corev1.ServiceAccount{}
			key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
			if kind == "ClusterRoleBinding" {
				got, key = &rbacv1.ClusterRoleBinding{}, client.ObjectKey{Name: crbName}
			}
			Expect(k8sClient.Get(ctx, key, got)).To(Succeed())
			Expect(string(got.GetUID())).To(Equal(replacedUID))
			Expect(got.GetLabels()).NotTo(HaveKey(vaultv1alpha1.LabelClaimName), "the replacement %s carries the claim's labels", kind)

			err = target.EnsureTokenReviewerSA(ctx, &target.ClientSet{Client: k8sClient}, claim)
			Expect(target.IsForeignReviewer(err)).To(BeTrue(), "next pass: %v", err)
		},
		Entry("ServiceAccount replaced", "rr0001", "ServiceAccount", true),
		Entry("ClusterRoleBinding replaced", "rr0002", "ClusterRoleBinding", true),
		Entry("nothing replaced", "rr0003", "ServiceAccount", false),
	)
})
