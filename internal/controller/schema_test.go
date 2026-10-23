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
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// schemaClaim is a claim the schema admits; each entry below changes one fact.
func schemaClaim() *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "schema", Namespace: "default"},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: "default"},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: "schema"},
			SecretsPrefix:  "clusters/schema",
			Auth: vaultv1alpha1.AuthSpec{
				MountPath: "kubernetes-schema",
				TokenReviewer: vaultv1alpha1.TokenReviewerSpec{ServiceAccount: vaultv1alpha1.ServiceAccountRef{
					Namespace: "vault-reviewer", Name: "vault-token-reviewer"}},
			},
			Policies: []vaultv1alpha1.PolicySpec{{Name: "schema-apps", Rules: `path "secret/data/clusters/schema/x" { capabilities = ["read"] }`}},
			Roles: []vaultv1alpha1.RoleSpec{{
				Name:                 "apps",
				BoundServiceAccounts: vaultv1alpha1.BoundServiceAccounts{Name: "reader", Namespace: "apps"},
				Policies:             []string{"schema-apps"},
			}},
		},
	}
}

func dryRunCreate(mutate func(c *vaultv1alpha1.VaultClaim)) error {
	c := schemaClaim()
	mutate(c)
	return k8sClient.Create(context.Background(), c, client.DryRunAll)
}

func identityPaths(paths ...string) []vaultv1alpha1.IdentityPath {
	out := make([]vaultv1alpha1.IdentityPath, 0, len(paths))
	for _, p := range paths {
		out = append(out, vaultv1alpha1.IdentityPath{Path: p, Capabilities: []string{"read"}})
	}
	return out
}

var _ = Describe("VaultClaim schema for template roles", func() {
	It("admits the base claim", func() {
		Expect(dryRunCreate(func(*vaultv1alpha1.VaultClaim) {})).To(Succeed())
	})

	DescribeTable("boundServiceAccounts",
		func(mutate func(b *vaultv1alpha1.BoundServiceAccounts), admitted bool) {
			err := dryRunCreate(func(c *vaultv1alpha1.VaultClaim) { mutate(&c.Spec.Roles[0].BoundServiceAccounts) })
			if admitted {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("a name", func(b *vaultv1alpha1.BoundServiceAccounts) {}, true),
		Entry("the glob *", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name = "*" }, false),
		Entry("a ? in the name", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name = "app-?" }, false),
		Entry("a [ in the name", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name = "app[12]" }, false),
		Entry("a prefix glob", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name = "app-*" }, false),
		Entry("the namespace *", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Namespace = "*" }, false),
		Entry("names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", []string{"zot-1", "zot-2"} }, true),
		Entry("names and name", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Names = []string{"zot-1"} }, false),
		Entry("neither", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name = "" }, false),
		Entry("a glob in names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", []string{"zot-*"} }, false),
		Entry("an upper-case name in names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", []string{"Zot"} }, false),
		Entry("a repeated name in names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", []string{"zot", "zot"} }, false),
		Entry("32 names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", numbered(32) }, true),
		Entry("33 names", func(b *vaultv1alpha1.BoundServiceAccounts) { b.Name, b.Names = "", numbered(33) }, false),
	)

	DescribeTable("aliasNameSource",
		func(v string, admitted bool) {
			err := dryRunCreate(func(c *vaultv1alpha1.VaultClaim) { c.Spec.Roles[0].AliasNameSource = v })
			if admitted {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("serviceaccount_name", vaultv1alpha1.AliasNameSourceName, true),
		Entry("serviceaccount_uid", vaultv1alpha1.AliasNameSourceUID, true),
		Entry("another value", "serviceaccount_secret", false),
	)

	DescribeTable("policies[].identityPaths",
		func(mutate func(p *vaultv1alpha1.PolicySpec), admitted bool) {
			err := dryRunCreate(func(c *vaultv1alpha1.VaultClaim) { mutate(&c.Spec.Policies[0]) })
			if admitted {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("both placeholders", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("secret/data/clusters/schema/{serviceAccountNamespace}/{serviceAccountName}")
		}, true),
		Entry("identityPaths without rules", func(p *vaultv1alpha1.PolicySpec) {
			p.Rules, p.IdentityPaths = "", identityPaths("secret/data/clusters/schema/{serviceAccountName}")
		}, true),
		Entry("neither rules nor identityPaths", func(p *vaultv1alpha1.PolicySpec) { p.Rules = "" }, false),
		Entry("no placeholder", func(p *vaultv1alpha1.PolicySpec) { p.IdentityPaths = identityPaths("secret/data/clusters/schema/x") }, false),
		Entry("the reserved {meta.<key>}", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("secret/data/clusters/schema/{meta.area}/{serviceAccountName}")
		}, false),
		Entry("a glob", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("secret/data/clusters/schema/*/{serviceAccountName}")
		}, false),
		Entry("a + segment", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("secret/data/clusters/+/{serviceAccountName}")
		}, false),
		Entry("a leading /", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("/secret/data/clusters/schema/{serviceAccountName}")
		}, false),
		Entry("a .. segment", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = identityPaths("secret/data/clusters/schema/../{serviceAccountName}")
		}, false),
		Entry("sudo", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = []vaultv1alpha1.IdentityPath{{Path: "secret/data/clusters/schema/{serviceAccountName}", Capabilities: []string{"sudo"}}}
		}, false),
		Entry("deny", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = []vaultv1alpha1.IdentityPath{{Path: "secret/data/clusters/schema/{serviceAccountName}", Capabilities: []string{"deny"}}}
		}, false),
		Entry("no capabilities", func(p *vaultv1alpha1.PolicySpec) {
			p.IdentityPaths = []vaultv1alpha1.IdentityPath{{Path: "secret/data/clusters/schema/{serviceAccountName}"}}
		}, false),
		Entry("rules at the length limit", func(p *vaultv1alpha1.PolicySpec) {
			p.Rules = "#" + strings.Repeat("x", vaultv1alpha1.MaxRulesLength-1)
		}, true),
		Entry("rules past the length limit", func(p *vaultv1alpha1.PolicySpec) {
			p.Rules = "#" + strings.Repeat("x", vaultv1alpha1.MaxRulesLength)
		}, false),
	)
})

func numbered(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("sa-%02d", i))
	}
	return out
}
