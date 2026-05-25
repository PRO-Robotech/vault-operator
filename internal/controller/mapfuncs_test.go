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
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func newMapfuncTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgoscheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("vault scheme: %v", err)
	}
	return s
}

func sortedRequestNames(reqs []reconcile.Request) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.Namespace + "/" + r.Name
	}
	sort.Strings(out)
	return out
}

func makeClaim(name, ns, configName, kubeconfigSecret string) *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: vaultv1alpha1.VaultClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: configName},
			ClusterRef:     vaultv1alpha1.ClusterRef{Name: name, KubeconfigSecret: kubeconfigSecret},
			Auth:           vaultv1alpha1.AuthSpec{MountPath: "kubernetes-" + name},
		},
	}
}

func TestFindClaimsForVaultConfig_FanOut(t *testing.T) {
	scheme := newMapfuncTestScheme(t)
	cli := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
		makeClaim("c1", "ns-a", "shared", ""),
		makeClaim("c2", "ns-b", "shared", ""),
		makeClaim("c3", "ns-a", "other", ""),
	).Build()
	r := &VaultClaimReconciler{Client: cli}

	got := r.findClaimsForVaultConfig(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: "shared"}})
	want := []string{"ns-a/c1", "ns-b/c2"}
	if reqs := sortedRequestNames(got); !equalSlices(reqs, want) {
		t.Errorf("got %v, want %v", reqs, want)
	}
}

func TestFindClaimsForVaultConfig_WrongType(t *testing.T) {
	r := &VaultClaimReconciler{Client: fakeclient.NewClientBuilder().WithScheme(newMapfuncTestScheme(t)).Build()}
	got := r.findClaimsForVaultConfig(context.Background(), &corev1.Secret{})
	if len(got) != 0 {
		t.Errorf("expected empty for wrong type, got %v", got)
	}
}

func TestFindClaimsForVaultConfig_NoMatches(t *testing.T) {
	scheme := newMapfuncTestScheme(t)
	cli := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
		makeClaim("c1", "ns-a", "other", ""),
	).Build()
	r := &VaultClaimReconciler{Client: cli}

	got := r.findClaimsForVaultConfig(context.Background(), &vaultv1alpha1.VaultConfig{ObjectMeta: metav1.ObjectMeta{Name: "nobody-refs-this"}})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestFindClaimsForSecret_DefaultNaming(t *testing.T) {
	scheme := newMapfuncTestScheme(t)
	// Claim c1 uses default convention {clusterRef.name}-infra-kubeconfig.
	c1 := makeClaim("c1", "ns-a", "shared", "")
	c1.Spec.ClusterRef.Name = "c1"
	cli := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(c1).Build()
	r := &VaultClaimReconciler{Client: cli}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "c1-infra-kubeconfig", Namespace: "ns-a"}}
	got := r.findClaimsForSecret(context.Background(), secret)
	if got := sortedRequestNames(got); !equalSlices(got, []string{"ns-a/c1"}) {
		t.Errorf("got %v want %v", got, []string{"ns-a/c1"})
	}
}

func TestFindClaimsForSecret_ExplicitOverride(t *testing.T) {
	scheme := newMapfuncTestScheme(t)
	c := makeClaim("c1", "ns-a", "shared", "custom-kc")
	cli := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(c).Build()
	r := &VaultClaimReconciler{Client: cli}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "custom-kc", Namespace: "ns-a"}}
	got := r.findClaimsForSecret(context.Background(), secret)
	if got := sortedRequestNames(got); !equalSlices(got, []string{"ns-a/c1"}) {
		t.Errorf("got %v want %v", got, []string{"ns-a/c1"})
	}
}

func TestFindClaimsForSecret_DifferentNamespaceIgnored(t *testing.T) {
	scheme := newMapfuncTestScheme(t)
	c := makeClaim("c1", "ns-a", "shared", "")
	c.Spec.ClusterRef.Name = "c1"
	cli := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(c).Build()
	r := &VaultClaimReconciler{Client: cli}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "c1-infra-kubeconfig", Namespace: "different-ns"}}
	got := r.findClaimsForSecret(context.Background(), secret)
	if len(got) != 0 {
		t.Errorf("expected empty (wrong namespace), got %v", got)
	}
}

func TestFindClaimsForSecret_WrongType(t *testing.T) {
	r := &VaultClaimReconciler{Client: fakeclient.NewClientBuilder().WithScheme(newMapfuncTestScheme(t)).Build()}
	got := r.findClaimsForSecret(context.Background(), &vaultv1alpha1.VaultClaim{})
	if len(got) != 0 {
		t.Errorf("expected empty for wrong type, got %v", got)
	}
}

func TestKubeconfigSecretPredicate(t *testing.T) {
	pred := kubeconfigSecretPredicate()

	cases := []struct {
		name   string
		secret string
		want   bool
	}{
		{"convention match", "ec8a00-infra-kubeconfig", true},
		{"random secret", "tls-cert", false},
		{"empty name", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tc.secret}}
			if got := pred.Create(event.CreateEvent{Object: s}); got != tc.want {
				t.Errorf("Create = %v, want %v", got, tc.want)
			}
			if got := pred.Update(event.UpdateEvent{ObjectNew: s}); got != tc.want {
				t.Errorf("Update = %v, want %v", got, tc.want)
			}
			if got := pred.Delete(event.DeleteEvent{Object: s}); got != tc.want {
				t.Errorf("Delete = %v, want %v", got, tc.want)
			}
			if got := pred.Generic(event.GenericEvent{Object: s}); got != tc.want {
				t.Errorf("Generic = %v, want %v", got, tc.want)
			}
		})
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// _ keeps client.Object referenced in case the file is split later.
var _ client.Object = (*vaultv1alpha1.VaultClaim)(nil)
