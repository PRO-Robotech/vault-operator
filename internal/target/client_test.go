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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const sampleKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://example.invalid:6443
    insecure-skip-tls-verify: true
  name: target
contexts:
- context:
    cluster: target
    user: token-reviewer
  name: target
current-context: target
users:
- name: token-reviewer
  user:
    token: bogus
`

func TestClusterManager_GetParsesKubeconfigOnce(t *testing.T) {
	scheme := newTargetTestScheme(t)
	cm := NewClusterManager(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc", Namespace: "ns"},
		Data:       map[string][]byte{KubeconfigKey: []byte(sampleKubeconfig)},
	}

	got1, err := cm.Get(context.Background(), secret)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if got1 == nil || got1.Client == nil || got1.Kubernetes == nil {
		t.Fatal("expected populated ClientSet")
	}

	got2, err := cm.Get(context.Background(), secret)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got1 != got2 {
		t.Error("expected cached ClientSet to be reused")
	}

	// Mutate the kubeconfig bytes → cache must be invalidated.
	secret.Data[KubeconfigKey] = []byte(strings.Replace(sampleKubeconfig, "example.invalid", "other.invalid", 1))
	got3, err := cm.Get(context.Background(), secret)
	if err != nil {
		t.Fatalf("Get after change: %v", err)
	}
	if got1 == got3 {
		t.Error("expected fresh ClientSet after kubeconfig change")
	}
}

func TestClusterManager_GetRejectsMissingKubeconfig(t *testing.T) {
	scheme := newTargetTestScheme(t)
	cm := NewClusterManager(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc", Namespace: "ns"},
		Data:       map[string][]byte{"other": []byte("x")},
	}

	if _, err := cm.Get(context.Background(), secret); err == nil {
		t.Fatal("expected error when KubeconfigKey is absent")
	}
}

func TestClusterManager_GetRejectsMalformedKubeconfig(t *testing.T) {
	scheme := newTargetTestScheme(t)
	cm := NewClusterManager(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc", Namespace: "ns"},
		Data:       map[string][]byte{KubeconfigKey: []byte("not-yaml")},
	}

	if _, err := cm.Get(context.Background(), secret); err == nil {
		t.Fatal("expected parse error")
	}
}
