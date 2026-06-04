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
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

func newCATestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	return s
}

func TestLoadCABundle_Secret(t *testing.T) {
	s := newCATestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"server.crt": []byte("PEM-BUNDLE")},
	}
	cli := fakeclient.NewClientBuilder().WithScheme(s).WithObjects(secret).Build()

	got, err := loadCABundle(context.Background(), cli, &vaultv1alpha1.TLSSpec{
		CABundleSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "ca", Namespace: "ns", Key: "server.crt"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "PEM-BUNDLE" {
		t.Fatalf("got %q, want %q", got, "PEM-BUNDLE")
	}
}

func TestLoadCABundle_SecretMissingKey(t *testing.T) {
	s := newCATestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string][]byte{"other": []byte("nope")},
	}
	cli := fakeclient.NewClientBuilder().WithScheme(s).WithObjects(secret).Build()

	_, err := loadCABundle(context.Background(), cli, &vaultv1alpha1.TLSSpec{
		CABundleSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "ca", Namespace: "ns", Key: "server.crt"},
	})
	if err == nil || !strings.Contains(err.Error(), "server.crt") {
		t.Fatalf("expected error naming the missing key, got: %v", err)
	}
}

func TestLoadCABundle_ConfigMap(t *testing.T) {
	s := newCATestScheme(t)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
		Data:       map[string]string{"trust.pem": "PEM-FROM-CM"},
	}
	cli := fakeclient.NewClientBuilder().WithScheme(s).WithObjects(cm).Build()

	got, err := loadCABundle(context.Background(), cli, &vaultv1alpha1.TLSSpec{
		CABundleConfigMapRef: &vaultv1alpha1.ConfigMapKeySelector{Name: "ca", Namespace: "ns", Key: "trust.pem"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "PEM-FROM-CM" {
		t.Fatalf("got %q, want %q", got, "PEM-FROM-CM")
	}
}

func TestLoadCABundle_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, []byte("PEM-FROM-FILE"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cli := fakeclient.NewClientBuilder().WithScheme(newCATestScheme(t)).Build()
	got, err := loadCABundle(context.Background(), cli, &vaultv1alpha1.TLSSpec{CABundleFile: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "PEM-FROM-FILE" {
		t.Fatalf("got %q, want %q", got, "PEM-FROM-FILE")
	}
}

func TestLoadCABundle_None(t *testing.T) {
	cli := fakeclient.NewClientBuilder().WithScheme(newCATestScheme(t)).Build()
	got, err := loadCABundle(context.Background(), cli, &vaultv1alpha1.TLSSpec{ServerName: "vault.example"})
	if err != nil {
		t.Fatalf("unexpected error for empty spec: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil bytes for empty spec, got %q", got)
	}
}
