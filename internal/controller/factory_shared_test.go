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
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const revokeCall = "POST auth/token/revoke-self"

func factoryConfig(addr string, generation int64) *vaultv1alpha1.VaultConfig {
	return &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "shared", Generation: generation},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address:     addr,
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{MountPath: "kubernetes-mgmt", Role: "vault-operator"},
		},
	}
}

// A process with a VaultConfig probe and a claim controller on one
// VaultConfig holds one client: the secret factory hands out the shared one.
func TestSecretFactoryHandsOutTheSharedClient(t *testing.T) {
	v := newHTTPVault().start()
	t.Cleanup(v.Close)
	shared := &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	secrets := &DefaultSecretVaultClientFactory{Shared: shared}
	cfg := factoryConfig(v.URL, 1)

	a, err := shared.For(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	b, err := secrets.For(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if a.(*vault.Client) != b.(*vault.Client) {
		t.Fatal("the two factories built two clients for one VaultConfig")
	}
	if err := a.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	if err := b.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	if n := v.logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1", n)
	}
}

// Twin: without Shared the secret factory keeps its own client.
func TestSecretFactoryWithoutSharedKeepsItsOwn(t *testing.T) {
	v := newHTTPVault().start()
	t.Cleanup(v.Close)
	shared := &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	own := &DefaultSecretVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	cfg := factoryConfig(v.URL, 1)
	a, _ := shared.For(context.Background(), nil, cfg)
	b, _ := own.For(context.Background(), nil, cfg)
	if a.(*vault.Client) == b.(*vault.Client) {
		t.Fatal("an unshared factory handed out the shared client")
	}
}

// At shutdown the factory gives every token back.
func TestFactoryRevokeAllGivesTheTokensBack(t *testing.T) {
	v := newHTTPVault().start()
	t.Cleanup(v.Close)
	f := &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	vc, err := f.For(context.Background(), nil, factoryConfig(v.URL, 1))
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if err := vc.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	f.RevokeAll(context.Background())
	if calls := v.calls(); !slices.Contains(calls, revokeCall) {
		t.Fatalf("calls %v, want a revoke-self", calls)
	}
}

// A new generation of the VaultConfig gets a new client, and the old token is
// revoked rather than left to its TTL.
func TestFactoryNewGenerationRevokesTheOldToken(t *testing.T) {
	v := newHTTPVault().start()
	t.Cleanup(v.Close)
	f := &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	old, err := f.For(context.Background(), nil, factoryConfig(v.URL, 1))
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if err := old.EnsureLoggedIn(context.Background()); err != nil {
		t.Fatalf("EnsureLoggedIn: %v", err)
	}
	fresh, err := f.For(context.Background(), nil, factoryConfig(v.URL, 2))
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if fresh.(*vault.Client) == old.(*vault.Client) {
		t.Fatal("a new generation reused the client")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(v.calls(), revokeCall) {
		if time.Now().After(deadline) {
			t.Fatalf("calls %v: the replaced token was not revoked", v.calls())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A bundle that cannot be re-read leaves the working client in place; a
// changed one replaces it and keeps the token.
func TestFactoryRevalidateRebuildsOnlyOnAChangedBundle(t *testing.T) {
	ca1, err := newTestCA("ca-1")
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	ca2, err := newTestCA("ca-2")
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-ca", Namespace: "ns"},
		Data:       map[string][]byte{"ca.crt": ca1.caPEM},
	}
	cli := fakeclient.NewClientBuilder().WithScheme(newCATestScheme(t)).WithObjects(secret).Build()
	cfg := factoryConfig("https://127.0.0.1:1", 1)
	cfg.Spec.TLS = &vaultv1alpha1.TLSSpec{CABundleSecretRef: &vaultv1alpha1.SecretKeySelector{Name: "vault-ca", Namespace: "ns", Key: "ca.crt"}}
	f := &DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource("jwt")}
	ctx := context.Background()

	first, err := f.For(ctx, cli, cfg)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if err := f.Revalidate(ctx, cli, cfg); err != nil {
		t.Fatalf("Revalidate of an unchanged bundle: %v", err)
	}
	if again, _ := f.For(ctx, cli, cfg); again.(*vault.Client) != first.(*vault.Client) {
		t.Fatal("an unchanged bundle rebuilt the client")
	}

	if err := cli.Delete(ctx, secret); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := f.Revalidate(ctx, cli, cfg); err == nil {
		t.Fatal("an unreadable bundle was not reported")
	}
	if again, _ := f.For(ctx, cli, cfg); again.(*vault.Client) != first.(*vault.Client) {
		t.Fatal("an unreadable bundle dropped the working client")
	}

	secret.ResourceVersion = ""
	secret.Data["ca.crt"] = ca2.caPEM
	if err := cli.Create(ctx, secret); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Revalidate(ctx, cli, cfg); err != nil {
		t.Fatalf("Revalidate of a rotated bundle: %v", err)
	}
	if again, _ := f.For(ctx, cli, cfg); again.(*vault.Client) == first.(*vault.Client) {
		t.Fatal("a rotated bundle kept the old client")
	}
}
