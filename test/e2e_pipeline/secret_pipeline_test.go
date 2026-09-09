//go:build e2e
// +build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package e2e_pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	secretConfigName = "vault-secret"
	secretRole       = "vault-secret-operator"
	secretClaimName  = "scl001"
)

// TestSecretPipelineE2E exercises the VaultSecretClaim pipeline (generate +
// copy + Purge) against a real `vault server -dev` and envtest. Skips if the
// vault binary or envtest assets are unavailable.
func TestSecretPipelineE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	vaultSrv, err := NewVaultDevServer(ctx)
	if err != nil {
		if errors.Is(err, ErrVaultBinaryMissing) {
			t.Skipf("vault binary not in PATH; skipping secret pipeline e2e: %v", err)
		}
		t.Fatalf("start vault dev: %v", err)
	}
	defer func() { _ = vaultSrv.Close() }()

	if err := EnsureKVMount(ctx, vaultSrv, sharedKVMount); err != nil {
		t.Fatalf("ensure KV mount: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	if err := vaultv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	testEnv := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	if bin := firstEnvtestBinaryDir(); bin != "" {
		testEnv.BinaryAssetsDirectory = bin
	}
	envCfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("envtest.Start: %v", err)
	}
	defer func() { _ = testEnv.Stop() }()

	k8sClient, err := client.New(envCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("k8s client: %v", err)
	}
	kc, err := kubernetes.NewForConfig(envCfg)
	if err != nil {
		t.Fatalf("kube clientset: %v", err)
	}

	if err := bootstrapOperatorSA(ctx, k8sClient); err != nil {
		t.Fatalf("bootstrap operator SA: %v", err)
	}
	// Default audience (nil) — see note in pipeline_test.go.
	operatorJWT, err := issueSAJWT(ctx, kc, operatorNS, operatorSA, nil)
	if err != nil {
		t.Fatalf("issue operator SA JWT: %v", err)
	}

	// Enable the shared kubernetes auth method + reviewer config, then add the
	// secret operator's role/policy alongside it.
	if err := BootstrapVaultDev(ctx, vaultSrv, BootstrapConfig{
		ManagerAuthPath:   mgmtAuthPath,
		ManagerRole:       mgmtRole,
		KubernetesHost:    envCfg.Host,
		KubernetesCACert:  string(envCfg.CAData),
		TokenReviewerJWT:  operatorJWT,
		SABoundNames:      []string{operatorSA},
		SABoundNamespaces: []string{operatorNS},
	}); err != nil {
		t.Fatalf("bootstrap vault: %v", err)
	}
	if err := BootstrapSecretRole(ctx, vaultSrv, mgmtAuthPath, secretRole, []string{operatorSA}, []string{operatorNS}); err != nil {
		t.Fatalf("bootstrap secret role: %v", err)
	}

	// Seed the copy source.
	if err := SeedKV(ctx, vaultSrv, sharedKVMount, "system/dex", map[string]interface{}{"staticClient": "abc123"}); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	factory := &controller.DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource(operatorJWT)}
	secretFactory := &controller.DefaultSecretVaultClientFactory{JWTSource: vault.StaticJWTSource(operatorJWT)}

	vcfgReconciler := &controller.VaultConfigReconciler{
		Client:           k8sClient,
		Scheme:           scheme,
		VaultFactory:     factory,
		VaultConfigOwner: vaultv1alpha1.OwnerVaultSecretOperator,
	}
	claimReconciler := &controller.VaultSecretClaimReconciler{
		Client:       k8sClient,
		Scheme:       scheme,
		VaultFactory: secretFactory,
	}

	vcfg := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:   secretConfigName,
			Labels: map[string]string{vaultv1alpha1.LabelVaultConfigOwner: vaultv1alpha1.OwnerVaultSecretOperator},
		},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address: vaultSrv.Addr,
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
				Method:    vaultv1alpha1.AuthMethodKubernetes,
				MountPath: mgmtAuthPath,
				Role:      secretRole,
			},
			Storage: vaultv1alpha1.StorageSpec{KvMountPath: sharedKVMount},
		},
	}
	if err := k8sClient.Create(ctx, vcfg); err != nil {
		t.Fatalf("create VaultConfig: %v", err)
	}

	reconcileUntil(t, ctx, "VaultConfig", 10*time.Second, func() (bool, error) {
		if _, rerr := vcfgReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: vcfg.Name}}); rerr != nil {
			return false, rerr
		}
		got := &vaultv1alpha1.VaultConfig{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: vcfg.Name}, got); err != nil {
			return false, err
		}
		return isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionReachable) &&
			isConditionTrue(got.Status.Conditions, vaultv1alpha1.ConditionSharedMountFound), nil
	})

	claim := &vaultv1alpha1.VaultSecretClaim{
		ObjectMeta: metav1.ObjectMeta{Name: secretClaimName, Namespace: claimNS},
		Spec: vaultv1alpha1.VaultSecretClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: secretConfigName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: secretClaimName},
			SecretsPrefix:  "clusters/" + secretClaimName,
			DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
			SecretList: []vaultv1alpha1.SecretListItem{
				{
					Name:        "argocd-admin",
					Type:        vaultv1alpha1.SecretTypeGenerate,
					Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "admin.password", HashedKey: "admin.passwordBcrypt"},
					Generate:    &vaultv1alpha1.GenerateSpec{Length: 16, Hash: vaultv1alpha1.HashBcrypt},
				},
				{
					Name:        "grafana-oidc",
					Type:        vaultv1alpha1.SecretTypeCopy,
					Source:      &vaultv1alpha1.SourceSpec{Path: "system/dex", Key: "staticClient"},
					Destination: vaultv1alpha1.DestinationSpec{Path: "grafana", Key: "staticClient"},
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, claim); err != nil {
		t.Fatalf("create VaultSecretClaim: %v", err)
	}

	reconcileUntil(t, ctx, "VaultSecretClaim", 20*time.Second, func() (bool, error) {
		if _, rerr := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}}); rerr != nil {
			return false, rerr
		}
		got := &vaultv1alpha1.VaultSecretClaim{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, got); err != nil {
			return false, err
		}
		return got.Status.Phase == vaultv1alpha1.PhaseReady, nil
	})

	// Verify generate + copy landed in Vault.
	grafana, err := ReadKVRoot(ctx, vaultSrv, sharedKVMount, "clusters/"+secretClaimName+"/grafana")
	if err != nil {
		t.Fatalf("read grafana secret: %v", err)
	}
	if grafana["staticClient"] != "abc123" {
		t.Fatalf("copied staticClient = %v, want abc123", grafana["staticClient"])
	}
	argocd, err := ReadKVRoot(ctx, vaultSrv, sharedKVMount, "clusters/"+secretClaimName+"/argocd")
	if err != nil {
		t.Fatalf("read argocd secret: %v", err)
	}
	pw, _ := argocd["admin.password"].(string)
	if len(pw) != 16 {
		t.Fatalf("generated admin.password length = %d, want 16", len(pw))
	}
	if bh, _ := argocd["admin.passwordBcrypt"].(string); !strings.HasPrefix(bh, "$2a$") {
		t.Fatalf("admin.passwordBcrypt = %q, want $2a$ prefix", bh)
	}

	// Delete with Purge → secrets removed.
	if err := k8sClient.Delete(ctx, claim); err != nil {
		t.Fatalf("delete VaultSecretClaim: %v", err)
	}
	reconcileUntil(t, ctx, "VaultSecretClaim-delete", 15*time.Second, func() (bool, error) {
		if _, rerr := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}}); rerr != nil {
			return false, rerr
		}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}, &vaultv1alpha1.VaultSecretClaim{})
		return err != nil, nil
	})

	if _, err := ReadKVRoot(ctx, vaultSrv, sharedKVMount, "clusters/"+secretClaimName+"/argocd"); err == nil {
		t.Errorf("argocd secret still present after Purge")
	}
	if _, err := ReadKVRoot(ctx, vaultSrv, sharedKVMount, "clusters/"+secretClaimName+"/grafana"); err == nil {
		t.Errorf("grafana secret still present after Purge")
	}
}
