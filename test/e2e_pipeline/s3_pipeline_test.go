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
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
	pb "github.com/PRO-Robotech/vault-operator/internal/cloudmanager/proto"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

const (
	s3ConfigName = "s3-bucket"
	s3Role       = "s3-bucket-operator"
	s3ClaimName  = "s3e2e01"
	s3Login      = "cust-e2e"
	s3Foreign    = "theirs"
)

// s3BucketOperatorPolicy is the production shape (only the per-cluster s3
// leaf) plus the leaf the destinationPath-change scenario moves to.
const s3BucketOperatorPolicy = `
path "sys/mounts"                              { capabilities = ["read", "list"] }
path "secret/data/clusters/+/s3"               { capabilities = ["create", "update", "read"] }
path "secret/metadata/clusters/+/s3"           { capabilities = ["read", "delete"] }
path "secret/data/clusters/+/backup/s3"        { capabilities = ["create", "update", "read"] }
path "secret/metadata/clusters/+/backup/s3"    { capabilities = ["read", "delete"] }
path "auth/token/renew-self"                   { capabilities = ["update"] }
path "auth/token/lookup-self"                  { capabilities = ["read"] }
`

// TestS3BucketPipelineE2E runs the S3BucketClaim pipeline against a real
// `vault server -dev` and envtest, with cloud-manager served by cmfake over
// gRPC (the real client, the server semantics of cloud-manager). It checks
// the result in Vault and in the fake, not the calls made.
func TestS3BucketPipelineE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	vaultSrv := StartVaultDev(ctx, t)
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
	operatorJWT, err := issueSAJWT(ctx, kc, operatorNS, operatorSA, nil)
	if err != nil {
		t.Fatalf("issue operator SA JWT: %v", err)
	}
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
	if err := vaultPut(ctx, vaultSrv, "/v1/sys/policies/acl/s3-bucket-operator", map[string]string{"policy": s3BucketOperatorPolicy}); err != nil {
		t.Fatalf("write s3 policy: %v", err)
	}
	if err := vaultPost(ctx, vaultSrv, "/v1/auth/"+mgmtAuthPath+"/role/"+s3Role, map[string]interface{}{
		"bound_service_account_names":      []string{operatorSA},
		"bound_service_account_namespaces": []string{operatorNS},
		"token_policies":                   []string{"s3-bucket-operator"},
		"token_ttl":                        3600,
	}); err != nil {
		t.Fatalf("create s3 role: %v", err)
	}

	cm := cmfake.New()
	lis := cmfake.Serve(cm)
	defer lis.Stop()
	conn, err := lis.Dial()
	if err != nil {
		t.Fatalf("dial fake cloud-manager: %v", err)
	}
	buckets := cloudmanager.NewFromConn(conn, cloudmanager.DefaultOptions())
	defer func() { _ = buckets.Close() }()

	vcfgReconciler := &controller.VaultConfigReconciler{
		Client:           k8sClient,
		Scheme:           scheme,
		VaultFactory:     &controller.DefaultVaultClientFactory{JWTSource: vault.StaticJWTSource(operatorJWT)},
		VaultConfigOwner: vaultv1alpha1.OwnerBucketOperator,
	}
	claimReconciler := &controller.S3BucketClaimReconciler{
		Client:                 k8sClient,
		Scheme:                 scheme,
		VaultFactory:           &controller.DefaultSecretVaultClientFactory{JWTSource: vault.StaticJWTSource(operatorJWT)},
		Buckets:                buckets,
		DefaultConfigurationID: "s3_v1",
	}

	vcfg := &vaultv1alpha1.VaultConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:   s3ConfigName,
			Labels: map[string]string{vaultv1alpha1.LabelVaultConfigOwner: vaultv1alpha1.OwnerBucketOperator},
		},
		Spec: vaultv1alpha1.VaultConfigSpec{
			Address: vaultSrv.Addr,
			ManagerAuth: vaultv1alpha1.ManagerAuthSpec{
				Method: vaultv1alpha1.AuthMethodKubernetes, MountPath: mgmtAuthPath, Role: s3Role,
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

	// The production shape of a cluster claim.
	claim := &vaultv1alpha1.S3BucketClaim{
		ObjectMeta: metav1.ObjectMeta{Name: s3ClaimName, Namespace: claimNS},
		Spec: vaultv1alpha1.S3BucketClaimSpec{
			VaultConfigRef: vaultv1alpha1.VaultConfigRef{Name: s3ConfigName},
			ClusterRef:     vaultv1alpha1.SecretClusterRef{Name: s3ClaimName},
			CustomerLogin:  s3Login,
			Region:         "ru1",
			Bucket:         vaultv1alpha1.S3BucketSpec{ManagedBy: vaultv1alpha1.S3ManagedBySystem, ConfigurationID: "s3_v1"},
			Vault:          vaultv1alpha1.S3VaultSpec{SecretsPrefix: "clusters/" + s3ClaimName, DestinationPath: "s3"},
			DeletionPolicy: vaultv1alpha1.DeletionPolicyPurge,
		},
	}
	if err := k8sClient.Create(ctx, claim); err != nil {
		t.Fatalf("create S3BucketClaim: %v", err)
	}
	key := types.NamespacedName{Name: claim.Name, Namespace: claim.Namespace}
	reconcileOnce := func() {
		t.Helper()
		if _, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	get := func() *vaultv1alpha1.S3BucketClaim {
		t.Helper()
		got := &vaultv1alpha1.S3BucketClaim{}
		if err := k8sClient.Get(ctx, key, got); err != nil {
			t.Fatalf("get claim: %v", err)
		}
		return got
	}
	leafPath := "clusters/" + s3ClaimName + "/s3"
	movedPath := "clusters/" + s3ClaimName + "/backup/s3"

	reconcileUntil(t, ctx, "S3BucketClaim", 20*time.Second, func() (bool, error) {
		reconcileOnce()
		return get().Status.Phase == vaultv1alpha1.PhaseReady, nil
	})
	got := get()
	if got.Status.BucketOwnership != vaultv1alpha1.BucketOwnershipCreated || got.Status.WrittenPath != "s3" {
		t.Fatalf("status ownership=%q writtenPath=%q", got.Status.BucketOwnership, got.Status.WrittenPath)
	}
	bucketName := got.Status.BucketName
	leaf := mustReadKV(ctx, t, vaultSrv, leafPath)
	if leaf["bucketName"] != bucketName || leaf["accessKey"] != "AK-"+bucketName || leaf["s3ForcePathStyle"] != "true" {
		t.Fatalf("leaf = %v", leaf)
	}

	// Steady state: further passes create no KV version.
	v0 := mustKVVersion(ctx, t, vaultSrv, leafPath)
	for i := 0; i < 3; i++ {
		reconcileOnce()
	}
	if v := mustKVVersion(ctx, t, vaultSrv, leafPath); v != v0 {
		t.Fatalf("steady state wrote: version %d -> %d", v0, v)
	}

	// A key removed outside the operator is restored by the next pass; a
	// foreign key added next to ours survives it.
	delete(leaf, "secretKey")
	leaf["registry"] = s3Foreign
	if err := SeedKV(ctx, vaultSrv, sharedKVMount, leafPath, leaf); err != nil {
		t.Fatalf("tamper leaf: %v", err)
	}
	reconcileOnce()
	leaf = mustReadKV(ctx, t, vaultSrv, leafPath)
	if leaf["secretKey"] != "SK-"+bucketName || leaf["registry"] != s3Foreign {
		t.Fatalf("after repair leaf = %v", leaf)
	}

	// destinationPath change: keys move, the foreign value stays where it was.
	got = get()
	got.Spec.Vault.DestinationPath = "backup/s3"
	if err := k8sClient.Update(ctx, got); err != nil {
		t.Fatalf("update destinationPath: %v", err)
	}
	reconcileOnce()
	if moved := mustReadKV(ctx, t, vaultSrv, movedPath); moved["accessKey"] != "AK-"+bucketName {
		t.Fatalf("moved leaf = %v", moved)
	}
	if old := mustReadKV(ctx, t, vaultSrv, leafPath); len(old) != 1 || old["registry"] != s3Foreign {
		t.Fatalf("old leaf after move = %v, want only the foreign key", old)
	}

	// Purge: the bucket goes REMOVED, the claim's leaf (only its keys) is
	// deleted, the foreign value at the old path is untouched.
	if err := k8sClient.Delete(ctx, get()); err != nil {
		t.Fatalf("delete claim: %v", err)
	}
	reconcileUntil(t, ctx, "S3BucketClaim-delete", 20*time.Second, func() (bool, error) {
		if _, err := claimReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key}); err != nil {
			return false, err
		}
		err := k8sClient.Get(ctx, key, &vaultv1alpha1.S3BucketClaim{})
		return apierrors.IsNotFound(err), nil
	})
	if b := cm.Get(bucketName); b == nil || b.GetStatus() != pb.Status_REMOVED {
		t.Fatalf("bucket after purge = %v, want REMOVED", b)
	}
	if _, err := ReadKVRoot(ctx, vaultSrv, sharedKVMount, movedPath); err == nil {
		t.Fatalf("claim leaf still present after purge")
	}
	if old := mustReadKV(ctx, t, vaultSrv, leafPath); old["registry"] != s3Foreign {
		t.Fatalf("foreign value after purge = %v", old)
	}
	if creates, _, removes := cm.Counters(); creates != 1 || removes != 1 {
		t.Fatalf("cloud-manager creates=%d removes=%d, want 1 and 1", creates, removes)
	}
}

func mustReadKV(ctx context.Context, t *testing.T, srv *VaultDevServer, path string) map[string]interface{} {
	t.Helper()
	data, err := ReadKVRoot(ctx, srv, sharedKVMount, path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func mustKVVersion(ctx context.Context, t *testing.T, srv *VaultDevServer, path string) int {
	t.Helper()
	body, err := vaultGet(ctx, srv, "/v1/"+sharedKVMount+"/metadata/"+path)
	if err != nil {
		t.Fatalf("read metadata %s: %v", path, err)
	}
	var raw struct {
		Data struct {
			CurrentVersion int `json:"current_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode metadata %s: %v", path, err)
	}
	if raw.Data.CurrentVersion == 0 {
		t.Fatalf("metadata %s: no current_version (%s)", path, fmt.Sprint(string(body)))
	}
	return raw.Data.CurrentVersion
}
