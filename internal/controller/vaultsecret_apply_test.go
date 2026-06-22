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
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/secretgen"
)

type fakeKV struct {
	store  map[string]map[string]any
	writes int
}

func newFakeKV() *fakeKV { return &fakeKV{store: map[string]map[string]any{}} }

func (f *fakeKV) seed(path string, data map[string]any) {
	f.store["secret|"+path] = cloneData(data)
}

func (f *fakeKV) ReadKV(_ context.Context, mount, path string) (map[string]any, bool, error) {
	d, ok := f.store[mount+"|"+path]
	if !ok {
		return nil, false, nil
	}
	return cloneData(d), true, nil
}

func (f *fakeKV) WriteKV(_ context.Context, mount, path string, data map[string]any) error {
	f.store[mount+"|"+path] = cloneData(data)
	f.writes++
	return nil
}

func copyItem() *vaultv1alpha1.SecretListItem {
	return &vaultv1alpha1.SecretListItem{
		Name:        "grafana-oidc",
		Type:        vaultv1alpha1.SecretTypeCopy,
		Source:      &vaultv1alpha1.SourceSpec{Path: "system/dex", Key: "staticClient"},
		Destination: vaultv1alpha1.DestinationSpec{Path: "grafana", Key: "staticClient"},
	}
}

func TestApplyCopy_WritesAndDetectsNoChange(t *testing.T) {
	kv := newFakeKV()
	kv.seed("system/dex", map[string]any{"staticClient": "abc"})
	item := copyItem()

	h1, changed, err := applyCopyItem(context.Background(), kv, "secret", "clusters/ec8a00", item, "")
	if err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	if got := kv.store["secret|clusters/ec8a00/grafana"]["staticClient"]; got != "abc" {
		t.Fatalf("destination = %v", got)
	}

	_, changed, err = applyCopyItem(context.Background(), kv, "secret", "clusters/ec8a00", item, h1)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if changed {
		t.Fatalf("expected no change when source hash matches")
	}
}

func TestApplyCopy_RecopiesOnSourceChange(t *testing.T) {
	kv := newFakeKV()
	kv.seed("system/dex", map[string]any{"staticClient": "abc"})
	item := copyItem()
	h1, _, _ := applyCopyItem(context.Background(), kv, "secret", "clusters/ec8a00", item, "")

	kv.seed("system/dex", map[string]any{"staticClient": "xyz"})
	h2, changed, err := applyCopyItem(context.Background(), kv, "secret", "clusters/ec8a00", item, h1)
	if err != nil || !changed {
		t.Fatalf("expected recopy on source change: changed=%v err=%v", changed, err)
	}
	if h1 == h2 {
		t.Fatalf("source hash should change with value")
	}
	if got := kv.store["secret|clusters/ec8a00/grafana"]["staticClient"]; got != "xyz" {
		t.Fatalf("destination not updated: %v", got)
	}
}

func TestApplyCopy_PreservesSiblingKeys(t *testing.T) {
	kv := newFakeKV()
	kv.seed("system/dex", map[string]any{"staticClient": "abc"})
	kv.seed("clusters/ec8a00/grafana", map[string]any{"other": "keep"})
	item := copyItem()

	if _, _, err := applyCopyItem(context.Background(), kv, "secret", "clusters/ec8a00", item, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	dst := kv.store["secret|clusters/ec8a00/grafana"]
	if dst["other"] != "keep" || dst["staticClient"] != "abc" {
		t.Fatalf("merge clobbered sibling key: %v", dst)
	}
}

func TestValidateCopySources_MissingSource(t *testing.T) {
	kv := newFakeKV()
	items := []vaultv1alpha1.SecretListItem{*copyItem()}
	err := validateCopySources(context.Background(), kv, "secret", items)
	if err == nil || !strings.Contains(err.Error(), "grafana-oidc") {
		t.Fatalf("expected missing-source error naming item, got %v", err)
	}
}

func genItem(hash, hashedKey string) *vaultv1alpha1.SecretListItem {
	return &vaultv1alpha1.SecretListItem{
		Name:        "argocd-admin",
		Type:        vaultv1alpha1.SecretTypeGenerate,
		Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "admin.password", HashedKey: hashedKey},
		Generate:    &vaultv1alpha1.GenerateSpec{Length: 16, Hash: hash},
	}
}

func TestApplyGenerate_CreateOnceThenStable(t *testing.T) {
	kv := newFakeKV()
	item := genItem(secretgen.HashNone, "")

	h1, changed, err := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, "")
	if err != nil || !changed {
		t.Fatalf("first generate: changed=%v err=%v", changed, err)
	}
	gen := kv.store["secret|clusters/ec8a00/argocd"]["admin.password"].(string)
	if len(gen) != 16 {
		t.Fatalf("generated length = %d", len(gen))
	}

	_, changed, err = applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, h1)
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if changed {
		t.Fatalf("expected create-once: no regenerate when criteria unchanged")
	}
	if kv.store["secret|clusters/ec8a00/argocd"]["admin.password"].(string) != gen {
		t.Fatalf("value changed on stable reconcile")
	}
}

func TestApplyGenerate_RecreateProtection(t *testing.T) {
	kv := newFakeKV()
	kv.seed("clusters/ec8a00/argocd", map[string]any{"admin.password": "preexisting"})
	item := genItem(secretgen.HashNone, "")

	_, changed, err := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, "")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed {
		t.Fatalf("key exists + empty baseline must adopt baseline, not regenerate")
	}
	if kv.store["secret|clusters/ec8a00/argocd"]["admin.password"] != "preexisting" {
		t.Fatalf("value should be untouched")
	}
}

func TestApplyGenerate_RegenerateOnCriteriaChange(t *testing.T) {
	kv := newFakeKV()
	item := genItem(secretgen.HashNone, "")
	h1, _, _ := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, "")
	first := kv.store["secret|clusters/ec8a00/argocd"]["admin.password"].(string)

	item.Generate.Length = 32
	h2, changed, err := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, h1)
	if err != nil || !changed {
		t.Fatalf("expected regenerate on criteria change: changed=%v err=%v", changed, err)
	}
	if h1 == h2 {
		t.Fatalf("criteria hash should change")
	}
	second := kv.store["secret|clusters/ec8a00/argocd"]["admin.password"].(string)
	if len(second) != 32 || second == first {
		t.Fatalf("value not regenerated: %q", second)
	}
}

func TestApplyGenerate_BcryptWritesRawAndHash(t *testing.T) {
	kv := newFakeKV()
	item := genItem(secretgen.HashBcrypt, "admin.passwordBcrypt")

	if _, _, err := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	dst := kv.store["secret|clusters/ec8a00/argocd"]
	raw := dst["admin.password"].(string)
	hashed := dst["admin.passwordBcrypt"].(string)
	if !strings.HasPrefix(hashed, "$2a$") {
		t.Fatalf("hashed key missing bcrypt prefix: %q", hashed)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(raw)); err != nil {
		t.Fatalf("hash does not match raw: %v", err)
	}
}

func TestApplyGenerate_HashWithoutHashedKeyFails(t *testing.T) {
	kv := newFakeKV()
	item := genItem(secretgen.HashBcrypt, "")
	if _, _, err := applyGenerateItem(context.Background(), kv, "secret", "clusters/ec8a00", item, ""); err == nil {
		t.Fatalf("expected error when hash != none but hashedKey empty")
	}
}

func TestValidateUniqueDestinations(t *testing.T) {
	dup := []vaultv1alpha1.SecretListItem{
		{Name: "a", Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "pw"}},
		{Name: "b", Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "pw"}},
	}
	if err := validateUniqueDestinations(dup); err == nil {
		t.Fatalf("expected error for duplicate destination path+key")
	}

	distinct := []vaultv1alpha1.SecretListItem{
		{Name: "a", Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "pw"}},
		{Name: "b", Destination: vaultv1alpha1.DestinationSpec{Path: "argocd", Key: "pwBcrypt"}},
		{Name: "c", Destination: vaultv1alpha1.DestinationSpec{Path: "grafana", Key: "pw"}},
	}
	if err := validateUniqueDestinations(distinct); err != nil {
		t.Fatalf("unexpected error for distinct destinations: %v", err)
	}
}
