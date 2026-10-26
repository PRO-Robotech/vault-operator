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
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/secretgen"
)

// kvClient is the minimal KV surface the apply layer needs.
type kvClient interface {
	ReadKV(ctx context.Context, mount, path string) (map[string]any, bool, error)
	WriteKV(ctx context.Context, mount, path string, data map[string]any) error
}

const defaultGenerateLength = 24

func resolveMount(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

func joinPath(prefix, p string) string {
	return strings.Trim(prefix, "/") + "/" + strings.Trim(p, "/")
}

func hasKey(data map[string]any, key string) bool {
	_, ok := data[key]
	return ok
}

func cloneData(data map[string]any) map[string]any {
	out := make(map[string]any, len(data)+1)
	for k, v := range data {
		out[k] = v
	}
	return out
}

func effLength(g vaultv1alpha1.GenerateSpec) int {
	if g.Length == 0 {
		return defaultGenerateLength
	}
	return g.Length
}

func effHash(g vaultv1alpha1.GenerateSpec) string {
	if g.Hash == "" {
		return secretgen.HashNone
	}
	return g.Hash
}

// sha256Hex hashes parts joined by a NUL separator (a domain separator that
// can't appear in the inputs); used for change-detection.
func sha256Hex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// criteriaHash hashes the effective generation criteria; a change re-generates.
func criteriaHash(g vaultv1alpha1.GenerateSpec) string {
	return sha256Hex(strconv.Itoa(effLength(g)), g.Charset, effHash(g))
}

// validateCopySources checks every copy item's source exists before any write
func validateCopySources(ctx context.Context, kv kvClient, defMount string, items []vaultv1alpha1.SecretListItem) error {
	for i := range items {
		item := &items[i]
		if item.Type != vaultv1alpha1.SecretTypeCopy || item.Source == nil {
			continue
		}
		mount := resolveMount(item.Source.Mount, defMount)
		data, ok, err := kv.ReadKV(ctx, mount, item.Source.Path)
		if err != nil {
			log.FromContext(ctx).V(1).Info("reading a copy source failed", "item", item.Name, "err", err.Error())
			return statusErrorf("item %q: reading source %s/%s failed: %s", item.Name, mount, item.Source.Path, failureText(err))
		}
		if !ok || !hasKey(data, item.Source.Key) {
			return statusErrorf("item %q: source %s/%s#%s not found", item.Name, mount, item.Source.Path, item.Source.Key)
		}
	}
	return nil
}

// applyCopyItem copies the source value into the destination when the
// destination does not already hold it, so a source change and an outside edit
// of the destination are both repaired; sibling keys at the destination
// survive (KV-v2 writes full-replace). No hash of the value is kept anywhere.
func applyCopyItem(ctx context.Context, kv kvClient, defMount, secretsPrefix string, item *vaultv1alpha1.SecretListItem) (bool, error) {
	srcMount := resolveMount(item.Source.Mount, defMount)
	srcData, ok, err := kv.ReadKV(ctx, srcMount, item.Source.Path)
	if err != nil {
		return false, err
	}
	if !ok || !hasKey(srcData, item.Source.Key) {
		return false, statusErrorf("item %q: source %s/%s#%s not found", item.Name, srcMount, item.Source.Path, item.Source.Key)
	}
	value := srcData[item.Source.Key]

	dstMount := resolveMount(item.Destination.Mount, defMount)
	dstPath := joinPath(secretsPrefix, item.Destination.Path)
	dstData, _, err := kv.ReadKV(ctx, dstMount, dstPath)
	if err != nil {
		return false, err
	}
	if cur, ok := dstData[item.Destination.Key]; ok && reflect.DeepEqual(cur, value) {
		return false, nil
	}
	merged := cloneData(dstData)
	merged[item.Destination.Key] = value
	if err := kv.WriteKV(ctx, dstMount, dstPath, merged); err != nil {
		return false, err
	}
	return true, nil
}

// applyGenerateItem generates create-once: it regenerates only on a missing key
// or changed criteria (an existing key with an empty baseline is adopted).
func applyGenerateItem(ctx context.Context, kv kvClient, defMount, secretsPrefix string, item *vaultv1alpha1.SecretListItem, prevHash string) (string, bool, error) {
	g := *item.Generate
	mount := resolveMount(item.Destination.Mount, defMount)
	path := joinPath(secretsPrefix, item.Destination.Path)

	data, _, err := kv.ReadKV(ctx, mount, path)
	if err != nil {
		return "", false, err
	}
	keyExists := hasKey(data, item.Destination.Key)
	ch := criteriaHash(g)

	regenerate := !keyExists || (prevHash != "" && prevHash != ch)
	if !regenerate {
		return ch, false, nil
	}

	// secretgen refuses only what the generate spec asks for; its text names
	// the spec values, never a remote endpoint.
	raw, err := secretgen.Generate(effLength(g), g.Charset)
	if err != nil {
		return "", false, statusErrorf("item %q: %v", item.Name, err)
	}
	merged := cloneData(data)
	merged[item.Destination.Key] = raw
	if effHash(g) != secretgen.HashNone {
		if item.Destination.HashedKey == "" {
			return "", false, statusErrorf("item %q: generate.hash=%s requires destination.hashedKey", item.Name, effHash(g))
		}
		hashed, err := secretgen.Hash(effHash(g), raw)
		if err != nil {
			return "", false, statusErrorf("item %q: %v", item.Name, err)
		}
		merged[item.Destination.HashedKey] = hashed
	}
	if err := kv.WriteKV(ctx, mount, path, merged); err != nil {
		return "", false, err
	}
	return ch, true, nil
}
