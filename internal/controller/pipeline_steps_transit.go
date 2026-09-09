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
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// DefaultTransitMountPath mirrors the CRD default for objects created before it.
const DefaultTransitMountPath = "transit"

func transitMountPath(claim *vaultv1alpha1.VaultClaim) string {
	if claim.Spec.Transit != nil && claim.Spec.Transit.MountPath != "" {
		return claim.Spec.Transit.MountPath
	}
	return DefaultTransitMountPath
}

// transitKeyStatus finds the ledger entry for a key name.
func transitKeyStatus(claim *vaultv1alpha1.VaultClaim, name string) *vaultv1alpha1.TransitKeyStatus {
	if claim.Status.Vault == nil {
		return nil
	}
	for i := range claim.Status.Vault.TransitKeys {
		if claim.Status.Vault.TransitKeys[i].Name == name {
			return &claim.Status.Vault.TransitKeys[i]
		}
	}
	return nil
}

// stepEnsureTransitKeys reconciles spec.transit against the Transit engine.
// It never mounts the engine, never deletes or rotates a key, and never
// recreates a key it previously created.
func (r *VaultClaimReconciler) stepEnsureTransitKeys(ctx context.Context, claim *vaultv1alpha1.VaultClaim, state *pipelineState) (StepResult, error) {
	if claim.Spec.Transit == nil || len(claim.Spec.Transit.Keys) == 0 {
		return Proceed, nil
	}

	mount := transitMountPath(claim)

	exists, err := state.Vault.MountExists(ctx, mount, "transit")
	if err != nil {
		reason := "MountCheckFailed"
		if vault.IsForbidden(err) {
			reason = "MountCheckForbidden"
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
			reason, fmt.Sprintf("cannot read sys/mounts: %v", err))
		return Proceed, fmt.Errorf("check transit mount %q: %w", mount, err)
	}
	if !exists {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
			"MountMissing", fmt.Sprintf("no Transit secrets engine mounted at %q", mount))
		return Wait, nil
	}

	// Early returns below write the ledger, so the summary must exist first.
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}

	observed := make([]vaultv1alpha1.TransitKeyStatus, 0, len(claim.Spec.Transit.Keys))

	for i := range claim.Spec.Transit.Keys {
		keySpec := claim.Spec.Transit.Keys[i]
		prior := transitKeyStatus(claim, keySpec.Name)

		live, err := state.Vault.ReadTransitKey(ctx, mount, keySpec.Name)
		switch {
		case err == nil:
		case vault.IsNotFound(err):
			// A namesake key is different material: it would strand every existing ciphertext.
			if prior != nil && prior.CreatedByClaim {
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
					"KeyMissing", fmt.Sprintf("key %q was created by this claim and no longer exists in Vault; refusing to recreate it", keySpec.Name))
				if r.Recorder != nil {
					r.Recorder.Eventf(claim, corev1.EventTypeWarning, "TransitKeyMissing",
						"Transit key %s/%s vanished; recreating it would strand existing ciphertext, so reconciliation is stopped", mount, keySpec.Name)
				}
				claim.Status.Vault.TransitKeys = keepTransitLedger(claim, observed, claim.Spec.Transit.Keys[i:])
				return Wait, nil
			}
			if err := r.createTransitKey(ctx, state, claim, mount, keySpec); err != nil {
				return Proceed, err
			}
			live, err = state.Vault.ReadTransitKey(ctx, mount, keySpec.Name)
			if err != nil {
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
					"ReadBackFailed", fmt.Sprintf("key %q created but cannot be read back: %v", keySpec.Name, err))
				return Proceed, fmt.Errorf("read back transit key %q: %w", keySpec.Name, err)
			}
			observed = append(observed, vaultv1alpha1.TransitKeyStatus{
				Name:           keySpec.Name,
				LatestVersion:  live.LatestVersion,
				CreatedByClaim: true,
			})
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeNormal, "TransitKeyCreated",
					"created Transit key %s/%s (%s)", mount, keySpec.Name, live.Type)
			}
			continue
		default:
			reason := "ReadKeyFailed"
			if vault.IsForbidden(err) {
				reason = "ReadKeyForbidden"
			}
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
				reason, fmt.Sprintf("key %q: %v", keySpec.Name, err))
			return Proceed, fmt.Errorf("read transit key %q: %w", keySpec.Name, err)
		}

		if mismatch := immutableKeyMismatch(keySpec, live); mismatch != "" {
			setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
				"KeyMismatch", fmt.Sprintf("key %q: %s", keySpec.Name, mismatch))
			claim.Status.Vault.TransitKeys = keepTransitLedger(claim, observed, claim.Spec.Transit.Keys[i:])
			return Wait, nil
		}

		if diff := mutableKeyDiff(keySpec, live); diff != "" {
			cfg := vault.TransitKeyConfig{
				DeletionAllowed:      keySpec.DeletionAllowed,
				Exportable:           keySpec.Exportable,
				AllowPlaintextBackup: keySpec.AllowPlaintextBackup,
				AutoRotatePeriodSecs: autoRotateSeconds(keySpec),
			}
			if err := state.Vault.UpdateTransitKeyConfig(ctx, mount, keySpec.Name, cfg); err != nil {
				setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
					"ConfigUpdateFailed", fmt.Sprintf("key %q: %v", keySpec.Name, err))
				return Proceed, fmt.Errorf("update transit key %q config: %w", keySpec.Name, err)
			}
			if r.Recorder != nil {
				r.Recorder.Eventf(claim, corev1.EventTypeWarning, "TransitKeyDrift",
					"Transit key %s/%s diverged from spec (%s); configuration reapplied", mount, keySpec.Name, diff)
			}
		}

		createdByClaim := prior != nil && prior.CreatedByClaim
		observed = append(observed, vaultv1alpha1.TransitKeyStatus{
			Name:           keySpec.Name,
			LatestVersion:  live.LatestVersion,
			CreatedByClaim: createdByClaim,
		})
	}

	sort.Slice(observed, func(i, j int) bool { return observed[i].Name < observed[j].Name })
	claim.Status.Vault.TransitKeys = observed
	setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionTrue, claim.Generation,
		"Ready", fmt.Sprintf("%d transit keys ready in %q", len(observed), mount))
	return Proceed, nil
}

func (r *VaultClaimReconciler) createTransitKey(ctx context.Context, state *pipelineState, claim *vaultv1alpha1.VaultClaim, mount string, keySpec vaultv1alpha1.TransitKeySpec) error {
	req := vault.CreateTransitKeyRequest{
		Type:                 keySpec.Type,
		Derived:              keySpec.Derived,
		Exportable:           keySpec.Exportable,
		AllowPlaintextBackup: keySpec.AllowPlaintextBackup,
		AutoRotatePeriodSecs: autoRotateSeconds(keySpec),
	}
	if err := state.Vault.CreateTransitKey(ctx, mount, keySpec.Name, req); err != nil {
		reason := "CreateKeyFailed"
		if vault.IsForbidden(err) {
			reason = "CreateKeyForbidden"
		}
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
			reason, fmt.Sprintf("key %q: %v", keySpec.Name, err))
		return fmt.Errorf("create transit key %q: %w", keySpec.Name, err)
	}
	// deletion_allowed is rejected at creation and needs its own write.
	cfg := vault.TransitKeyConfig{
		DeletionAllowed:      keySpec.DeletionAllowed,
		Exportable:           keySpec.Exportable,
		AllowPlaintextBackup: keySpec.AllowPlaintextBackup,
		AutoRotatePeriodSecs: autoRotateSeconds(keySpec),
	}
	if err := state.Vault.UpdateTransitKeyConfig(ctx, mount, keySpec.Name, cfg); err != nil {
		setCondition(&claim.Status.Conditions, vaultv1alpha1.ConditionTransitKeysReady, metav1.ConditionFalse, claim.Generation,
			"ConfigUpdateFailed", fmt.Sprintf("key %q: %v", keySpec.Name, err))
		return fmt.Errorf("configure transit key %q: %w", keySpec.Name, err)
	}
	return nil
}

func autoRotateSeconds(keySpec vaultv1alpha1.TransitKeySpec) int {
	if keySpec.AutoRotatePeriod == nil {
		return 0
	}
	return int(keySpec.AutoRotatePeriod.Seconds())
}

// immutableKeyMismatch names divergences Vault cannot repair.
func immutableKeyMismatch(keySpec vaultv1alpha1.TransitKeySpec, live *vault.TransitKey) string {
	var parts []string
	if keySpec.Type != "" && live.Type != keySpec.Type {
		parts = append(parts, fmt.Sprintf("type is %q, spec wants %q (fixed at creation)", live.Type, keySpec.Type))
	}
	if live.Derived != keySpec.Derived {
		parts = append(parts, fmt.Sprintf("derived is %t, spec wants %t (fixed at creation)", live.Derived, keySpec.Derived))
	}
	if live.Exportable && !keySpec.Exportable {
		parts = append(parts, "key is exportable and Vault cannot un-export it")
	}
	if live.AllowPlaintextBackup && !keySpec.AllowPlaintextBackup {
		parts = append(parts, "key allows plaintext backup and Vault cannot revoke that")
	}
	return strings.Join(parts, "; ")
}

// mutableKeyDiff names divergences the /config endpoint can fix.
func mutableKeyDiff(keySpec vaultv1alpha1.TransitKeySpec, live *vault.TransitKey) string {
	var parts []string
	if live.DeletionAllowed != keySpec.DeletionAllowed {
		parts = append(parts, fmt.Sprintf("deletion_allowed %t != %t", live.DeletionAllowed, keySpec.DeletionAllowed))
	}
	if want := autoRotateSeconds(keySpec); live.AutoRotatePeriod != want {
		parts = append(parts, fmt.Sprintf("auto_rotate_period %ds != %ds", live.AutoRotatePeriod, want))
	}
	if !live.Exportable && keySpec.Exportable {
		parts = append(parts, "exportable must be enabled")
	}
	if !live.AllowPlaintextBackup && keySpec.AllowPlaintextBackup {
		parts = append(parts, "allow_plaintext_backup must be enabled")
	}
	return strings.Join(parts, "; ")
}

// keepTransitLedger preserves ledger entries when the step stops early.
func keepTransitLedger(claim *vaultv1alpha1.VaultClaim, observed []vaultv1alpha1.TransitKeyStatus, remaining []vaultv1alpha1.TransitKeySpec) []vaultv1alpha1.TransitKeyStatus {
	out := append([]vaultv1alpha1.TransitKeyStatus(nil), observed...)
	seen := make(map[string]struct{}, len(out))
	for _, e := range out {
		seen[e.Name] = struct{}{}
	}
	for i := range remaining {
		name := remaining[i].Name
		if _, ok := seen[name]; ok {
			continue
		}
		if prior := transitKeyStatus(claim, name); prior != nil {
			out = append(out, *prior)
			seen[name] = struct{}{}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
