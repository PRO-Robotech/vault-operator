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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

func reviewerClaim() *vaultv1alpha1.VaultClaim {
	return &vaultv1alpha1.VaultClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 1},
		Spec: vaultv1alpha1.VaultClaimSpec{Auth: vaultv1alpha1.AuthSpec{
			MountPath: "kubernetes-ec8a00",
			TokenReviewer: vaultv1alpha1.TokenReviewerSpec{ServiceAccount: vaultv1alpha1.ServiceAccountRef{
				Namespace: "beget-vault-system", Name: "vault-token-reviewer", AutoCreate: true,
			}},
		}},
	}
}

// A reviewer ServiceAccount that is not the claim's refuses the claim with
// ForeignReviewer on TokenReviewerJWTFresh; the claim's own one proceeds.
func TestEnsureTargetSARefusesAForeignReviewer(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for name, labels := range map[string]map[string]string{
		"foreign": {vaultv1alpha1.LabelClaimName: "zz0001", vaultv1alpha1.LabelClaimNamespace: "dlputi1u"},
		"own":     {vaultv1alpha1.LabelClaimName: "ec8a00", vaultv1alpha1.LabelClaimNamespace: "dlputi1u"},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeclient.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "beget-vault-system", Name: "vault-token-reviewer", Labels: labels}},
			).Build()
			r := &VaultClaimReconciler{TargetManager: &target.FakeManager{Set: &target.ClientSet{Client: c}}, Recorder: record.NewFakeRecorder(10)}
			claim := reviewerClaim()
			state := &pipelineState{}
			res, err := r.stepEnsureTargetSA(context.Background(), claim, state)
			if name == "own" {
				if err != nil || res != Proceed {
					t.Fatalf("own reviewer: %v, %v", res, err)
				}
				return
			}
			if err != nil || res != Refuse || state.RefusedReason != ReasonForeignReviewer {
				t.Fatalf("foreign reviewer: res=%v err=%v reason=%q", res, err, state.RefusedReason)
			}
			if got := reasonOf(claim, vaultv1alpha1.ConditionTokenReviewerJWTFresh); got != ReasonForeignReviewer {
				t.Fatalf("TokenReviewerJWTFresh reason = %q", got)
			}
		})
	}
}
