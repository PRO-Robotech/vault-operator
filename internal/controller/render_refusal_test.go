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
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// reasonRenderFailed is spelled out: the property is the reason a reader of
// the claim sees, under the name the documentation gives it.
const reasonRenderFailed = "RenderFailed"

// The condition of a policy whose rules do not render says why: the refused
// construct and its position, the length and its limit, the size and its
// limit. The text is built from the writer's own spec and the operator's
// limits; the accessor the oversized body embeds is not echoed. The step
// refuses the claim instead of failing it as a transient error. The twin of
// the same harness renders and writes, so a refusal is not the harness
// failing to reach the render.
func TestApplyPoliciesConditionNamesWhyTheRulesDoNotRender(t *testing.T) {
	long := "auth_kubernetes_" + strings.Repeat("a", 64<<10)
	cases := []struct {
		name     string
		rules    string
		accessor string
		want     []string
	}{
		{
			name:     "a construct outside the closed set",
			rules:    `path "secret/data/clusters/ec8a00/*" { capabilities = ["read"] }` + "\n{{ range 3 }}x{{ end }}",
			accessor: testAccessor,
			want:     []string{"range at policy:2:"},
		},
		{
			name:     "rules past the length limit",
			rules:    strings.Repeat("#", vaultv1alpha1.MaxRulesLength+1),
			accessor: testAccessor,
			want:     []string{strconv.Itoa(vaultv1alpha1.MaxRulesLength + 1), strconv.Itoa(vaultv1alpha1.MaxRulesLength)},
		},
		{
			name:     "a body past the size limit",
			rules:    strings.Repeat(`path "x/{{ .AuthMountAccessor }}" { capabilities = ["read"] }`+"\n", 8),
			accessor: long,
			want:     []string{strconv.Itoa(maxRenderedPolicy)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := vaultv1alpha1.PolicySpec{Name: "ec8a00-apps", Rules: tc.rules}
			_, renderErr := renderClaimPolicy(p, tc.accessor)
			if renderErr == nil {
				t.Fatal("the rules render: the case does not reach a refusal")
			}
			claim := &vaultv1alpha1.VaultClaim{
				ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 3},
				Spec: vaultv1alpha1.VaultClaimSpec{
					SecretsPrefix: "clusters/ec8a00",
					Auth:          vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"},
					Policies:      []vaultv1alpha1.PolicySpec{p},
				},
			}
			fake := &fakeVaultClient{AccessorResp: tc.accessor}
			state := &pipelineState{Vault: fake}
			r := &VaultClaimReconciler{}

			res, err := r.stepApplyPolicies(context.Background(), claim, state)
			if err != nil || res != Refuse {
				t.Errorf("stepApplyPolicies = %v, %v; want Refuse, <nil>: rules that do not render are not a transient failure", res, err)
			}
			if state.RefusedReason != reasonRenderFailed {
				t.Errorf("refused reason = %q, want %q", state.RefusedReason, reasonRenderFailed)
			}
			cond := apimeta.FindStatusCondition(claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied)
			if cond == nil {
				t.Fatal("no PoliciesApplied condition")
			}
			if cond.Status != metav1.ConditionFalse || cond.Reason != reasonRenderFailed || cond.ObservedGeneration != 3 {
				t.Errorf("PoliciesApplied = %s/%s gen %d, want False/%s gen 3", cond.Status, cond.Reason, cond.ObservedGeneration, reasonRenderFailed)
			}
			if want := fmt.Sprintf("policy %q: %s", p.Name, renderErr.Error()); cond.Message != want {
				t.Errorf("message = %q\nwant      %q", cond.Message, want)
			}
			for _, w := range tc.want {
				if !strings.Contains(cond.Message, w) {
					t.Errorf("message %q does not name %q", cond.Message, w)
				}
			}
			if strings.Contains(cond.Message, strings.Repeat("a", 64)) {
				t.Errorf("message echoes the accessor: %d bytes", len(cond.Message))
			}
			if fake.ReadPolicyCalls != 0 || fake.PutPolicyCalls != 0 {
				t.Errorf("Vault policy calls on a refusal: read %d, put %d", fake.ReadPolicyCalls, fake.PutPolicyCalls)
			}
		})
	}

	t.Run("the twin: admitted forms render and are written", func(t *testing.T) {
		claim := &vaultv1alpha1.VaultClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 3},
			Spec: vaultv1alpha1.VaultClaimSpec{
				SecretsPrefix: "clusters/ec8a00",
				Auth:          vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"},
				Policies: []vaultv1alpha1.PolicySpec{{Name: "ec8a00-apps",
					Rules: `path "secret/data/clusters/ec8a00/{{ vaultSAName }}" { capabilities = ["read"] }`}},
			},
		}
		fake := &fakeVaultClient{AccessorResp: testAccessor}
		r := &VaultClaimReconciler{}
		res, err := r.stepApplyPolicies(context.Background(), claim, &pipelineState{Vault: fake})
		if err != nil || res != Proceed {
			t.Fatalf("stepApplyPolicies = %v, %v; want Proceed", res, err)
		}
		if fake.PutPolicyCalls != 1 {
			t.Fatalf("PutPolicy calls = %d, want 1", fake.PutPolicyCalls)
		}
	})
}

var _ = Describe("VaultClaim rules that do not render", func() {
	It("are refused once per generation: passes do not render them again before the recheck is due or spec changes", func() {
		now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		name := nextClaimName()
		fakeVC := &fakeVaultClient{SharedMountResp: true, AccessorResp: "auth_kubernetes_" + name}
		recorder := record.NewFakeRecorder(200)
		r := &VaultClaimReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			Recorder:      recorder,
			VaultFactory:  &fakeVaultFactory{Client: fakeVC},
			TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", now.Add(24*time.Hour))},
			Now:           func() time.Time { return now },
		}
		cfg, sec := fixture(name)
		// The ServiceAccount function makes every pass that renders the rules
		// read the accessor first: AccessorCalls counts the renders.
		admitted := `path "secret/data/clusters/` + name + `/{{ vaultSAName }}" { capabilities = ["read"] }`
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", admitted+"\n{{ if true }}x{{ end }}"))))

		const passes = 5
		var requeues []time.Duration
		for range passes {
			res, err := reconcileClaim(r, name)
			Expect(err).NotTo(HaveOccurred())
			requeues = append(requeues, res.RequeueAfter)
		}
		fakeVC.mu.Lock()
		renders, puts := fakeVC.AccessorCalls, fakeVC.PutPolicyCalls
		fakeVC.mu.Unlock()
		Expect(renders).To(Equal(1), "passes of one generation that rendered the refused rules, of %d", passes)
		Expect(puts).To(BeZero(), "policies written for refused rules")
		for i, d := range requeues {
			Expect(d).To(BeNumerically(">=", RequeueClaimDriftReady), "pass %d asked to be repeated after %s", i+1, d)
		}

		got := claimNamed(name)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		Expect(reasonOf(got, vaultv1alpha1.ConditionReady)).To(Equal(reasonRenderFailed))
		Expect(reasonOf(got, vaultv1alpha1.ConditionPoliciesApplied)).To(Equal(reasonRenderFailed))
		Expect(conditionOf(got, vaultv1alpha1.ConditionPoliciesApplied).Message).To(ContainSubstring("if at policy:2:"))
		if d := conditionOf(got, conditionDegraded); d != nil {
			Expect(d.Status).NotTo(Equal(metav1.ConditionTrue), "a refusal reported as a transient failure: %s", d.Reason)
		}
		var refusals, retries int
		for _, e := range drainEvents(recorder) {
			if strings.Contains(e, "StepRetrying") {
				retries++
			}
			if strings.HasPrefix(e, "Warning "+reasonRenderFailed+" ") {
				refusals++
			}
		}
		Expect(retries).To(BeZero(), "StepRetrying events for rules that do not render")
		Expect(refusals).To(Equal(1), "RenderFailed events over %d passes of one generation", passes)

		By("the recheck is due: one pass renders the rules again")
		now = now.Add(RequeueClaimDriftReady)
		_, err := reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		fakeVC.mu.Lock()
		renders = fakeVC.AccessorCalls
		fakeVC.mu.Unlock()
		Expect(renders).To(Equal(2), "renders after the recheck came due")

		By("an edit of spec is rendered at once")
		fresh := claimNamed(name)
		fresh.Spec.Policies[0].Rules = admitted
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		_, err = reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		fakeVC.mu.Lock()
		renders, puts = fakeVC.AccessorCalls, fakeVC.PutPolicyCalls
		fakeVC.mu.Unlock()
		Expect(renders).To(Equal(3), "renders after spec changed")
		Expect(puts).To(Equal(1))
		Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
	})
})
