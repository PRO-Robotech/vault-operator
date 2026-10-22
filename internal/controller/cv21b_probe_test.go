//go:build cv21

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

func cvShort(s string) string {
	if len(s) > 260 {
		return s[:260] + fmt.Sprintf("…(+%d)", len(s)-260)
	}
	return s
}

// E1 at the step: the condition a writer reads names the cause.
func TestCV21bStepConditionNamesTheCause(t *testing.T) {
	longAcc := "auth_kubernetes_" + strings.Repeat("a", 400)
	cases := []struct {
		name, rules, accessor string
		want                  []string
	}{
		{"range", `path "secret/data/clusters/ec8a00/*" { capabilities = ["read"] }` + "\n{{ range 3 }}x{{ end }}", testAccessor, []string{"range at policy:2:"}},
		{"if", "{{ if true }}x{{ end }}", testAccessor, []string{"if at policy:1:"}},
		{"with", "{{ with \"a\" }}x{{ end }}", testAccessor, []string{"with at policy:1:"}},
		{"rules-16385", strings.Repeat("#", vaultv1alpha1.MaxRulesLength+1), testAccessor, []string{"16385 bytes, the limit is 16384"}},
		{"render-over-size", strings.Repeat("{{ .AuthMountAccessor }}", 650), longAcc, []string{"the limit is 262144", "at least"}},
		{"long-function-parse-error", "{{ " + strings.Repeat("f", 16000) + " }}", testAccessor, []string{"not defined"}},
		{"long-field", "{{ ." + strings.Repeat("g", 16000) + " }}", testAccessor, []string{"the field .ggg", "…"}},
		{"bare-identity", "{{identity.entity.id}}", testAccessor, []string{"unescaped"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := vaultv1alpha1.PolicySpec{Name: "ec8a00-apps", Rules: tc.rules}
			claim := &vaultv1alpha1.VaultClaim{
				ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 7},
				Spec: vaultv1alpha1.VaultClaimSpec{SecretsPrefix: "clusters/ec8a00",
					Auth: vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"}, Policies: []vaultv1alpha1.PolicySpec{p}},
			}
			fake := &fakeVaultClient{AccessorResp: tc.accessor}
			state := &pipelineState{Vault: fake}
			rec := record.NewFakeRecorder(10)
			r := &VaultClaimReconciler{Recorder: rec}
			start := time.Now()
			res, err := r.stepApplyPolicies(context.Background(), claim, state)
			el := time.Since(start)
			cond := apimeta.FindStatusCondition(claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied)
			if cond == nil {
				t.Fatalf("CV %s: no PoliciesApplied condition; res=%v err=%v", tc.name, res, err)
			}
			t.Logf("CV E1 %s: res=%v err=%v elapsed=%s reason=%s len=%d message=%q", tc.name, res, err, el, cond.Reason, len(cond.Message), cvShort(cond.Message))
			ev := drainEvents(rec)
			for _, e := range ev {
				t.Logf("CV E1 %s event len=%d %q", tc.name, len(e), cvShort(e))
			}
			if res != Refuse || err != nil {
				t.Errorf("want Refuse,<nil>; got %v,%v", res, err)
			}
			if cond.Reason != "RenderFailed" || cond.Status != metav1.ConditionFalse || cond.ObservedGeneration != 7 {
				t.Errorf("condition %s/%s gen %d", cond.Status, cond.Reason, cond.ObservedGeneration)
			}
			for _, w := range tc.want {
				if !strings.Contains(cond.Message, w) {
					t.Errorf("message does not name %q", w)
				}
			}
			if strings.Contains(cond.Message, "the rules do not render as a template") {
				t.Errorf("message is the old fixed text")
			}
			if strings.Contains(cond.Message, strings.Repeat("a", 64)) {
				t.Errorf("message echoes the accessor")
			}
			if len(cond.Message) > 32768 {
				t.Errorf("message %d bytes is past the Condition schema limit 32768", len(cond.Message))
			}
			if d := apimeta.FindStatusCondition(claim.Status.Conditions, conditionDegraded); d != nil {
				t.Errorf("Degraded set on a refusal: %s/%s", d.Status, d.Reason)
			}
			if fake.PutPolicyCalls != 0 || fake.ReadPolicyCalls != 0 {
				t.Errorf("Vault policy calls: put %d read %d", fake.PutPolicyCalls, fake.ReadPolicyCalls)
			}
		})
	}
}

// I7 holder: a loop at the step is refused fast (hangs when admitTemplate is gone).
func TestCV21bStepRefusesALoopFast(t *testing.T) {
	p := vaultv1alpha1.PolicySpec{Name: "ec8a00-apps", Rules: "{{ range 1e11 }}{{ end }}"}
	claim := &vaultv1alpha1.VaultClaim{ObjectMeta: metav1.ObjectMeta{Name: "ec8a00", Namespace: "dlputi1u", Generation: 1},
		Spec: vaultv1alpha1.VaultClaimSpec{SecretsPrefix: "clusters/ec8a00",
			Auth: vaultv1alpha1.AuthSpec{MountPath: "kubernetes-ec8a00"}, Policies: []vaultv1alpha1.PolicySpec{p}}}
	done := make(chan struct{})
	var res StepResult
	var err error
	start := time.Now()
	go func() {
		res, err = (&VaultClaimReconciler{}).stepApplyPolicies(context.Background(), claim, &pipelineState{Vault: &fakeVaultClient{AccessorResp: testAccessor}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CV I7: stepApplyPolicies with {{ range 1e11 }} did not return within 10s")
	}
	t.Logf("CV I7 loop at step: elapsed=%s res=%v err=%v", time.Since(start), res, err)
	if res != Refuse {
		t.Errorf("want Refuse, got %v %v", res, err)
	}
}

func cvVaultCalls(f *fakeVaultClient) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.SealCalls + f.LoginCalls + f.LookupSelfCalls + f.ReadAuthMountCalls + f.EnableAuthCalls +
		f.WriteConfigCalls + f.AccessorCalls + f.PutPolicyCalls + f.ListPoliciesCalls + f.PutRoleCalls +
		f.ListRolesCalls + f.ListAuthMountsCalls + f.ReadAuthCfgCalls + f.ReadPolicyCalls + f.ReadRoleCalls
}

func cvReconciler(fakeVC *fakeVaultClient, rec *record.FakeRecorder, now *time.Time, c client.Client) *VaultClaimReconciler {
	return &VaultClaimReconciler{
		Client:        c,
		Scheme:        k8sClient.Scheme(),
		Recorder:      rec,
		VaultFactory:  &fakeVaultFactory{Client: fakeVC},
		TargetManager: &target.FakeManager{Set: newTargetClientSetWithReactor(targetScheme(), "jwt", now.Add(24*time.Hour))},
		Now:           func() time.Time { return *now },
	}
}

var _ = Describe("CV21b render refusal", func() {
	DescribeTable("E1 live: the condition read from the API server names the cause",
		func(label, rules, accessorSuffix, want string) {
			now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
			name := nextClaimName()
			fakeVC := &fakeVaultClient{SharedMountResp: true, AccessorResp: "auth_kubernetes_" + name + accessorSuffix}
			rec := record.NewFakeRecorder(100)
			r := cvReconciler(fakeVC, rec, &now, k8sClient)
			cfg, sec := fixture(name)
			createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", rules))))
			_, err := reconcileClaim(r, name)
			Expect(err).NotTo(HaveOccurred())
			got := claimNamed(name)
			pa := conditionOf(got, vaultv1alpha1.ConditionPoliciesApplied)
			rd := conditionOf(got, vaultv1alpha1.ConditionReady)
			dg := conditionOf(got, conditionDegraded)
			Expect(pa).NotTo(BeNil())
			GinkgoWriter.Printf("CV E1-live %s: phase=%s PoliciesApplied=%s/%s len=%d msg=%q\n", label, got.Status.Phase, pa.Status, pa.Reason, len(pa.Message), cvShort(pa.Message))
			if rd != nil {
				GinkgoWriter.Printf("CV E1-live %s: Ready=%s/%s msg=%q\n", label, rd.Status, rd.Reason, rd.Message)
			}
			if dg != nil {
				GinkgoWriter.Printf("CV E1-live %s: Degraded=%s/%s\n", label, dg.Status, dg.Reason)
			}
			for _, e := range drainEvents(rec) {
				GinkgoWriter.Printf("CV E1-live %s event: %q\n", label, cvShort(e))
			}
			Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
			Expect(pa.Reason).To(Equal("RenderFailed"))
			Expect(pa.Message).To(ContainSubstring(want))
			if dg != nil {
				Expect(dg.Status).NotTo(Equal(metav1.ConditionTrue))
			}
		},
		Entry("range", "range", `path "secret/data/x/*" { capabilities = ["read"] }`+"\n{{ range 3 }}x{{ end }}", "", "range at policy:2:"),
		Entry("if", "if", "{{ if true }}x{{ end }}", "", "if at policy:1:"),
		Entry("render past the size limit", "size", strings.Repeat("{{ .AuthMountAccessor }}", 650), "_"+strings.Repeat("a", 400), "the limit is 262144"),
		Entry("long function name parse error", "longfn", "{{ "+strings.Repeat("f", 16000)+" }}", "", "not defined"),
	)

	It("E1 live: rules of 16385 bytes are refused by the API server, naming the limit", func() {
		name := nextClaimName()
		cfg, sec := fixture(name)
		c := newClaim(name, cfg, sec, withPolicies(policy(name+"-p", strings.Repeat("#", vaultv1alpha1.MaxRulesLength+1))))
		err := k8sClient.Create(context.Background(), c)
		GinkgoWriter.Printf("CV E1-live rules-16385 create: %v\n", err)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("16384"))
	})

	It("NEW: a deterministic refusal is not repeated hot over N passes of one generation, and a fixed spec recovers", func() {
		now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		name := nextClaimName()
		fakeVC := &fakeVaultClient{SharedMountResp: true, AccessorResp: "auth_kubernetes_" + name}
		rec := record.NewFakeRecorder(500)
		r := cvReconciler(fakeVC, rec, &now, k8sClient)
		cfg, sec := fixture(name)
		admitted := `path "secret/data/clusters/` + name + `/{{ vaultSAName }}" { capabilities = ["read"] }`
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", admitted+"\n{{ range 3 }}x{{ end }}"))))

		const passes = 20
		var calls []int
		var rvs []string
		var reqs []time.Duration
		for range passes {
			res, err := reconcileClaim(r, name)
			Expect(err).NotTo(HaveOccurred())
			calls = append(calls, cvVaultCalls(fakeVC))
			rvs = append(rvs, claimNamed(name).ResourceVersion)
			reqs = append(reqs, res.RequeueAfter)
		}
		var renderEv, retryEv int
		for _, e := range drainEvents(rec) {
			if strings.HasPrefix(e, "Warning RenderFailed ") {
				renderEv++
			}
			if strings.Contains(e, "StepRetrying") {
				retryEv++
			}
		}
		fakeVC.mu.Lock()
		acc, put := fakeVC.AccessorCalls, fakeVC.PutPolicyCalls
		fakeVC.mu.Unlock()
		gen := claimNamed(name).Generation
		GinkgoWriter.Printf("CV NEW hot: passes=%d generation=%d vaultCallsAfterPass1=%d vaultCallsAfterPass%d=%d accessorCalls=%d put=%d renderFailedEvents=%d stepRetrying=%d rv1=%s rvN=%s requeue1=%s requeueN=%s\n",
			passes, gen, calls[0], passes, calls[passes-1], acc, put, renderEv, retryEv, rvs[0], rvs[passes-1], reqs[0], reqs[passes-1])
		Expect(calls[passes-1]).To(Equal(calls[0]), "Vault calls grew after pass 1 within one generation")
		Expect(rvs[passes-1]).To(Equal(rvs[0]), "status rewritten by repeated passes")
		Expect(acc).To(Equal(1))
		Expect(put).To(BeZero())
		Expect(renderEv).To(Equal(1))
		Expect(retryEv).To(BeZero())
		for i, d := range reqs {
			Expect(d).To(BeNumerically(">=", RequeueClaimDriftReady), "pass %d requeue %s", i+1, d)
		}

		By("fix spec immediately, the clock not advanced")
		fresh := claimNamed(name)
		fresh.Spec.Policies[0].Rules = admitted
		Expect(k8sClient.Update(context.Background(), fresh)).To(Succeed())
		res, err := reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		got := claimNamed(name)
		fakeVC.mu.Lock()
		acc, put = fakeVC.AccessorCalls, fakeVC.PutPolicyCalls
		fakeVC.mu.Unlock()
		pa := conditionOf(got, vaultv1alpha1.ConditionPoliciesApplied)
		GinkgoWriter.Printf("CV NEW recover: generation=%d phase=%s Ready=%s PoliciesApplied=%s/%s Degraded=%s accessorCalls=%d put=%d requeue=%s\n",
			got.Generation, got.Status.Phase, reasonOf(got, vaultv1alpha1.ConditionReady), pa.Status, pa.Reason, reasonOf(got, conditionDegraded), acc, put, res.RequeueAfter)
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
		Expect(pa.Status).To(Equal(metav1.ConditionTrue))
		Expect(put).To(Equal(1))
		Expect(conditionOf(got, vaultv1alpha1.ConditionReady).Status).To(Equal(metav1.ConditionTrue))

		By("further passes of the fixed generation are not skipped as refused")
		before := cvVaultCalls(fakeVC)
		now = now.Add(time.Minute)
		_, err = reconcileClaim(r, name)
		Expect(err).NotTo(HaveOccurred())
		GinkgoWriter.Printf("CV NEW after-recover pass: vaultCalls %d -> %d phase=%s\n", before, cvVaultCalls(fakeVC), claimNamed(name).Status.Phase)
		Expect(claimNamed(name).Status.Phase).To(Equal(vaultv1alpha1.PhaseReady))
	})

	It("NEW twin: the counter is not blind — with the clock past the recheck every pass renders", func() {
		now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		name := nextClaimName()
		fakeVC := &fakeVaultClient{SharedMountResp: true, AccessorResp: "auth_kubernetes_" + name}
		rec := record.NewFakeRecorder(500)
		r := cvReconciler(fakeVC, rec, &now, k8sClient)
		cfg, sec := fixture(name)
		admitted := `path "secret/data/clusters/` + name + `/{{ vaultSAName }}" { capabilities = ["read"] }`
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", admitted+"\n{{ range 3 }}x{{ end }}"))))
		const passes = 5
		for range passes {
			_, err := reconcileClaim(r, name)
			Expect(err).NotTo(HaveOccurred())
			now = now.Add(RequeueClaimDriftReady)
		}
		fakeVC.mu.Lock()
		acc := fakeVC.AccessorCalls
		fakeVC.mu.Unlock()
		GinkgoWriter.Printf("CV NEW twin: passes=%d with clock +%s each, accessorCalls=%d\n", passes, RequeueClaimDriftReady, acc)
		Expect(acc).To(Equal(passes))
	})

	It("NEW out of plan: a refusal whose status write failed is not skipped on the next pass", func() {
		now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
		name := nextClaimName()
		fakeVC := &fakeVaultClient{SharedMountResp: true, AccessorResp: "auth_kubernetes_" + name}
		rec := record.NewFakeRecorder(500)
		failed := 0
		c := interceptor.NewClient(watchClient(), interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if vc, ok := obj.(*vaultv1alpha1.VaultClaim); ok && failed == 0 && vc.Status.Phase == vaultv1alpha1.PhaseFailed {
					failed++
					return errors.New("cv: injected status write failure")
				}
				return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		})
		r := cvReconciler(fakeVC, rec, &now, c)
		cfg, sec := fixture(name)
		admitted := `path "secret/data/clusters/` + name + `/{{ vaultSAName }}" { capabilities = ["read"] }`
		createClaim(newClaim(name, cfg, sec, withPolicies(policy(name+"-p", admitted+"\n{{ range 3 }}x{{ end }}"))))
		_, err1 := reconcileClaim(r, name)
		_, err2 := reconcileClaim(r, name)
		got := claimNamed(name)
		fakeVC.mu.Lock()
		acc := fakeVC.AccessorCalls
		fakeVC.mu.Unlock()
		GinkgoWriter.Printf("CV NEW status-write-failed: injectedFailures=%d err1=%v err2=%v accessorCalls=%d phase=%s PoliciesApplied=%s\n",
			failed, err1, err2, acc, got.Status.Phase, reasonOf(got, vaultv1alpha1.ConditionPoliciesApplied))
		Expect(failed).To(Equal(1))
		Expect(err1).To(HaveOccurred())
		Expect(acc).To(Equal(2), "second pass skipped although the refusal never reached the API server")
		Expect(got.Status.Phase).To(Equal(vaultv1alpha1.PhaseFailed))
		Expect(reasonOf(got, vaultv1alpha1.ConditionPoliciesApplied)).To(Equal("RenderFailed"))
	})
})
