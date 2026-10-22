/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"sigs.k8s.io/yaml"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

const testAccessor = "auth_kubernetes_1a2b3c4d"

// legacyRender is the renderer of the release production runs, kept verbatim:
// a claim without the new forms must render to the same bytes.
func legacyRender(hcl string, accessor string) (string, error) {
	tmpl, err := template.New("policy").Option("missingkey=error").Parse(hcl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{"AuthMountAccessor": accessor}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// The three forms production and the documentation have used render byte for
// byte as before.
func TestRenderClaimPolicyKeepsLegacyFormsByteForByte(t *testing.T) {
	corpus := map[string]string{
		"static": `path "secret/data/clusters/ab3b6f/*" {
  capabilities = ["read", "list"]
}
`,
		"escaped vault template": "path \"secret/data/clusters/x/{{`{{`}} identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace {{`}}`}}/*\" {\n  capabilities = [\"read\"]\n}\n",
		"accessor only":          `path "secret/data/clusters/{{ .AuthMountAccessor }}/*" { capabilities = ["read"] }`,
	}
	for name, rules := range corpus {
		t.Run(name, func(t *testing.T) {
			want, err := legacyRender(rules, testAccessor)
			if err != nil {
				t.Fatalf("legacy render: %v", err)
			}
			got, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: rules}, testAccessor)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if got != want {
				t.Fatalf("rendered body changed:\nwant %q\ngot  %q", want, got)
			}
		})
	}
}

func TestRenderClaimPolicyServiceAccountFunctions(t *testing.T) {
	rules := `path "secret/data/clusters/x/{{ vaultSANamespace }}/{{ vaultSAName }}" { capabilities = ["read"] }`
	got, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: rules}, testAccessor)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := `path "secret/data/clusters/x/{{identity.entity.aliases.` + testAccessor + `.metadata.service_account_namespace}}/{{identity.entity.aliases.` + testAccessor + `.metadata.service_account_name}}" { capabilities = ["read"] }`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// A Vault template written without escaping is refused with a message that
// says what to write instead; the escaped twin renders.
func TestRenderClaimPolicyRefusesABareVaultTemplate(t *testing.T) {
	bare := `path "secret/data/{{identity.entity.aliases.x.metadata.service_account_namespace}}/*" { capabilities = ["read"] }`
	_, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: bare}, testAccessor)
	if !errors.Is(err, errBareIdentity) {
		t.Fatalf("err = %v, want errBareIdentity", err)
	}
	for _, hint := range []string{"vaultSAName", "identityPaths"} {
		if !strings.Contains(errBareIdentity.Error(), hint) {
			t.Errorf("the refusal does not name %q: %q", hint, errBareIdentity.Error())
		}
	}
	escaped := "path \"secret/data/{{`{{`}}identity.entity.aliases.x.metadata.service_account_namespace{{`}}`}}/*\" { capabilities = [\"read\"] }"
	if _, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: escaped}, testAccessor); err != nil {
		t.Fatalf("escaped twin refused: %v", err)
	}
}

func TestRenderClaimPolicyAppendsIdentityPaths(t *testing.T) {
	p := vaultv1alpha1.PolicySpec{
		Name:  "p",
		Rules: `path "auth/token/lookup-self" { capabilities = ["read"] }`,
		IdentityPaths: []vaultv1alpha1.IdentityPath{
			{Path: "secret/data/clusters/x/{serviceAccountNamespace}/{serviceAccountName}", Capabilities: []string{"read", "list"}},
			{Path: "secret/metadata/clusters/x/{serviceAccountNamespace}", Capabilities: []string{"list"}},
		},
	}
	got, err := renderClaimPolicy(p, testAccessor)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	ns := "{{identity.entity.aliases." + testAccessor + ".metadata.service_account_namespace}}"
	sa := "{{identity.entity.aliases." + testAccessor + ".metadata.service_account_name}}"
	want := `path "auth/token/lookup-self" { capabilities = ["read"] }

path "secret/data/clusters/x/` + ns + `/` + sa + `" {
  capabilities = ["read", "list"]
}

path "secret/metadata/clusters/x/` + ns + `" {
  capabilities = ["list"]
}
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	only := vaultv1alpha1.PolicySpec{Name: "q", IdentityPaths: p.IdentityPaths[:1]}
	got, err = renderClaimPolicy(only, testAccessor)
	if err != nil {
		t.Fatalf("render identityPaths only: %v", err)
	}
	if want := "path \"secret/data/clusters/x/" + ns + "/" + sa + "\" {\n  capabilities = [\"read\", \"list\"]\n}\n"; got != want {
		t.Fatalf("identityPaths only:\ngot  %q\nwant %q", got, want)
	}
}

// What the schema refuses the renderer refuses too: a claim admitted under an
// older schema, or written past it, renders nothing it would not admit.
func TestRenderClaimPolicyJudgesIdentityPathsLikeTheSchema(t *testing.T) {
	for _, tc := range []struct {
		path string
		caps []string
		ok   bool
	}{
		{"secret/data/x/{serviceAccountNamespace}/{serviceAccountName}", []string{"read"}, true},
		{"secret/data/x/{meta.area}", []string{"read"}, false},
		{"secret/data/x/*/{serviceAccountName}", []string{"read"}, false},
		{"secret/data/x/+/{serviceAccountName}", []string{"read"}, false},
		{"/secret/data/x/{serviceAccountName}", []string{"read"}, false},
		{"secret/data/../{serviceAccountName}", []string{"read"}, false},
		{"secret/data/x/static", []string{"read"}, false},
		{"secret/data/x/{serviceAccountName}", []string{"sudo"}, false},
		{"secret/data/x/{serviceAccountName}", []string{"deny"}, false},
		{"secret/data/x/{serviceAccountName}", nil, false},
	} {
		p := vaultv1alpha1.PolicySpec{Name: "p", IdentityPaths: []vaultv1alpha1.IdentityPath{{Path: tc.path, Capabilities: tc.caps}}}
		_, err := renderClaimPolicy(p, testAccessor)
		if (err == nil) != tc.ok {
			t.Errorf("path %q caps %v: err = %v, want ok=%t", tc.path, tc.caps, err, tc.ok)
		}
	}
}

// An accessor that would break out of the Vault template is refused; the
// identity forms are the only ones that embed it in a template.
func TestRenderClaimPolicyRefusesAnAccessorOfAnotherForm(t *testing.T) {
	p := vaultv1alpha1.PolicySpec{Name: "p", IdentityPaths: []vaultv1alpha1.IdentityPath{
		{Path: "secret/data/x/{serviceAccountName}", Capabilities: []string{"read"}},
	}}
	for _, acc := range []string{"", "auth.kubernetes", `x"}`, "a b"} {
		if _, err := renderClaimPolicy(p, acc); err == nil {
			t.Errorf("accessor %q accepted", acc)
		}
	}
	if _, err := renderClaimPolicy(p, testAccessor); err != nil {
		t.Errorf("twin accessor refused: %v", err)
	}
}

// The accessor is needed when the parse tree uses it, not when the text
// happens to mention it.
func TestPolicyNeedsAccessorReadsTheParseTree(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    vaultv1alpha1.PolicySpec
		want bool
	}{
		{"static", vaultv1alpha1.PolicySpec{Rules: `path "a" { capabilities = ["read"] }`}, false},
		{"named in a comment", vaultv1alpha1.PolicySpec{Rules: "# uses .AuthMountAccessor elsewhere\npath \"a\" { capabilities = [\"read\"] }"}, false},
		{"escapes only", vaultv1alpha1.PolicySpec{Rules: "path \"{{`{{`}}x{{`}}`}}\" { capabilities = [\"read\"] }"}, false},
		{"accessor field", vaultv1alpha1.PolicySpec{Rules: `path "{{ .AuthMountAccessor }}" { capabilities = ["read"] }`}, true},
		{"service account function", vaultv1alpha1.PolicySpec{Rules: `path "a/{{ vaultSAName }}" { capabilities = ["read"] }`}, true},
		{"inside a branch", vaultv1alpha1.PolicySpec{Rules: `{{ if true }}path "a/{{ vaultSANamespace }}" { capabilities = ["read"] }{{ end }}`}, true},
		{"identity paths", vaultv1alpha1.PolicySpec{IdentityPaths: []vaultv1alpha1.IdentityPath{{Path: "a/{serviceAccountName}", Capabilities: []string{"read"}}}}, true},
	} {
		if got := policyNeedsAccessor(tc.p); got != tc.want {
			t.Errorf("%s: policyNeedsAccessor = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// An identity path under the claim's prefix is inside its scope for the policy
// guard, which judges guests in enforce mode; a path outside is not.
func TestRenderedIdentityPathsAreJudgedByThePolicyGuard(t *testing.T) {
	scope := policyguard.Scope{KVMount: "secret", SecretsPrefix: "clusters/x/namespaces/reg/apps/docker-registry"}
	in := vaultv1alpha1.PolicySpec{Name: "p", IdentityPaths: []vaultv1alpha1.IdentityPath{
		{Path: "secret/data/clusters/x/namespaces/reg/apps/docker-registry/{serviceAccountName}", Capabilities: []string{"read"}},
	}}
	body, err := renderClaimPolicy(in, testAccessor)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if v := policyguard.Check(body, scope); len(v) != 0 {
		t.Fatalf("in-scope identity path refused: %v", v)
	}
	out := in
	out.IdentityPaths = []vaultv1alpha1.IdentityPath{{Path: "secret/data/clusters/y/{serviceAccountName}", Capabilities: []string{"read"}}}
	body, err = renderClaimPolicy(out, testAccessor)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if v := policyguard.Check(body, scope); len(v) == 0 {
		t.Fatal("out-of-scope identity path passed the guard")
	}
}

// crdPolicyField is the schema of spec.policies[].<field> in the VaultClaim CRD
// the tree ships.
func crdPolicyField(t *testing.T, field ...string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", "bases", "vault.in-cloud.io_vaultclaims.yaml"))
	if err != nil {
		t.Fatalf("read CRD: %v", err)
	}
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatalf("decode CRD: %v", err)
	}
	node := crd.Spec.Versions[0].Schema.OpenAPIV3Schema
	for _, step := range append([]string{"spec", "policies"}, field...) {
		props, _ := node["properties"].(map[string]any)
		next, _ := props[step].(map[string]any)
		if next == nil {
			t.Fatalf("CRD has no %q on the way to policies[].%s", step, strings.Join(field, "."))
		}
		if items, ok := next["items"].(map[string]any); ok {
			next = items
		}
		node = next
	}
	return node
}

// The renderer and the schema judge a path by one pattern: the CRD must carry
// the constant the renderer compiles.
func TestIdentityPathPatternIsTheOneInTheCRD(t *testing.T) {
	node := crdPolicyField(t, "identityPaths", "path")
	if got, _ := node["pattern"].(string); got != vaultv1alpha1.IdentityPathPattern {
		t.Fatalf("CRD pattern %q differs from IdentityPathPattern %q", got, vaultv1alpha1.IdentityPathPattern)
	}
}

// The renderer and the schema bound the rules by one length.
func TestMaxRulesLengthIsTheOneInTheCRD(t *testing.T) {
	node := crdPolicyField(t, "rules")
	if got, _ := node["maxLength"].(float64); int(got) != vaultv1alpha1.MaxRulesLength {
		t.Fatalf("CRD maxLength of rules = %v, want MaxRulesLength %d", node["maxLength"], vaultv1alpha1.MaxRulesLength)
	}
}

// renderChildEnv carries the rules a child run of the bounded-time probe renders.
const renderChildEnv = "VAULT_OPERATOR_RENDER_PROBE_RULES"

// A loop or a self-calling template in the rules is refused at once, both on
// the apply path and on the drift check that renders every claim. The render
// runs in a child process of the test binary, so one that does not return is
// killed at the deadline instead of holding the run or its memory.
func TestRenderClaimPolicyRefusesALoopWithinBoundedTime(t *testing.T) {
	if rules, child := os.LookupEnv(renderChildEnv); child {
		_, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: rules}, "")
		fmt.Printf("render outcome: %v\n", err)
		return
	}
	const deadline = 10 * time.Second
	for name, rules := range map[string]string{
		"range over a number with a body": "{{range 100000000000}}x{{end}}",
		"range over a number":             "{{range 100000000000}}{{end}}",
		"self-calling template":           `{{define "a"}}{{template "a"}}{{template "a"}}{{end}}{{template "a"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRenderClaimPolicyRefusesALoopWithinBoundedTime$")
			cmd.Env = append(os.Environ(), renderChildEnv+"="+rules)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("the render of %q did not return within %s", rules, deadline)
			}
			if err != nil {
				t.Fatalf("child run: %v\n%s", err, out)
			}
			if want := "render outcome: " + errTemplateForm.Error(); !strings.Contains(string(out), want) {
				t.Fatalf("the render of %q was not refused as a template form:\n%s", rules, out)
			}
		})
	}
}

// Only text, the accessor field, the SA functions and string constants are
// admitted; every other construct of the template language is refused by its
// parse tree before anything executes. The admitted twins render.
func TestRenderClaimPolicyAdmitsOnlyTheClosedForms(t *testing.T) {
	for _, rules := range []string{
		`{{range 3}}x{{end}}`,
		`{{if true}}x{{end}}`,
		`{{with .AuthMountAccessor}}{{.}}{{end}}`,
		`{{block "b" .}}x{{end}}`,
		`{{define "a"}}x{{end}}{{template "a"}}`,
		`{{printf "%09d" 1}}`,
		`{{ .AuthMountAccessor | printf "%s" }}`,
		`{{ len "x" }}`,
		`{{ $x := "a" }}{{ $x }}`,
		`{{ . }}`,
		`{{ 1 }}`,
		`{{ .Other }}`,
	} {
		_, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: rules}, testAccessor)
		if !errors.Is(err, errTemplateForm) {
			t.Errorf("rules %q: err = %v, want errTemplateForm", rules, err)
		}
	}
	for rules, want := range map[string]string{
		`a {{- .AuthMountAccessor -}} b`: "a" + testAccessor + "b",
		"{{ `x` }}":                      "x",
		`{{ "x" }}`:                      "x",
		`{{vaultSAName}}`:                "{{identity.entity.aliases." + testAccessor + ".metadata.service_account_name}}",
	} {
		got, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: rules}, testAccessor)
		if err != nil || got != want {
			t.Errorf("admitted rules %q: got %q, %v; want %q", rules, got, err, want)
		}
	}
}

// The renderer refuses rules longer than the schema admits, so a claim stored
// before the limit renders nothing larger; rules at the limit render.
func TestRenderClaimPolicyRefusesRulesLongerThanTheSchema(t *testing.T) {
	at := "#" + strings.Repeat("x", vaultv1alpha1.MaxRulesLength-1)
	if got, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: at}, testAccessor); err != nil || got != at {
		t.Fatalf("rules at the limit: %d bytes, %v", len(got), err)
	}
	if _, err := renderClaimPolicy(vaultv1alpha1.PolicySpec{Name: "p", Rules: at + "x"}, testAccessor); !errors.Is(err, errRulesTooLong) {
		t.Fatalf("rules past the limit: err = %v, want errRulesTooLong", err)
	}
}

// A rendered body is bounded whatever the accessor holds, through the rules
// and through identity paths alike; the same policy renders with an accessor
// of the usual form.
func TestRenderClaimPolicyBoundsTheRenderedBody(t *testing.T) {
	long := strings.Repeat("a", 64<<10)
	rules := strings.Repeat(`path "x/{{ .AuthMountAccessor }}" { capabilities = ["read"] }`+"\n", 8)
	paths := make([]vaultv1alpha1.IdentityPath, 0, 8)
	for i := range 8 {
		paths = append(paths, vaultv1alpha1.IdentityPath{
			Path: fmt.Sprintf("x/{serviceAccountNamespace}/{serviceAccountName}/%d", i), Capabilities: []string{"read"}})
	}
	for name, p := range map[string]vaultv1alpha1.PolicySpec{
		"rules":          {Name: "p", Rules: rules},
		"identity paths": {Name: "p", IdentityPaths: paths},
	} {
		if _, err := renderClaimPolicy(p, long); !errors.Is(err, errRenderTooLarge) {
			t.Errorf("%s with a %d-byte accessor: err = %v, want errRenderTooLarge", name, len(long), err)
		}
		if _, err := renderClaimPolicy(p, testAccessor); err != nil {
			t.Errorf("%s with the usual accessor: %v", name, err)
		}
	}
}
