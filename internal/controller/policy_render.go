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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"text/template/parse"
	"unicode/utf8"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// Template functions offered to spec.policies[].rules. identity is declared
// only so that a bare Vault template parses and can be refused by name; it is
// never executed.
const (
	funcSAName      = "vaultSAName"
	funcSANamespace = "vaultSANamespace"
	funcBareVault   = "identity"
)

// maxRenderedPolicy bounds the HCL one policy renders to. Admitted rules expand
// at most a few times over (an SA function writes a Vault template of under a
// hundred bytes), so a body of MaxRulesLength with identity paths stays well
// inside it; the bound is what keeps an accessor of unexpected length from
// growing a body without limit.
const maxRenderedPolicy = 256 << 10

// Alias metadata keys the Kubernetes auth method writes on every login.
const (
	metaSAName      = "service_account_name"
	metaSANamespace = "service_account_namespace"
)

var (
	errBareIdentity = errors.New("the rules use a Vault template ({{identity...}}) unescaped: " +
		"write {{`{{`}}identity...{{`}}`}}, or use {{ vaultSAName }} / {{ vaultSANamespace }} or identityPaths")
	errAccessorForm = errors.New("the auth mount accessor has an unexpected form")
	errTemplateForm = errors.New("the rules use a template form outside the admitted ones " +
		"(text, {{ .AuthMountAccessor }}, {{ vaultSAName }}, {{ vaultSANamespace }}, a string constant such as {{`{{`}})")
	errRulesTooLong   = errors.New("the rules are longer than the limit")
	errRenderTooLarge = errors.New("the rendered policy is larger than the limit")

	// accessorForm is what an accessor may hold to be embedded in a Vault
	// template; Vault's own are auth_<type>_<hex>.
	accessorForm     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	identityPathForm = regexp.MustCompile(vaultv1alpha1.IdentityPathPattern)
	bareVaultHint    = regexp.MustCompile(`\{\{-?\s*identity\b`)

	identityCapabilities = map[string]struct{}{
		"create": {}, "read": {}, "update": {}, "patch": {}, "delete": {}, "list": {},
	}
)

// identityTemplate is the Vault template naming alias metadata key of the
// login through the mount with accessor.
func identityTemplate(accessor, key string) string {
	return "{{identity.entity.aliases." + accessor + ".metadata." + key + "}}"
}

func parsePolicyRules(rules, accessor string) (*template.Template, error) {
	meta := func(key string) func() (string, error) {
		return func() (string, error) {
			if !accessorForm.MatchString(accessor) {
				return "", errAccessorForm
			}
			return identityTemplate(accessor, key), nil
		}
	}
	return template.New("policy").Option("missingkey=error").Funcs(template.FuncMap{
		funcSAName:      meta(metaSAName),
		funcSANamespace: meta(metaSANamespace),
		funcBareVault:   func() (string, error) { return "", errBareIdentity },
	}).Parse(rules)
}

// templateUse is what a parsed rules template refers to.
type templateUse struct {
	data         bool // the template data: {{ .AuthMountAccessor }}, {{ . }}, $
	saFunctions  bool // vaultSAName, vaultSANamespace
	bareIdentity bool // {{identity...}} written without escaping
}

func inspectTemplate(t *template.Template) templateUse {
	var u templateUse
	for _, tt := range t.Templates() {
		if tt.Tree != nil {
			u.walk(tt.Root)
		}
	}
	return u
}

func (u *templateUse) walk(n parse.Node) {
	switch x := n.(type) {
	case *parse.ListNode:
		if x == nil {
			return
		}
		for _, c := range x.Nodes {
			u.walk(c)
		}
	case *parse.ActionNode:
		u.walk(x.Pipe)
	case *parse.PipeNode:
		if x == nil {
			return
		}
		for _, d := range x.Decl {
			u.walk(d)
		}
		for _, c := range x.Cmds {
			u.walk(c)
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			u.walk(a)
		}
	case *parse.ChainNode:
		u.walk(x.Node)
	case *parse.IfNode:
		u.walkBranch(&x.BranchNode)
	case *parse.RangeNode:
		u.walkBranch(&x.BranchNode)
	case *parse.WithNode:
		u.walkBranch(&x.BranchNode)
	case *parse.TemplateNode:
		u.walk(x.Pipe)
	case *parse.FieldNode, *parse.DotNode:
		u.data = true
	case *parse.VariableNode:
		if len(x.Ident) > 0 && x.Ident[0] == "$" {
			u.data = true
		}
	case *parse.IdentifierNode:
		switch x.Ident {
		case funcSAName, funcSANamespace:
			u.saFunctions = true
		case funcBareVault:
			u.bareIdentity = true
		}
	}
}

func (u *templateUse) walkBranch(b *parse.BranchNode) {
	u.walk(b.Pipe)
	u.walk(b.List)
	u.walk(b.ElseList)
}

// admitTemplate refuses every construct of the template language but the
// closed set rules are written in: text, and actions of one operand that is a
// string constant, the accessor field or a ServiceAccount function. Without
// loops, branches, variables, pipelines, built-in functions or further
// templates, a render is one pass over the parse tree, and its output grows
// with the rules alone.
func admitTemplate(t *template.Template) error {
	for _, tt := range t.Templates() {
		if tt.Name() != t.Name() {
			return fmt.Errorf("%w: the template %q is defined", errTemplateForm, clipConstruct(tt.Name()))
		}
	}
	if t.Tree == nil || t.Root == nil {
		return nil
	}
	for _, n := range t.Root.Nodes {
		if err := admitNode(t.Tree, n); err != nil {
			return err
		}
	}
	return nil
}

func admitNode(tree *parse.Tree, n parse.Node) error {
	refuse := func(what string) error {
		loc, _ := tree.ErrorContext(n)
		return fmt.Errorf("%w: %s at %s", errTemplateForm, clipConstruct(what), loc)
	}
	switch x := n.(type) {
	case *parse.TextNode:
		return nil
	case *parse.ActionNode:
		pipe := x.Pipe
		if pipe == nil || len(pipe.Decl) > 0 || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
			return refuse("an action of more than one operand")
		}
		switch a := pipe.Cmds[0].Args[0].(type) {
		case *parse.StringNode:
			return nil
		case *parse.FieldNode:
			if len(a.Ident) == 1 && a.Ident[0] == "AuthMountAccessor" {
				return nil
			}
			return refuse("the field ." + strings.Join(a.Ident, "."))
		case *parse.IdentifierNode:
			switch a.Ident {
			case funcSAName, funcSANamespace, funcBareVault:
				return nil
			}
			return refuse("the function " + a.Ident)
		default:
			return refuse("the operand " + a.String())
		}
	case *parse.RangeNode:
		return refuse("range")
	case *parse.IfNode:
		return refuse("if")
	case *parse.WithNode:
		return refuse("with")
	case *parse.TemplateNode:
		return refuse("template")
	default:
		return refuse(n.String())
	}
}

// maxConstructText bounds how much of a refused construct a refusal quotes:
// the construct is the writer's own text, but an operand may be as long as
// the rules, and the refusal ends up in a status condition.
const maxConstructText = 64

func clipConstruct(s string) string {
	if len(s) <= maxConstructText {
		return s
	}
	cut := maxConstructText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// rulesTooLong and renderTooLarge are the refusals of the two bounds. Their
// text names the measured size and the limit and is shown to the writer as
// it is; errors.Is still matches the sentinels.
func rulesTooLong(n int) error {
	return fmt.Errorf("%w: %d bytes, the limit is %d", errRulesTooLong, n, vaultv1alpha1.MaxRulesLength)
}

func renderTooLarge(atLeast int) error {
	return fmt.Errorf("%w: at least %d bytes, the limit is %d", errRenderTooLarge, atLeast, maxRenderedPolicy)
}

// boundedBuffer is a render target that fails the write which would take it
// past max bytes, which ends the template execution with that error.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if n := b.buf.Len() + len(p); n > b.max {
		return 0, renderTooLarge(n)
	}
	return b.buf.Write(p)
}

// policyNeedsAccessor reports whether rendering p reads the auth mount
// accessor: identity paths always do, rules when their parse tree refers to
// the template data or to a ServiceAccount function. Rules that do not parse
// need nothing; rendering reports them.
func policyNeedsAccessor(p vaultv1alpha1.PolicySpec) bool {
	if len(p.IdentityPaths) > 0 {
		return true
	}
	if p.Rules == "" {
		return false
	}
	t, err := parsePolicyRules(p.Rules, "")
	if err != nil {
		return false
	}
	u := inspectTemplate(t)
	return u.data || u.saFunctions
}

func claimNeedsAccessor(claim *vaultv1alpha1.VaultClaim) bool {
	for i := range claim.Spec.Policies {
		if policyNeedsAccessor(claim.Spec.Policies[i]) {
			return true
		}
	}
	return false
}

// renderClaimPolicy is the HCL the operator writes for p: the rules rendered
// as a Go template, then one stanza per identity path. A policy without
// identity paths renders exactly as its rules always have.
//
// Its error is shown to the writer as it is (stepApplyPolicies): rendering
// reads nothing but p and the accessor, and no error text carries the
// accessor or the rendered body — only the writer's own spec, a construct of
// it clipped to maxConstructText, and the operator's limits.
func renderClaimPolicy(p vaultv1alpha1.PolicySpec, accessor string) (string, error) {
	if len(p.Rules) > vaultv1alpha1.MaxRulesLength {
		return "", rulesTooLong(len(p.Rules))
	}
	var body string
	if p.Rules != "" {
		t, err := parsePolicyRules(p.Rules, accessor)
		if err != nil {
			if bareVaultHint.MatchString(p.Rules) {
				return "", errBareIdentity
			}
			return "", err
		}
		if inspectTemplate(t).bareIdentity {
			return "", errBareIdentity
		}
		if err := admitTemplate(t); err != nil {
			return "", err
		}
		out := &boundedBuffer{max: maxRenderedPolicy}
		if err := t.Execute(out, map[string]string{"AuthMountAccessor": accessor}); err != nil {
			return "", err
		}
		body = out.buf.String()
	}
	if len(p.IdentityPaths) == 0 {
		return body, nil
	}
	if !accessorForm.MatchString(accessor) {
		return "", errAccessorForm
	}
	var b strings.Builder
	b.WriteString(body)
	for _, ip := range p.IdentityPaths {
		stanza, err := identityStanza(ip, accessor)
		if err != nil {
			return "", err
		}
		if b.Len() > 0 {
			if !strings.HasSuffix(b.String(), "\n") {
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
		b.WriteString(stanza)
		if b.Len() > maxRenderedPolicy {
			return "", renderTooLarge(b.Len())
		}
	}
	return b.String(), nil
}

// RenderClaimPolicy is renderClaimPolicy for tools outside the operator, such
// as the policy guard census: the same admitted template forms, the same
// bounds, the same HCL the operator writes.
func RenderClaimPolicy(p vaultv1alpha1.PolicySpec, accessor string) (string, error) {
	return renderClaimPolicy(p, accessor)
}

// identityStanza judges ip as the schema does, then renders its placeholders.
func identityStanza(ip vaultv1alpha1.IdentityPath, accessor string) (string, error) {
	if len(ip.Path) > 512 || !identityPathForm.MatchString(ip.Path) {
		return "", fmt.Errorf("identity path %q is not of the admitted form", ip.Path)
	}
	if len(ip.Capabilities) == 0 {
		return "", fmt.Errorf("identity path %q grants no capability", ip.Path)
	}
	caps := make([]string, 0, len(ip.Capabilities))
	for _, c := range ip.Capabilities {
		if _, ok := identityCapabilities[c]; !ok {
			return "", fmt.Errorf("identity path %q: capability %q is not offered", ip.Path, c)
		}
		caps = append(caps, `"`+c+`"`)
	}
	path := strings.NewReplacer(
		vaultv1alpha1.PlaceholderServiceAccountName, identityTemplate(accessor, metaSAName),
		vaultv1alpha1.PlaceholderServiceAccountNamespace, identityTemplate(accessor, metaSANamespace),
	).Replace(ip.Path)
	return fmt.Sprintf("path \"%s\" {\n  capabilities = [%s]\n}\n", path, strings.Join(caps, ", ")), nil
}
