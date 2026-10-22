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

// Alias metadata keys the Kubernetes auth method writes on every login.
const (
	metaSAName      = "service_account_name"
	metaSANamespace = "service_account_namespace"
)

var (
	errBareIdentity = errors.New("the rules use a Vault template ({{identity...}}) unescaped: " +
		"write {{`{{`}}identity...{{`}}`}}, or use {{ vaultSAName }} / {{ vaultSANamespace }} or identityPaths")
	errAccessorForm = errors.New("the auth mount accessor has an unexpected form")

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
func renderClaimPolicy(p vaultv1alpha1.PolicySpec, accessor string) (string, error) {
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
		var buf bytes.Buffer
		if err := t.Execute(&buf, map[string]string{"AuthMountAccessor": accessor}); err != nil {
			return "", err
		}
		body = buf.String()
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
	}
	return b.String(), nil
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
