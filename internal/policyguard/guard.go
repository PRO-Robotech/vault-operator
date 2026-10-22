/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package policyguard judges the ACL policies a VaultClaim asks the operator
// to write. The operator holds sys/policies/acl/* and auth/* with sudo, so a
// claim that could write any HCL would hold the operator's privileges. The
// guard is closed: a stanza passes only when its path belongs to one of the
// classes a claim owns, and every capability is one that class allows.
//
// Documents are parsed with HCL v1, the parser Vault itself uses, so the JSON
// form is judged like the HCL form and a document Vault would read
// differently from us cannot pass: a parse error or an unknown key refuses.
package policyguard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/token"
)

// Mode selects what a violation does.
type Mode string

const (
	// ModeAudit writes the policy and reports the violation (event, metric).
	ModeAudit Mode = "audit"
	// ModeEnforce refuses to write a policy with any violation.
	ModeEnforce Mode = "enforce"
)

// ParseMode accepts exactly the two modes.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeAudit, ModeEnforce:
		return Mode(s), nil
	}
	return "", fmt.Errorf("policy guard mode %q: want %q or %q", s, ModeAudit, ModeEnforce)
}

// Violation rules, a closed set.
const (
	RuleUnparseable          = "Unparseable"
	RuleUnknownKey           = "UnknownKey"
	RulePathOutsideScope     = "PathOutsideScope"
	RuleCapabilityNotAllowed = "CapabilityNotAllowed"
	RuleScopeInvalid         = "ScopeInvalid"
)

// Scope is what one claim owns: its KV prefix under the shared KV mount and
// its declared Transit keys.
type Scope struct {
	// KVMount is VaultConfig.spec.storage.kvMountPath.
	KVMount string
	// SecretsPrefix is spec.secretsPrefix.
	SecretsPrefix string
	// TransitMount is spec.transit.mountPath (defaulted).
	TransitMount string
	// TransitKeys are spec.transit.keys[].name.
	TransitKeys []string
}

// Violation names one refused stanza. Path is the stanza path as written, or
// empty for a document-level refusal.
type Violation struct {
	Path string
	Rule string
}

func (v Violation) String() string {
	if v.Path == "" {
		return v.Rule
	}
	return fmt.Sprintf("%s at path %q", v.Rule, v.Path)
}

// Capability sets per class. deny only narrows a token and is allowed
// everywhere a class matches; sudo is allowed nowhere.
var (
	kvCaps          = capSet("create", "read", "update", "patch", "delete", "list", "deny")
	transitReadCaps = capSet("read", "deny")
	transitUseCaps  = capSet("create", "update", "deny")
	readOnlyCaps    = capSet("read", "deny")
	renewCaps       = capSet("update", "deny")
)

func capSet(caps ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		out[c] = struct{}{}
	}
	return out
}

// Check judges one rendered policy document against scope. An empty result
// means every stanza belongs to the claim.
func Check(rules string, scope Scope) []Violation {
	if !scope.valid() {
		return []Violation{{Rule: RuleScopeInvalid}}
	}
	root, err := hcl.Parse(rules)
	if err != nil {
		return []Violation{{Rule: RuleUnparseable}}
	}
	list, ok := root.Node.(*ast.ObjectList)
	if !ok {
		return []Violation{{Rule: RuleUnparseable}}
	}

	var out []Violation
	for _, item := range list.Items {
		if name, ok := keyText(item); !ok || name != "path" {
			out = append(out, Violation{Rule: RuleUnknownKey})
		}
	}
	for _, item := range list.Filter("path").Items {
		out = append(out, judgeStanza(item, scope)...)
	}
	return out
}

func judgeStanza(item *ast.ObjectItem, scope Scope) []Violation {
	if len(item.Keys) != 1 {
		label, _ := keyText(item)
		return []Violation{{Path: label, Rule: RuleUnknownKey}}
	}
	path, ok := keyText(item)
	if !ok {
		return []Violation{{Rule: RuleUnknownKey}}
	}
	body, ok := item.Val.(*ast.ObjectType)
	if !ok {
		return []Violation{{Path: path, Rule: RuleUnknownKey}}
	}

	var caps []string
	for _, sub := range body.List.Items {
		key, ok := keyText(sub)
		if !ok || key != "capabilities" || len(sub.Keys) != 1 {
			return []Violation{{Path: path, Rule: RuleUnknownKey}}
		}
		var one []string
		if err := hcl.DecodeObject(&one, sub.Val); err != nil {
			return []Violation{{Path: path, Rule: RuleUnparseable}}
		}
		caps = append(caps, one...)
	}

	allowed := scope.classOf(path)
	if allowed == nil {
		return []Violation{{Path: path, Rule: RulePathOutsideScope}}
	}
	for _, c := range caps {
		if _, ok := allowed[c]; !ok {
			return []Violation{{Path: path, Rule: RuleCapabilityNotAllowed}}
		}
	}
	return nil
}

// keyText returns the first label of an item when it is an identifier or a
// string; anything else is not a key Vault would accept.
func keyText(item *ast.ObjectItem) (string, bool) {
	if len(item.Keys) == 0 || item.Keys[0] == nil {
		return "", false
	}
	tok := item.Keys[0].Token
	if tok.Type != token.IDENT && tok.Type != token.STRING {
		return "", false
	}
	s, ok := tok.Value().(string)
	return s, ok
}

// classOf returns the capabilities the stanza's path class allows, or nil when
// the path belongs to no class of this claim. The part of a path up to and
// including the claim's own boundary is compared as a literal, so a wildcard
// or a template there can never widen the match.
func (s Scope) classOf(raw string) map[string]struct{} {
	p := strings.TrimPrefix(raw, "/")
	if strings.Contains(p, "+*") || hasDotSegment(p) {
		return nil
	}
	switch p {
	case "sys/mounts", "auth/token/lookup-self":
		return readOnlyCaps
	case "auth/token/renew-self":
		return renewCaps
	}
	for _, kind := range []string{"data", "metadata"} {
		base := s.KVMount + "/" + kind + "/" + s.SecretsPrefix
		if p == base || strings.HasPrefix(p, base+"/") {
			return kvCaps
		}
	}
	for _, key := range s.TransitKeys {
		switch p {
		case s.TransitMount + "/keys/" + key:
			return transitReadCaps
		case s.TransitMount + "/encrypt/" + key, s.TransitMount + "/decrypt/" + key:
			return transitUseCaps
		}
	}
	return nil
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// valid refuses a scope whose own parts could act as wildcards, templates or
// path escapes: comparing against such a scope would accept anything.
func (s Scope) valid() bool {
	parts := append([]string{s.KVMount, s.SecretsPrefix}, s.TransitKeys...)
	if len(s.TransitKeys) > 0 {
		parts = append(parts, s.TransitMount)
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, "*+{}") || hasDotSegment(part) ||
			strings.HasPrefix(part, "/") || strings.HasSuffix(part, "/") {
			return false
		}
	}
	return true
}

// Summary renders violations in a stable order for conditions and events.
func Summary(v []Violation) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, x.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
