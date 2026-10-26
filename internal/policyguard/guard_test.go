/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package policyguard

import (
	"strings"
	"testing"
)

func claimScope() Scope {
	return Scope{
		KVMount:       "secret",
		SecretsPrefix: "clusters/acme-ab3b6f",
		TransitMount:  "transit",
		TransitKeys:   []string{"acme-ab3b6f"},
	}
}

// The four policy shapes the production census found, rendered for one claim.
// Each must pass: the guard is closed, so a false refusal here is a regression
// on live claims.
var lawfulShapes = map[string]string{
	"read-only": `path "sys/mounts" { capabilities = ["read"] }

path "secret/data/clusters/acme-ab3b6f/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/clusters/acme-ab3b6f/*" {
  capabilities = ["list"]
}
`,
	"etcd-kms": `path "transit/encrypt/acme-ab3b6f" {
  capabilities = ["update"]
}

path "transit/decrypt/acme-ab3b6f" {
  capabilities = ["update"]
}

path "transit/keys/acme-ab3b6f" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
`,
	"app-leaves": `path "secret/data/clusters/acme-ab3b6f/argocd" { capabilities = ["read"] }
path "secret/data/clusters/acme-ab3b6f/docker-registry" { capabilities = ["read"] }
path "secret/data/clusters/acme-ab3b6f/s3" { capabilities = ["read"] }
`,
	"app-leaves-with-lookup": `path "secret/data/clusters/acme-ab3b6f/argocd" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
`,
	"json-form":         `{"path": {"secret/data/clusters/acme-ab3b6f/*": {"capabilities": ["read"]}}}`,
	"exact-prefix-leaf": `path "secret/data/clusters/acme-ab3b6f" { capabilities = ["read"] }`,
	"leading-slash":     `path "/secret/data/clusters/acme-ab3b6f/x" { capabilities = ["read"] }`,
	"identity-template-below-prefix": `path "secret/data/clusters/acme-ab3b6f/{{identity.entity.aliases.auth_kubernetes_1234.metadata.service_account_name}}" {
  capabilities = ["read"]
}`,
	"own-writes":  `path "secret/data/clusters/acme-ab3b6f/app/*" { capabilities = ["create", "read", "update", "patch", "delete", "list"] }`,
	"deny-in-own": `path "secret/data/clusters/acme-ab3b6f/frozen" { capabilities = ["deny"] }`,
}

func TestLawfulShapesPass(t *testing.T) {
	for name, rules := range lawfulShapes {
		t.Run(name, func(t *testing.T) {
			if v := Check(rules, claimScope()); len(v) != 0 {
				t.Fatalf("lawful policy refused: %v", v)
			}
		})
	}
}

// Each case changes exactly one fact against a lawful twin from the table above.
func TestEscalationsAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		rule  string
	}{
		{"operator policy store", `path "sys/policies/acl/x" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"policy store glob", `path "sys/policies/*" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"auth method config", `path "sys/auth/kubernetes-mgmt" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"other mount roles", `path "auth/kubernetes-mgmt/role/vault-operator" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"identity store", `path "identity/entity" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"audit device", `path "sys/audit/file" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"raw storage", `path "sys/raw/*" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"generate root", `path "sys/generate-root/attempt" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"token creation", `path "auth/token/create" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"glob above the prefix", `path "secret/data/clusters/*" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"glob glued to the prefix", `path "secret/data/clusters/acme-ab3b6f*" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"segment wildcard inside the prefix", `path "secret/data/clusters/+/x" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"segment wildcard before kv kind", `path "secret/+/clusters/acme-ab3b6f/x" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"other claim's prefix", `path "secret/data/clusters/other-cb93d2/*" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"dot-dot escape", `path "secret/data/clusters/acme-ab3b6f/../other-cb93d2/x" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"kv delete endpoint", `path "secret/destroy/clusters/acme-ab3b6f/x" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"template above the prefix", `path "secret/data/{{identity.entity.name}}/x" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"other claim's transit key", `path "transit/decrypt/other-cb93d2" { capabilities = ["update"] }`, RulePathOutsideScope},
		{"transit export", `path "transit/export/encryption-key/acme-ab3b6f" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"transit key glob", `path "transit/keys/*" { capabilities = ["read"] }`, RulePathOutsideScope},
		{"sudo in own prefix", `path "secret/data/clusters/acme-ab3b6f/*" { capabilities = ["read", "sudo"] }`, RuleCapabilityNotAllowed},
		{"write to sys/mounts", `path "sys/mounts" { capabilities = ["update"] }`, RuleCapabilityNotAllowed},
		{"update own transit key config", `path "transit/keys/acme-ab3b6f" { capabilities = ["update"] }`, RuleCapabilityNotAllowed},
		{"unknown capability", `path "secret/data/clusters/acme-ab3b6f/x" { capabilities = ["root"] }`, RuleCapabilityNotAllowed},
		{"legacy policy shortcut", `path "secret/data/clusters/acme-ab3b6f/x" { policy = "write" }`, RuleUnknownKey},
		{"parameter constraints", `path "secret/data/clusters/acme-ab3b6f/x" {
  capabilities = ["update"]
  allowed_parameters = { "*" = [] }
}`, RuleUnknownKey},
		{"top-level name", "name = \"x\"\n" + `path "secret/data/clusters/acme-ab3b6f/x" { capabilities = ["read"] }`, RuleUnknownKey},
		{"two-label stanza", `path "secret/data/clusters/acme-ab3b6f/x" "extra" { capabilities = ["read"] }`, RuleUnknownKey},
		{"parse error", `path "secret/data/clusters/acme-ab3b6f/x" { capabilities = ["read" }`, RuleUnparseable},
		{"json escalation", `{"path": {"sys/policies/acl/x": {"capabilities": ["update"]}}}`, RulePathOutsideScope},
		{"json parse error", `{"path": [`, RuleUnparseable},
		// HCL v1 accepts this truncated JSON; the stanza it yields has no body.
		{"json stanza without body", `{"path": {"sys/policies/acl/x": }`, RuleUnknownKey},
		{"plus-star", `path "secret/data/clusters/acme-ab3b6f/+*" { capabilities = ["read"] }`, RulePathOutsideScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Check(tc.rules, claimScope())
			if len(v) == 0 {
				t.Fatalf("escalation accepted: %s", tc.rules)
			}
			found := false
			for _, x := range v {
				if x.Rule == tc.rule {
					found = true
				}
			}
			if !found {
				t.Fatalf("violations %v do not name rule %s", v, tc.rule)
			}
		})
	}
}

// One lawful stanza must not launder a forbidden one in the same document.
func TestEveryStanzaIsJudged(t *testing.T) {
	rules := lawfulShapes["read-only"] + "\npath \"sys/policies/acl/x\" { capabilities = [\"update\"] }\n"
	v := Check(rules, claimScope())
	if len(v) != 1 || v[0].Path != "sys/policies/acl/x" {
		t.Fatalf("violations = %v, want exactly the sys/policies stanza", v)
	}
}

// A duplicated capabilities key is judged in full, not by its first value.
func TestDuplicatedCapabilitiesAreAllJudged(t *testing.T) {
	rules := `path "secret/data/clusters/acme-ab3b6f/x" {
  capabilities = ["read"]
  capabilities = ["sudo"]
}`
	v := Check(rules, claimScope())
	if len(v) == 0 || v[0].Rule != RuleCapabilityNotAllowed {
		t.Fatalf("violations = %v, want CapabilityNotAllowed", v)
	}
}

// A scope that itself carries a wildcard would make every comparison above
// meaningless; it refuses everything instead of accepting everything.
func TestWildcardScopeRefusesEverything(t *testing.T) {
	for _, mutate := range []func(*Scope){
		func(s *Scope) { s.SecretsPrefix = "clusters/*" },
		func(s *Scope) { s.SecretsPrefix = "" },
		func(s *Scope) { s.KVMount = "+" },
		func(s *Scope) { s.TransitKeys = []string{"k*"} },
		func(s *Scope) { s.SecretsPrefix = "clusters/../x" },
	} {
		s := claimScope()
		mutate(&s)
		v := Check(lawfulShapes["read-only"], s)
		if len(v) == 0 || v[0].Rule != RuleScopeInvalid {
			t.Fatalf("scope %+v: violations = %v, want ScopeInvalid", s, v)
		}
	}
}

func TestTransitClassNeedsDeclaredKey(t *testing.T) {
	s := claimScope()
	s.TransitKeys = nil
	if v := Check(lawfulShapes["etcd-kms"], s); len(v) == 0 {
		t.Fatal("transit stanzas accepted for a claim that declares no keys")
	}
}

func TestViolationTextNamesThePath(t *testing.T) {
	v := Check(`path "sys/policies/acl/x" { capabilities = ["update"] }`, claimScope())
	if len(v) != 1 || !strings.Contains(v[0].String(), `"sys/policies/acl/x"`) {
		t.Fatalf("violation text %v does not name the path", v)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"audit": ModeAudit, "enforce": ModeEnforce} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("off"); err == nil {
		t.Fatal("ParseMode accepted an unknown mode")
	}
}
