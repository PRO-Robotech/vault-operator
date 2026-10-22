/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command policyguard-census runs the policy guard over a VaultClaim list
// (`kubectl get vaultclaims -A -o json`) read from stdin and prints the
// violations it would raise. It is the rollout gate for --policy-guard=enforce:
// enforce is switched on only after this census reports zero on every cluster.
//
// Exit codes: 0 — no violations; 1 — violations found; 2 — input unreadable or
// empty (a census of nothing is not a pass).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/template"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

func main() {
	kvMount := flag.String("kv-mount", "secret", "VaultConfig.spec.storage.kvMountPath the claims share")
	accessor := flag.String("accessor", "auth_kubernetes_00000000", "accessor substituted for {{ .AuthMountAccessor }}")
	flag.Parse()

	var list vaultv1alpha1.VaultClaimList
	if err := json.NewDecoder(os.Stdin).Decode(&list); err != nil {
		fmt.Fprintf(os.Stderr, "decode VaultClaim list: %v\n", err)
		os.Exit(2)
	}
	claims, policies, violations := 0, 0, 0
	for i := range list.Items {
		c := &list.Items[i]
		claims++
		scope := policyguard.Scope{KVMount: *kvMount, SecretsPrefix: c.Spec.SecretsPrefix, TransitMount: "transit"}
		if c.Spec.Transit != nil {
			if c.Spec.Transit.MountPath != "" {
				scope.TransitMount = c.Spec.Transit.MountPath
			}
			for _, k := range c.Spec.Transit.Keys {
				scope.TransitKeys = append(scope.TransitKeys, k.Name)
			}
		}
		for _, p := range c.Spec.Policies {
			policies++
			rendered, err := render(p.Rules, *accessor)
			if err != nil {
				violations++
				fmt.Printf("%s/%s policy %q: does not render\n", c.Namespace, c.Name, p.Name)
				continue
			}
			for _, v := range policyguard.Check(rendered, scope) {
				violations++
				fmt.Printf("%s/%s policy %q: %s\n", c.Namespace, c.Name, p.Name, v)
			}
		}
	}
	fmt.Printf("census: claims=%d policies=%d violations=%d\n", claims, policies, violations)
	switch {
	case claims == 0:
		os.Exit(2)
	case violations > 0:
		os.Exit(1)
	}
}

func render(rules, accessor string) (string, error) {
	tmpl, err := template.New("policy").Option("missingkey=error").Parse(rules)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{"AuthMountAccessor": accessor}); err != nil {
		return "", err
	}
	return buf.String(), nil
}
