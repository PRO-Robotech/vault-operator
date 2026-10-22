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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/policyguard"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the census over the list read from in; it returns the exit code.
func run(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("policyguard-census", flag.ContinueOnError)
	fs.SetOutput(errOut)
	kvMount := fs.String("kv-mount", "secret", "VaultConfig.spec.storage.kvMountPath the claims share")
	accessor := fs.String("accessor", "auth_kubernetes_00000000", "auth mount accessor templated policies and identity paths are rendered with")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var list vaultv1alpha1.VaultClaimList
	if err := json.NewDecoder(in).Decode(&list); err != nil {
		fmt.Fprintf(errOut, "decode VaultClaim list: %v\n", err)
		return 2
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
			// The operator's own render: the closed set of template forms,
			// the bounds on rules and on the rendered body, identity paths.
			rendered, err := controller.RenderClaimPolicy(p, *accessor)
			if err != nil {
				violations++
				fmt.Fprintf(out, "%s/%s policy %q: does not render: %v\n", c.Namespace, c.Name, p.Name, err)
				continue
			}
			for _, v := range policyguard.Check(rendered, scope) {
				violations++
				fmt.Fprintf(out, "%s/%s policy %q: %s\n", c.Namespace, c.Name, p.Name, v)
			}
		}
	}
	fmt.Fprintf(out, "census: claims=%d policies=%d violations=%d\n", claims, policies, violations)
	switch {
	case claims == 0:
		return 2
	case violations > 0:
		return 1
	}
	return 0
}
