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
	"slices"
	"sort"
	"strings"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// builtinReservedPolicies are Vault's own policies; no claim may write,
// delete or reference them.
var builtinReservedPolicies = []string{"root", "default", "response-wrapping", "control-group"}

// OwnershipPolicy is the operator-wide part of name ownership. Each list comes
// from the deployment (the chart that writes the operator's own Vault objects),
// so the binary does not carry another product's names.
type OwnershipPolicy struct {
	// ReservedPolicyNames are never written, deleted or referenced by a claim
	// (the operators' own policies). Vault's built-ins are always reserved.
	ReservedPolicyNames []string
	// ExternalPolicyNames are written by someone else; claims never write or
	// delete them, but roles may reference them.
	ExternalPolicyNames []string
	// ReservedRoleNames are never written or deleted on an operator mount, in
	// addition to the roles VaultConfigs log in with.
	ReservedRoleNames []string
	// GuestMounts are auth mounts other than the VaultConfig mounts that guest
	// claims may add roles to.
	GuestMounts []string
}

func (o OwnershipPolicy) reservedPolicy(name string) bool {
	return containsName(builtinReservedPolicies, name) || containsName(o.ReservedPolicyNames, name)
}

// protectedPolicy: a claim never writes or deletes it.
func (o OwnershipPolicy) protectedPolicy(name string) bool {
	return o.reservedPolicy(name) || containsName(o.ExternalPolicyNames, name)
}

// nameKey is a policy or role name as Vault resolves it: Vault lower-cases a
// policy name and trims its spaces before every lookup, write and delete, and
// stores kubernetes roles lower-cased. "Ext-Template" and " ext-template "
// are the object "ext-template", so every ownership comparison of policy and
// role names goes through nameKey.
func nameKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// containsName reports whether list names the same Vault object as name.
func containsName(list []string, name string) bool {
	k := nameKey(name)
	return slices.ContainsFunc(list, func(x string) bool { return nameKey(x) == k })
}

func normMount(m string) string { return strings.Trim(m, "/") }

// ownershipView is what one pass knows about the rest of the cluster: the
// operator mounts and every other claim. It is built once per pass from the
// cache; nothing in it is read from Vault.
type ownershipView struct {
	policy OwnershipPolicy
	// operatorMounts maps a VaultConfig mount to the roles VaultConfigs log in with there.
	operatorMounts map[string][]string
	// elders are the claims that win a conflict against this one.
	elders []*vaultv1alpha1.VaultClaim
}

// olderThan orders claims for conflicts: creation time, then namespace/name.
// The elder keeps the name; the younger is refused.
func olderThan(a, b *vaultv1alpha1.VaultClaim) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
}

func (r *VaultClaimReconciler) buildOwnershipView(ctx context.Context, claim *vaultv1alpha1.VaultClaim) (*ownershipView, error) {
	view := &ownershipView{policy: r.Ownership, operatorMounts: map[string][]string{}}

	var cfgs vaultv1alpha1.VaultConfigList
	if err := r.List(ctx, &cfgs); err != nil {
		return nil, fmt.Errorf("list VaultConfigs: %w", err)
	}
	for i := range cfgs.Items {
		auth := cfgs.Items[i].Spec.ManagerAuth
		m := normMount(auth.MountPath)
		if m == "" {
			continue
		}
		view.operatorMounts[m] = append(view.operatorMounts[m], auth.Role)
	}

	var claims vaultv1alpha1.VaultClaimList
	if err := r.List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("list VaultClaims: %w", err)
	}
	for i := range claims.Items {
		other := &claims.Items[i]
		if other.UID == claim.UID || (other.Namespace == claim.Namespace && other.Name == claim.Name) {
			continue
		}
		if olderThan(other, claim) {
			view.elders = append(view.elders, other)
		}
	}
	return view, nil
}

// everyOtherClaim lists claims other than this one, elder or not; deletion uses
// it so that a name another claim still declares is never removed.
func (r *VaultClaimReconciler) everyOtherClaim(ctx context.Context, claim *vaultv1alpha1.VaultClaim) ([]*vaultv1alpha1.VaultClaim, error) {
	var claims vaultv1alpha1.VaultClaimList
	if err := r.List(ctx, &claims); err != nil {
		return nil, fmt.Errorf("list VaultClaims: %w", err)
	}
	out := make([]*vaultv1alpha1.VaultClaim, 0, len(claims.Items))
	for i := range claims.Items {
		other := &claims.Items[i]
		if other.UID == claim.UID || (other.Namespace == claim.Namespace && other.Name == claim.Name) {
			continue
		}
		out = append(out, other)
	}
	return out, nil
}

func (v *ownershipView) isOperatorMount(mount string) bool {
	_, ok := v.operatorMounts[normMount(mount)]
	return ok
}

// reservedRole: roles on an operator mount that claims never write or delete.
func (v *ownershipView) reservedRole(mount, role string) bool {
	roles, ok := v.operatorMounts[normMount(mount)]
	if !ok {
		return false
	}
	return containsName(roles, role) || containsName(v.policy.ReservedRoleNames, role)
}

// claimPolicyNames is spec ∪ ledger: a claim holds a name it declares and a
// name it may still have in Vault.
func claimPolicyNames(c *vaultv1alpha1.VaultClaim) []string {
	out := make([]string, 0, len(c.Spec.Policies))
	for i := range c.Spec.Policies {
		out = append(out, c.Spec.Policies[i].Name)
	}
	if c.Status.Vault != nil {
		out = append(out, c.Status.Vault.AppliedPolicies...)
	}
	return out
}

func claimRoleNames(c *vaultv1alpha1.VaultClaim) []string {
	out := make([]string, 0, len(c.Spec.Roles))
	for i := range c.Spec.Roles {
		out = append(out, c.Spec.Roles[i].Name)
	}
	if c.Status.Vault != nil {
		out = append(out, c.Status.Vault.AppliedRoles...)
	}
	return out
}

func claimTransitKeys(c *vaultv1alpha1.VaultClaim) []string {
	mount := transitMountPath(c)
	var out []string
	if c.Spec.Transit != nil {
		for i := range c.Spec.Transit.Keys {
			out = append(out, mount+"/"+c.Spec.Transit.Keys[i].Name)
		}
	}
	if c.Status.Vault != nil {
		for i := range c.Status.Vault.TransitKeys {
			out = append(out, mount+"/"+c.Status.Vault.TransitKeys[i].Name)
		}
	}
	return out
}

// prefixesOverlap: equal, or one continues the other by whole segments.
func prefixesOverlap(a, b string) bool {
	a, b = strings.Trim(a, "/"), strings.Trim(b, "/")
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// admissionRefusal is one reason a claim may not proceed: which condition
// carries it, the reason and the message.
type admissionRefusal struct {
	condition string
	reason    string
	message   string
}

// admit runs every check that needs only Kubernetes state. It never reads
// Vault and runs before the first Vault write of a pass. A reference to a
// reserved policy is refused always; a reference to any other policy the claim
// does not declare is refused when enforceRefs is set and reported otherwise.
func (v *ownershipView) admit(claim *vaultv1alpha1.VaultClaim, enforceRefs bool) *admissionRefusal {
	mount := normMount(claim.Spec.Auth.MountPath)
	guest := !claim.Spec.Auth.ManagesConfig()

	// Mount class: operator mounts take guests only; a guest takes nothing else.
	if !guest && v.isOperatorMount(mount) {
		return &admissionRefusal{vaultv1alpha1.ConditionAuthMountReady, ReasonMountConflict,
			fmt.Sprintf("auth mount %q is an operator mount; only a claim with spec.auth.manageConfig=false may use it", mount)}
	}
	if guest && !v.isOperatorMount(mount) && !slices.Contains(v.policy.GuestMounts, mount) {
		return &admissionRefusal{vaultv1alpha1.ConditionAuthMountReady, ReasonMountConflict,
			fmt.Sprintf("auth mount %q is neither an operator mount nor allow-listed for guest claims", mount)}
	}

	// Names the deployment reserves.
	declared := declaredPolicies(claim)
	for i := range claim.Spec.Policies {
		name := claim.Spec.Policies[i].Name
		if v.policy.protectedPolicy(name) {
			return &admissionRefusal{vaultv1alpha1.ConditionPoliciesApplied, ReasonOwnershipConflict,
				fmt.Sprintf("policy %q is reserved and cannot be written by a claim", name)}
		}
	}
	for i := range claim.Spec.Roles {
		role := claim.Spec.Roles[i]
		if v.reservedRole(mount, role.Name) {
			return &admissionRefusal{vaultv1alpha1.ConditionRolesApplied, ReasonOwnershipConflict,
				fmt.Sprintf("role %q on auth mount %q is reserved", role.Name, mount)}
		}
		for _, ref := range role.Policies {
			if _, own := declared[nameKey(ref)]; own {
				continue
			}
			if v.policy.reservedPolicy(ref) || (enforceRefs && !containsName(v.policy.ExternalPolicyNames, ref)) {
				return &admissionRefusal{vaultv1alpha1.ConditionRolesApplied, ReasonPolicyReferenceForbidden,
					fmt.Sprintf("role %q references policy %q, which the claim neither declares nor may reference", role.Name, ref)}
			}
		}
	}

	// Names another, elder claim holds.
	for _, other := range v.elders {
		who := other.Namespace + "/" + other.Name
		otherMount := normMount(other.Spec.Auth.MountPath)
		if !guest && other.Spec.Auth.ManagesConfig() && otherMount == mount {
			return &admissionRefusal{vaultv1alpha1.ConditionAuthMountReady, ReasonMountConflict,
				fmt.Sprintf("auth mount %q is owned by VaultClaim %s", mount, who)}
		}
		if prefixesOverlap(other.Spec.SecretsPrefix, claim.Spec.SecretsPrefix) {
			return &admissionRefusal{vaultv1alpha1.ConditionPoliciesApplied, ReasonOwnershipConflict,
				fmt.Sprintf("spec.secretsPrefix %q overlaps the prefix of VaultClaim %s", claim.Spec.SecretsPrefix, who)}
		}
		for _, name := range claimPolicyNames(other) {
			if _, ok := declared[nameKey(name)]; ok {
				return &admissionRefusal{vaultv1alpha1.ConditionPoliciesApplied, ReasonOwnershipConflict,
					fmt.Sprintf("policy %q belongs to VaultClaim %s", name, who)}
			}
		}
		if otherMount == mount {
			theirs := claimRoleNames(other)
			for i := range claim.Spec.Roles {
				if containsName(theirs, claim.Spec.Roles[i].Name) {
					return &admissionRefusal{vaultv1alpha1.ConditionRolesApplied, ReasonOwnershipConflict,
						fmt.Sprintf("role %q on auth mount %q belongs to VaultClaim %s", claim.Spec.Roles[i].Name, mount, who)}
				}
			}
		}
		theirKeys := claimTransitKeys(other)
		for _, key := range claimTransitKeys(claim) {
			if slices.Contains(theirKeys, key) {
				return &admissionRefusal{vaultv1alpha1.ConditionTransitKeysReady, ReasonOwnershipConflict,
					fmt.Sprintf("transit key %q belongs to VaultClaim %s", key, who)}
			}
		}
	}
	return nil
}

// referenceWarnings names the references admit lets through in audit mode.
func (v *ownershipView) referenceWarnings(claim *vaultv1alpha1.VaultClaim) []string {
	declared := declaredPolicies(claim)
	var out []string
	for i := range claim.Spec.Roles {
		for _, ref := range claim.Spec.Roles[i].Policies {
			if _, own := declared[nameKey(ref)]; own || containsName(v.policy.ExternalPolicyNames, ref) {
				continue
			}
			out = append(out, fmt.Sprintf("role %q references policy %q, which the claim neither declares nor may reference", claim.Spec.Roles[i].Name, ref))
		}
	}
	return out
}

// declaredPolicies is the set of the claim's policy names, keyed by nameKey.
func declaredPolicies(claim *vaultv1alpha1.VaultClaim) map[string]struct{} {
	out := make(map[string]struct{}, len(claim.Spec.Policies))
	for i := range claim.Spec.Policies {
		out[nameKey(claim.Spec.Policies[i].Name)] = struct{}{}
	}
	return out
}

// heldByOthers collects the names other claims hold, so that pruning and
// deletion never remove them even when this claim's ledger lists them. Names
// are keyed by nameKey.
type heldByOthers struct {
	policies map[string]struct{}
	roles    map[string]struct{} // mount + "/" + nameKey(role)
}

func collectHeld(others []*vaultv1alpha1.VaultClaim) heldByOthers {
	h := heldByOthers{policies: map[string]struct{}{}, roles: map[string]struct{}{}}
	for _, o := range others {
		for _, n := range claimPolicyNames(o) {
			h.policies[nameKey(n)] = struct{}{}
		}
		m := normMount(o.Spec.Auth.MountPath)
		for _, n := range claimRoleNames(o) {
			h.roles[m+"/"+nameKey(n)] = struct{}{}
		}
	}
	return h
}

// deletablePolicies filters ledger candidates: reserved, external and
// other-held names are dropped from the ledger without a Vault call.
func (r *VaultClaimReconciler) deletablePolicies(candidates []string, held heldByOthers) []string {
	out := make([]string, 0, len(candidates))
	for _, n := range candidates {
		if r.Ownership.protectedPolicy(n) {
			continue
		}
		if _, ok := held.policies[nameKey(n)]; ok {
			continue
		}
		out = append(out, n)
	}
	return out
}

func deletableRoles(view *ownershipView, mount string, candidates []string, held heldByOthers) []string {
	out := make([]string, 0, len(candidates))
	for _, n := range candidates {
		if view.reservedRole(mount, n) {
			continue
		}
		if _, ok := held.roles[normMount(mount)+"/"+nameKey(n)]; ok {
			continue
		}
		out = append(out, n)
	}
	return out
}

// mountDescription is the description the operator writes when it creates a
// claim's mount. It has not changed since the first release, so mounts made by
// any earlier version carry it too.
func mountDescription(claim *vaultv1alpha1.VaultClaim) string {
	return fmt.Sprintf("vault-operator: per-cluster auth for %s/%s", claim.Namespace, claim.Name)
}

// mountIsOurs: sys/auth shows a kubernetes mount with this claim's
// description, which only the operator's own POST sys/auth writes. Deletion
// disables a mount on this evidence alone.
func mountIsOurs(info vault.AuthMountInfo, claim *vaultv1alpha1.VaultClaim) bool {
	return info.Type == "kubernetes" && info.Description == mountDescription(claim)
}

// mountAccepted: the claim may configure the kubernetes mount sys/auth shows
// at its mountPath. Either the mount carries this claim's description, or
// recorded — status.vault.authMountPath as last persisted — names it. This
// release writes that record only after it accepted the mount, never before,
// so a claim that was refused or has not reached its mount step cannot hold
// it. A release before ownership checks wrote it for every claim and has
// configured that mount since; its claims keep their mount whatever its
// description, and the description is left as it is.
func mountAccepted(info vault.AuthMountInfo, claim *vaultv1alpha1.VaultClaim, recorded string) bool {
	if info.Type != "kubernetes" {
		return false
	}
	if info.Description == mountDescription(claim) {
		return true
	}
	mount := normMount(claim.Spec.Auth.MountPath)
	return mount != "" && normMount(recorded) == mount
}

func mountKey(mount string) string { return normMount(mount) + "/" }

// union returns the sorted set union.
func union(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// minus returns the names of a that name no Vault object b names (by
// nameKey), keeping a's order and spelling.
func minus(a, b []string) []string {
	drop := make(map[string]struct{}, len(b))
	for _, s := range b {
		drop[nameKey(s)] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := drop[nameKey(s)]; !ok {
			out = append(out, s)
		}
	}
	return out
}
