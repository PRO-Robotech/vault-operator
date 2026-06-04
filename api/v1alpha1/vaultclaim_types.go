/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Phase constants for VaultClaim lifecycle (OPERATOR-SPEC §9.1).
const (
	PhasePending     = "Pending"
	PhaseConfiguring = "Configuring"
	PhaseReady       = "Ready"
	PhaseFailed      = "Failed"
	PhaseDeleting    = "Deleting"
)

// Condition type constants for VaultClaim (OPERATOR-SPEC §9.2).
const (
	ConditionReady                 = "Ready"
	ConditionConfigResolved        = "ConfigResolved"
	ConditionVaultReachable        = "VaultReachable"
	ConditionKubeconfigAvailable   = "KubeconfigAvailable"
	ConditionAuthMountReady        = "AuthMountReady"
	ConditionPoliciesApplied       = "PoliciesApplied"
	ConditionRolesApplied          = "RolesApplied"
	ConditionTokenReviewerJWTFresh = "TokenReviewerJWTFresh"
)

const VaultClaimFinalizer = "vault.in-cloud.io/finalizer"

const (
	LabelClaimName      = "vault.in-cloud.io/claim-name"
	LabelClaimNamespace = "vault.in-cloud.io/claim-namespace"
)

// VaultConfigRef references a cluster-scoped VaultConfig.
type VaultConfigRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ClusterRef references the ClusterClaim and its kubeconfig Secret. Both
// fields are immutable — changing them would re-target this VaultClaim to a
// different cluster.
type ClusterRef struct {
	// Name of the ClusterClaim in the same namespace as this VaultClaim.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// KubeconfigSecret is the Secret name; defaults to "{Name}-infra-kubeconfig".
	// +optional
	KubeconfigSecret string `json:"kubeconfigSecret,omitempty"`
}

// AuthSpec configures the per-cluster Vault Kubernetes Auth Method.
type AuthSpec struct {
	// MountPath of the per-cluster auth method (convention:
	// "kubernetes-{metadata.name}"). Immutable.
	// +kubebuilder:validation:MinLength=1
	MountPath string `json:"mountPath"`

	// AutoCreate enables the operator to POST sys/auth; when false only
	// auth/{path}/config is written, assuming the mount already exists.
	// +kubebuilder:default=true
	AutoCreate bool `json:"autoCreate,omitempty"`

	// Issuer is the OIDC issuer URL of the infra cluster; empty triggers
	// auto-discovery via /.well-known/openid-configuration.
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// TokenReviewer identifies the SA whose JWT Vault uses for TokenReview.
	// +required
	TokenReviewer TokenReviewerSpec `json:"tokenReviewer"`
}

// TokenReviewerSpec describes the reviewer SA and its JWT TTL.
type TokenReviewerSpec struct {
	// +required
	ServiceAccount ServiceAccountRef `json:"serviceAccount"`

	// TTL of the JWT minted via TokenRequest. The operator rotates when less
	// than 30% TTL remains.
	// +kubebuilder:default="24h"
	TTL metav1.Duration `json:"ttl,omitempty"`
}

// ServiceAccountRef references a SA in the infra cluster and controls
// whether the operator creates it.
type ServiceAccountRef struct {
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// AutoCreate enables SSA of the SA and ClusterRoleBinding
	// (system:auth-delegator) in the infra cluster.
	// +kubebuilder:default=true
	AutoCreate bool `json:"autoCreate,omitempty"`
}

// BoundServiceAccounts identifies the single ServiceAccount allowed to log
// in through this role.
//
// This CRD intentionally binds ONE SA per role — unlike Vault's native
// bound_service_account_names / bound_service_account_namespaces which take
// arrays and produce a Cartesian product. Reasons:
//
//   - Audit clarity: a Vault login event names a role that maps 1:1 to a
//     specific SA. Multi-SA roles obscure who logged in.
//   - Per-SA tuning: TTLs, policies, and bound CIDRs can differ per role —
//     impossible to express on a shared multi-SA role.
//   - Identity mapping: Vault entity ↔ SA stays unambiguous.
//
// To share a policy across SAs, declare N roles with the same `policies` —
// policy objects are independent, only roles are scoped.
type BoundServiceAccounts struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// RoleSpec binds {SA, namespace} to a list of policies inside the
// per-cluster auth mount.
type RoleSpec struct {
	// Uniqueness scoped to auth/{mountPath}/role/.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +required
	BoundServiceAccounts BoundServiceAccounts `json:"boundServiceAccounts"`

	// +kubebuilder:validation:MinItems=1
	Policies []string `json:"policies"`

	// +optional
	TokenTTL *metav1.Duration `json:"tokenTTL,omitempty"`

	// +optional
	TokenMaxTTL *metav1.Duration `json:"tokenMaxTTL,omitempty"`
}

// PolicySpec defines an ACL policy written as HCL into Vault. Names should
// be prefixed with "{metadata.name}-" because Vault OSS policies live in a
// global namespace (OPERATOR-SPEC §2.4).
type PolicySpec struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Rules is HCL ACL content; may use {{ .AuthMountAccessor }} for identity
	// templating (OPERATOR-SPEC §10).
	// +kubebuilder:validation:MinLength=1
	Rules string `json:"rules"`
}

// VaultClaimSpec is the desired state of a VaultClaim. One VaultClaim per
// infra cluster (1:1 with ClusterClaim).
//
// +kubebuilder:validation:XValidation:rule="self.secretsPrefix == oldSelf.secretsPrefix",message="spec.secretsPrefix is immutable"
// +kubebuilder:validation:XValidation:rule="self.clusterRef.name == oldSelf.clusterRef.name",message="spec.clusterRef.name is immutable"
// +kubebuilder:validation:XValidation:rule="self.auth.mountPath == oldSelf.auth.mountPath",message="spec.auth.mountPath is immutable"
type VaultClaimSpec struct {
	// VaultConfigRef is mutable — changing it migrates this claim to a
	// different Vault.
	// +required
	VaultConfigRef VaultConfigRef `json:"vaultConfigRef"`

	// +required
	ClusterRef ClusterRef `json:"clusterRef"`

	// SecretsPrefix is the path prefix under the shared KV-v2 mount used in
	// policies. Convention: "clusters/{metadata.name}". Immutable.
	// +kubebuilder:validation:MinLength=1
	SecretsPrefix string `json:"secretsPrefix"`

	// +required
	Auth AuthSpec `json:"auth"`

	// +listType=map
	// +listMapKey=name
	// +optional
	Roles []RoleSpec `json:"roles,omitempty"`

	// +listType=map
	// +listMapKey=name
	// +optional
	Policies []PolicySpec `json:"policies,omitempty"`
}

// TokenReviewerJWTStatus tracks the reviewer JWT lifecycle.
type TokenReviewerJWTStatus struct {
	// +optional
	IssuedAt *metav1.Time `json:"issuedAt,omitempty"`
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
	// +optional
	LastRotated *metav1.Time `json:"lastRotated,omitempty"`
	// LastRotationAttempt records the last attempt, successful or not.
	// +optional
	LastRotationAttempt *metav1.Time `json:"lastRotationAttempt,omitempty"`
}

// VaultStatusSummary is a compact view of the actual Vault state.
type VaultStatusSummary struct {
	// +optional
	ConfigName string `json:"configName,omitempty"`

	// +optional
	AuthMountPath string `json:"authMountPath,omitempty"`

	// +optional
	SecretsPrefix string `json:"secretsPrefix,omitempty"`

	// AuthMountAccessor is cached from Vault, populated lazily on first
	// render of a policy that uses {{ .AuthMountAccessor }}.
	// +optional
	AuthMountAccessor string `json:"authMountAccessor,omitempty"`

	// +optional
	AppliedRoles []string `json:"appliedRoles,omitempty"`

	// +optional
	AppliedPolicies []string `json:"appliedPolicies,omitempty"`

	// +optional
	TokenReviewerJWT *TokenReviewerJWTStatus `json:"tokenReviewerJWT,omitempty"`

	// +optional
	LastReconcileAt *metav1.Time `json:"lastReconcileAt,omitempty"`

	// LastDriftCheckAt is the timestamp of the most recent drift detection
	// pass, whether drift was found or not.
	// +optional
	LastDriftCheckAt *metav1.Time `json:"lastDriftCheckAt,omitempty"`
}

// VaultClaimStatus is the observed state of VaultClaim.
type VaultClaimStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Enum=Pending;Configuring;Ready;Failed;Deleting
	// +optional
	Phase string `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	Vault *VaultStatusSummary `json:"vault,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Config",type="string",JSONPath=".spec.vaultConfigRef.name"
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VaultClaim is the per-cluster Vault configuration request, one per infra
// cluster (1:1 with ClusterClaim).
type VaultClaim struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec VaultClaimSpec `json:"spec"`

	// +optional
	Status VaultClaimStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VaultClaimList contains a list of VaultClaim.
type VaultClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VaultClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultClaim{}, &VaultClaimList{})
}
