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

// Condition type constants unique to VaultSecretClaim; ConfigResolved,
// VaultReachable and Ready are shared with VaultClaim.
const (
	ConditionSourcesResolved = "SourcesResolved"
	ConditionItemsApplied    = "ItemsApplied"
)

const VaultSecretClaimFinalizer = "vault.in-cloud.io/vaultsecretclaim-finalizer"

// LabelVaultConfigOwner scopes which operator process reconciles a VaultConfig.
// A label-less VaultConfig belongs to vault-operator.
const LabelVaultConfigOwner = "vault.in-cloud.io/owner"

const (
	OwnerVaultOperator       = "vault-operator"
	OwnerVaultSecretOperator = "vault-secret"
)

const (
	SecretTypeGenerate = "generate"
	SecretTypeCopy     = "copy"
)

const (
	HashNone   = "none"
	HashBcrypt = "bcrypt"
)

const (
	DeletionPolicyRetain = "Retain"
	DeletionPolicyPurge  = "Purge"
)

const (
	ItemStateApplied = "Applied"
	ItemStatePending = "Pending"
	ItemStateFailed  = "Failed"
)

// SecretClusterRef references the cluster by name. No kubeconfig is needed —
// VaultSecretClaim only talks to Vault.
type SecretClusterRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// DestinationSpec is where a value is written, relative to secretsPrefix.
type DestinationSpec struct {
	// Mount overrides VaultConfig.storage.kvMountPath.
	// +optional
	Mount string `json:"mount,omitempty"`

	// Path is relative to secretsPrefix.
	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// HashedKey receives the hash when generate.hash != none; ignored otherwise.
	// +optional
	HashedKey string `json:"hashedKey,omitempty"`
}

// SourceSpec is where a copy value is read from (an absolute path in the engine).
type SourceSpec struct {
	// +optional
	Mount string `json:"mount,omitempty"`

	// +kubebuilder:validation:MinLength=1
	Path string `json:"path"`

	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// GenerateSpec are the generation criteria; a change to any field re-generates.
type GenerateSpec struct {
	// +kubebuilder:default=24
	// +kubebuilder:validation:Minimum=8
	Length int `json:"length,omitempty"`

	// Charset is an alphabet (not a regex); defaults to [A-Za-z0-9].
	// +optional
	Charset string `json:"charset,omitempty"`

	// +kubebuilder:validation:Enum=none;bcrypt
	// +kubebuilder:default=none
	Hash string `json:"hash,omitempty"`
}

// SecretListItem describes one secret to generate or copy.
//
// +kubebuilder:validation:XValidation:rule="self.type != 'generate' || (has(self.generate) && !has(self.source))",message="type=generate requires generate and forbids source"
// +kubebuilder:validation:XValidation:rule="self.type != 'copy' || (has(self.source) && !has(self.generate))",message="type=copy requires source and forbids generate"
type SecretListItem struct {
	// Unique identifier within this CR.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Enum=generate;copy
	Type string `json:"type"`

	// +required
	Destination DestinationSpec `json:"destination"`

	// +optional
	Generate *GenerateSpec `json:"generate,omitempty"`

	// +optional
	Source *SourceSpec `json:"source,omitempty"`
}

// VaultSecretClaimSpec is the desired state. One per cluster (1:1).
//
// +kubebuilder:validation:XValidation:rule="self.secretsPrefix == oldSelf.secretsPrefix",message="spec.secretsPrefix is immutable"
// +kubebuilder:validation:XValidation:rule="self.clusterRef.name == oldSelf.clusterRef.name",message="spec.clusterRef.name is immutable"
type VaultSecretClaimSpec struct {
	// VaultConfigRef points at the cluster-scoped VaultConfig with the write
	// role (a separate instance from vault-operator's). Mutable.
	// +required
	VaultConfigRef VaultConfigRef `json:"vaultConfigRef"`

	// +required
	ClusterRef SecretClusterRef `json:"clusterRef"`

	// SecretsPrefix is the base prefix of per-cluster paths; must equal
	// VaultClaim.secretsPrefix. Convention "clusters/{metadata.name}". Immutable.
	// +kubebuilder:validation:MinLength=1
	SecretsPrefix string `json:"secretsPrefix"`

	// +kubebuilder:validation:Enum=Retain;Purge
	// +kubebuilder:default=Retain
	DeletionPolicy string `json:"deletionPolicy,omitempty"`

	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	SecretList []SecretListItem `json:"secretList"`
}

// SecretItemStatus is the per-item applied state with a change-detection hash.
type SecretItemStatus struct {
	Name string `json:"name"`

	// +kubebuilder:validation:Enum=Applied;Pending;Failed
	// +optional
	State string `json:"state,omitempty"`

	// SourceHash is the input hash (copy: source path+key+value; generate:
	// the length/charset/hash criteria).
	// +optional
	SourceHash string `json:"sourceHash,omitempty"`

	// +optional
	LastAppliedAt *metav1.Time `json:"lastAppliedAt,omitempty"`

	// +optional
	Message string `json:"message,omitempty"`
}

// VaultSecretClaimStatus is the observed state.
type VaultSecretClaimStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Enum=Pending;Ready;Failed;Deleting
	// +optional
	Phase string `json:"phase,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +listType=map
	// +listMapKey=name
	// +optional
	Items []SecretItemStatus `json:"items,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vsc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VaultSecretClaim fills Vault with secret values for one cluster (1:1).
type VaultSecretClaim struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec VaultSecretClaimSpec `json:"spec"`

	// +optional
	Status VaultSecretClaimStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VaultSecretClaimList contains a list of VaultSecretClaim.
type VaultSecretClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VaultSecretClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultSecretClaim{}, &VaultSecretClaimList{})
}
