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

const (
	ConditionBucketProvisioned = "BucketProvisioned"
	ConditionBucketRunning     = "BucketRunning"
	ConditionKeysWritten       = "KeysWritten"
)

const S3BucketClaimFinalizer = "vault.in-cloud.io/s3bucketclaim-finalizer"

const OwnerBucketOperator = "vault-bucket"

const (
	S3ManagedBySystem   = "SYSTEM"
	S3ManagedByCustomer = "CUSTOMER"
)

// S3BucketSpec holds the cloud-manager create parameters. The bucket name is
// derived by convention and recorded in status.bucketName.
type S3BucketSpec struct {
	// +kubebuilder:default=false
	Public bool `json:"public,omitempty"`

	// ManagedBy selects the creation strategy; SYSTEM is not customer-billed.
	// +kubebuilder:validation:Enum=SYSTEM;CUSTOMER
	// +kubebuilder:default=SYSTEM
	ManagedBy string `json:"managedBy,omitempty"`

	// ConfigurationID is the cloud-manager S3 configuration catalog id; empty
	// falls back to the operator default.
	// +optional
	ConfigurationID string `json:"configurationId,omitempty"`
}

type S3VaultSpec struct {
	// SecretsPrefix must equal VaultClaim.secretsPrefix. Immutable.
	// +kubebuilder:validation:MinLength=1
	SecretsPrefix string `json:"secretsPrefix"`

	// DestinationPath is relative to secretsPrefix.
	// +kubebuilder:default=backup/s3
	DestinationPath string `json:"destinationPath,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.clusterRef.name == oldSelf.clusterRef.name",message="spec.clusterRef.name is immutable"
// +kubebuilder:validation:XValidation:rule="self.customerLogin == oldSelf.customerLogin",message="spec.customerLogin is immutable"
// +kubebuilder:validation:XValidation:rule="self.vault.secretsPrefix == oldSelf.vault.secretsPrefix",message="spec.vault.secretsPrefix is immutable"
type S3BucketClaimSpec struct {
	// +required
	VaultConfigRef VaultConfigRef `json:"vaultConfigRef"`

	// +required
	ClusterRef SecretClusterRef `json:"clusterRef"`

	// CustomerLogin is the account the bucket is created under. Immutable.
	// +kubebuilder:validation:MinLength=1
	CustomerLogin string `json:"customerLogin"`

	// +optional
	Region string `json:"region,omitempty"`

	// +required
	Bucket S3BucketSpec `json:"bucket"`

	// +required
	Vault S3VaultSpec `json:"vault"`

	// Purge removes the bucket and Vault keys on deletion; Retain leaves them.
	// +kubebuilder:validation:Enum=Retain;Purge
	// +kubebuilder:default=Purge
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
}

type S3BucketClaimStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Enum=Pending;Ready;Failed;Deleting
	// +optional
	Phase string `json:"phase,omitempty"`

	// BucketName is the source of truth for idempotency, fixed on first
	// create or adopt.
	// +optional
	BucketName string `json:"bucketName,omitempty"`

	// +optional
	BucketStatus string `json:"bucketStatus,omitempty"`

	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// KeysWrittenHash detects external key rotation.
	// +optional
	KeysWrittenHash string `json:"keysWrittenHash,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=s3bc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Bucket",type="string",JSONPath=".status.bucketName"
// +kubebuilder:printcolumn:name="Cluster",type="string",JSONPath=".spec.clusterRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// S3BucketClaim provisions a per-cluster S3 bucket and writes its credentials
// into Vault.
type S3BucketClaim struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec S3BucketClaimSpec `json:"spec"`

	// +optional
	Status S3BucketClaimStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

type S3BucketClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []S3BucketClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&S3BucketClaim{}, &S3BucketClaimList{})
}
