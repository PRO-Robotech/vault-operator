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

// Values of status.bucketOwnership.
const (
	// BucketOwnershipCreated: this claim created the bucket; Purge may remove it.
	BucketOwnershipCreated = "Created"
	// BucketOwnershipAdopted: the bucket existed before this claim; Purge removes
	// it only with spec.bucket.purgeAdopted.
	BucketOwnershipAdopted = "Adopted"
)

const (
	S3ManagedBySystem   = "SYSTEM"
	S3ManagedByCustomer = "CUSTOMER"
)

// S3BucketSpec holds the cloud-manager create parameters. The bucket name is
// derived by convention and recorded in status.bucketName.
type S3BucketSpec struct {
	// Name adopts an existing bucket by its full server name (with the
	// server prefix) instead of creating one. An adopted bucket is removed on
	// Purge only with purgeAdopted. Immutable.
	// +optional
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9-]*[a-z0-9]$`
	Name string `json:"name,omitempty"`

	// PurgeAdopted lets deletionPolicy=Purge remove a bucket this claim adopted
	// (status.bucketOwnership=Adopted). Without it such a deletion is blocked.
	// +optional
	PurgeAdopted bool `json:"purgeAdopted,omitempty"`

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
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('/') && !self.contains('..')",message="spec.vault.destinationPath must be relative and must not contain '..'"
	DestinationPath string `json:"destinationPath,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.clusterRef.name == oldSelf.clusterRef.name",message="spec.clusterRef.name is immutable"
// +kubebuilder:validation:XValidation:rule="self.customerLogin == oldSelf.customerLogin",message="spec.customerLogin is immutable"
// +kubebuilder:validation:XValidation:rule="self.vault.secretsPrefix == oldSelf.vault.secretsPrefix",message="spec.vault.secretsPrefix is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.bucket.name) == has(oldSelf.bucket.name) && (!has(self.bucket.name) || self.bucket.name == oldSelf.bucket.name)",message="spec.bucket.name is immutable"
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

	// BucketOwnership records how status.bucketName was obtained. Empty on
	// claims written before this field: it is then derived once from the
	// BucketProvisioned reason ("Created" → Created, anything else → Adopted).
	// +kubebuilder:validation:Enum=Created;Adopted
	// +optional
	BucketOwnership string `json:"bucketOwnership,omitempty"`

	// PendingCreate is set, and persisted, before a create call and cleared
	// once status.bucketName is recorded. A bucket found by name while it is set
	// is the one this claim created; without it, a found bucket is Adopted.
	// +optional
	PendingCreate *PendingBucketCreate `json:"pendingCreate,omitempty"`

	// WrittenPath is the destinationPath (relative to spec.vault.secretsPrefix)
	// the credentials were last written to; on a destinationPath change the
	// keys this claim left there are removed.
	// +optional
	WrittenPath string `json:"writtenPath,omitempty"`

	// KeysWrittenHash is deprecated: no longer written and cleared on the next
	// reconcile (credentials are compared with Vault directly). Kept in the
	// schema so an older operator can still read the object.
	// +optional
	KeysWrittenHash string `json:"keysWrittenHash,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// PendingBucketCreate marks an in-flight create.
type PendingBucketCreate struct {
	// RequestedName is the name sent to cloud-manager (before its prefix).
	RequestedName string `json:"requestedName"`
	// Since is when the create was decided; a create that cannot be located
	// is retried only after a grace period.
	Since metav1.Time `json:"since"`
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
