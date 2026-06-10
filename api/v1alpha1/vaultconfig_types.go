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

// Condition type constants for VaultConfig (OPERATOR-SPEC §2.5, §3.8).
const (
	ConditionVaultInitialized = "VaultInitialized"
	ConditionVaultUnsealed    = "VaultUnsealed"
	ConditionReachable        = "Reachable"
	ConditionManagerLoggedIn  = "ManagerLoggedIn"
	ConditionSharedMountFound = "SharedMountFound"
)

// VaultConfigFinalizer blocks deletion while at least one VaultClaim
// references this VaultConfig.
const VaultConfigFinalizer = "vault.in-cloud.io/vaultconfig-finalizer"

// AuthMethodKubernetes is the only supported manager auth method in v1alpha1.
const AuthMethodKubernetes = "kubernetes"

// SecretKeySelector references a Secret and a specific key within it.
type SecretKeySelector struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +kubebuilder:default=ca.crt
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`
}

// ConfigMapKeySelector references a ConfigMap and a specific key within it.
type ConfigMapKeySelector struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +kubebuilder:default=ca.crt
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`
}

// ManagerAuthSpec describes how the operator authenticates to Vault. This
// is the "outer" auth (auth/{managerAuth.mountPath}/login), distinct from
// the per-cluster auth mounts the operator creates for consumer pods.
type ManagerAuthSpec struct {
	// +kubebuilder:validation:Enum=kubernetes
	// +kubebuilder:default=kubernetes
	Method string `json:"method,omitempty"`

	// MountPath of the auth method in Vault. Mutable, but the new mount
	// must already exist in Vault (validated at reconcile).
	// +kubebuilder:default=kubernetes-mgmt
	// +kubebuilder:validation:MinLength=1
	MountPath string `json:"mountPath,omitempty"`

	// +kubebuilder:default=vault-operator
	// +kubebuilder:validation:MinLength=1
	Role string `json:"role,omitempty"`
}

// StorageSpec describes the shared KV-v2 mount that holds all clusters'
// secrets. The mount itself is deployed by the platform; the operator only
// writes policies referencing paths under it (OPERATOR-SPEC D2).
type StorageSpec struct {
	// KvMountPath is immutable — changing it invalidates every previously
	// written policy.
	// +kubebuilder:default=secret
	// +kubebuilder:validation:MinLength=1
	KvMountPath string `json:"kvMountPath,omitempty"`
}

// CEL below uses size(self.caBundleFile) > 0, not an empty-string literal:
// gofmt rewrites a single-quote pair in doc comments into a curly quote.

// TLSSpec describes TLS settings for connecting to Vault. At most one of
// caBundleSecretRef, caBundleConfigMapRef, or caBundleFile may be set; an empty
// spec uses the system CA pool.
// +kubebuilder:validation:XValidation:rule="[has(self.caBundleSecretRef), has(self.caBundleConfigMapRef), (has(self.caBundleFile) && size(self.caBundleFile) > 0)].filter(x, x).size() <= 1",message="at most one of caBundleSecretRef, caBundleConfigMapRef or caBundleFile may be set"
type TLSSpec struct {
	// CABundleSecretRef references a Secret containing the CA bundle used to
	// verify the Vault server certificate.
	// +optional
	CABundleSecretRef *SecretKeySelector `json:"caBundleSecretRef,omitempty"`

	// CABundleConfigMapRef references a ConfigMap containing the CA bundle.
	// +optional
	CABundleConfigMapRef *ConfigMapKeySelector `json:"caBundleConfigMapRef,omitempty"`

	// CABundleFile is a filesystem path inside the operator pod where the CA
	// bundle is mounted (e.g. via a volume from a cluster-wide CA Secret).
	// +optional
	CABundleFile string `json:"caBundleFile,omitempty"`

	// ServerName overrides the hostname used in TLS SNI/verification.
	// +optional
	ServerName string `json:"serverName,omitempty"`

	// InsecureSkipVerify disables certificate verification. Dev only.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// VaultConfigSpec is the cluster-scoped Vault connection. One VaultConfig
// (typically "default") is referenced by many VaultClaims; multi-Vault is
// supported via multiple named VaultConfigs (OPERATOR-SPEC §1.1, D13).
//
// +kubebuilder:validation:XValidation:rule="self.storage.kvMountPath == oldSelf.storage.kvMountPath",message="spec.storage.kvMountPath is immutable"
type VaultConfigSpec struct {
	// Address is the Vault URL. https:// in production; http:// is permitted
	// for dev-mode Vault (e2e tests). Mutable — cascade reconciles all claims.
	// +kubebuilder:validation:Pattern=`^https?://`
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`

	// +kubebuilder:default={method: "kubernetes", mountPath: "kubernetes-mgmt", role: "vault-operator"}
	ManagerAuth ManagerAuthSpec `json:"managerAuth,omitempty"`

	// +kubebuilder:default={kvMountPath: "secret"}
	Storage StorageSpec `json:"storage,omitempty"`

	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// SealStatus mirrors GET /v1/sys/seal-status (OPERATOR-SPEC §3.8).
type SealStatus struct {
	// +optional
	Sealed bool `json:"sealed,omitempty"`
	// +optional
	Initialized bool `json:"initialized,omitempty"`
	// T is the threshold of Shamir shares needed for unseal.
	// +optional
	T int32 `json:"t,omitempty"`
	// N is the total number of Shamir shares.
	// +optional
	N int32 `json:"n,omitempty"`
	// Progress is the number of unseal shares submitted so far.
	// +optional
	Progress int32 `json:"progress,omitempty"`
}

// VaultConfigStatus reflects the observed health of Vault.
type VaultConfigStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	SealStatus *SealStatus `json:"sealStatus,omitempty"`

	// +optional
	VaultVersion string `json:"vaultVersion,omitempty"`

	// +optional
	LastHealthCheckAt *metav1.Time `json:"lastHealthCheckAt,omitempty"`

	// ReferencedBy is the count of VaultClaims referencing this VaultConfig;
	// drives the deletion finalizer.
	// +optional
	ReferencedBy int32 `json:"referencedBy,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=vcfg
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Address",type="string",JSONPath=".spec.address"
// +kubebuilder:printcolumn:name="Unsealed",type="string",JSONPath=".status.conditions[?(@.type=='VaultUnsealed')].status"
// +kubebuilder:printcolumn:name="Reachable",type="string",JSONPath=".status.conditions[?(@.type=='Reachable')].status"
// +kubebuilder:printcolumn:name="Refs",type="integer",JSONPath=".status.referencedBy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VaultConfig is the cluster-scoped Vault connection referenced by VaultClaims.
type VaultConfig struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec VaultConfigSpec `json:"spec"`

	// +optional
	Status VaultConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VaultConfigList contains a list of VaultConfig.
type VaultConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VaultConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultConfig{}, &VaultConfigList{})
}
