/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package target performs operations the vault-operator needs in an infra
// ("target") cluster: server-side-apply of the token-reviewer SA + CRB and
// minting reviewer JWTs through the TokenRequest API. Access is via the
// kubeconfig Secret published by certificate-set / cluster-claim-operator
// (data key "value"); the Manager caches one ClientSet per Secret keyed by
// namespace/name and invalidates on kubeconfig change (sha256 hash) or TTL.
package target

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldManager is the SSA field-owner string for every Apply this operator
// issues in target clusters.
const FieldManager = "vault-operator"

// KubeconfigKey is the data key inside the kubeconfig Secret produced by
// certificate-set.
const KubeconfigKey = "value"

const (
	defaultTTL      = 5 * time.Minute
	cleanupInterval = 1 * time.Minute

	requestTimeout = 10 * time.Second
)

// ClientSet bundles the two kube clients used in a target cluster: a
// controller-runtime client.Client for SSA on Namespace / SA / CRB and a
// kubernetes.Interface for the TokenRequest subresource. Host and CABundle
// are extracted from the parsed kubeconfig so callers don't re-parse it.
// CABundle is empty when the kubeconfig uses insecure-skip-tls-verify (tests).
type ClientSet struct {
	Client     client.Client
	Kubernetes kubernetes.Interface
	Host       string
	CABundle   []byte
}

// Manager is the seam tests rely on: production uses *ClusterManager (TTL
// cache + kubeconfig hash); tests substitute a fake.
type Manager interface {
	Get(ctx context.Context, secret *corev1.Secret) (*ClientSet, error)
}

type cachedClientSet struct {
	set      *ClientSet
	hash     string
	lastUsed time.Time
}

// ClusterManager parses the kubeconfig from the Secret, builds *ClientSet,
// caches it for defaultTTL (refreshed on access), and evicts entries via a
// background goroutine started by Start.
type ClusterManager struct {
	mu      sync.RWMutex
	clients map[string]*cachedClientSet
	scheme  *runtime.Scheme
	ttl     time.Duration
}

// NewClusterManager: scheme should include the core APIs (corev1, rbacv1)
// the operator manipulates in target clusters.
func NewClusterManager(scheme *runtime.Scheme) *ClusterManager {
	return &ClusterManager{
		clients: make(map[string]*cachedClientSet),
		scheme:  scheme,
		ttl:     defaultTTL,
	}
}

func (cm *ClusterManager) Get(_ context.Context, secret *corev1.Secret) (*ClientSet, error) {
	kubeconfigData := secret.Data[KubeconfigKey]
	if len(kubeconfigData) == 0 {
		return nil, fmt.Errorf("kubeconfig %q entry missing in secret %s/%s", KubeconfigKey, secret.Namespace, secret.Name)
	}

	key := secret.Namespace + "/" + secret.Name
	hash := computeHash(kubeconfigData)

	cm.mu.RLock()
	if cached, ok := cm.clients[key]; ok && cached.hash == hash {
		cached.lastUsed = time.Now()
		cm.mu.RUnlock()
		return cached.set, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cached, ok := cm.clients[key]; ok && cached.hash == hash {
		cached.lastUsed = time.Now()
		return cached.set, nil
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigData)
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig from %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	restConfig.Timeout = requestTimeout

	ctrlClient, err := client.New(restConfig, client.Options{Scheme: cm.scheme})
	if err != nil {
		return nil, fmt.Errorf("build controller-runtime client: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}

	set := &ClientSet{
		Client:     ctrlClient,
		Kubernetes: kubeClient,
		Host:       restConfig.Host,
		CABundle:   restConfig.CAData,
	}
	cm.clients[key] = &cachedClientSet{
		set:      set,
		hash:     hash,
		lastUsed: time.Now(),
	}
	return set, nil
}

// Start runs the eviction loop until ctx is cancelled (manager.Runnable).
func (cm *ClusterManager) Start(ctx context.Context) error {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cm.flush()
			return nil
		case <-ticker.C:
			cm.removeExpired()
		}
	}
}

func (cm *ClusterManager) removeExpired() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	now := time.Now()
	for key, cached := range cm.clients {
		if now.Sub(cached.lastUsed) > cm.ttl {
			delete(cm.clients, key)
		}
	}
}

func (cm *ClusterManager) flush() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.clients = make(map[string]*cachedClientSet)
}

func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:8])
}
