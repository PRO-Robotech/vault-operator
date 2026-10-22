/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Workers of every claim on one cluster share its cached client; reading the
// cache must not race with marking it used.
func TestClusterManager_ConcurrentGetIsRaceFree(t *testing.T) {
	cm := NewClusterManager(newTargetTestScheme(t))
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc", Namespace: "ns"},
		Data:       map[string][]byte{KubeconfigKey: []byte(sampleKubeconfig)},
	}
	if _, err := cm.Get(context.Background(), secret); err != nil {
		t.Fatalf("Get: %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := cm.Get(context.Background(), secret); err != nil {
					t.Errorf("Get: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// A cached target client outlives the reconcile interval of a Ready claim
// (10 min): a shorter TTL rebuilds clients and transports on every pass.
func TestClusterManager_TTLOutlivesTheDriftInterval(t *testing.T) {
	cm := NewClusterManager(newTargetTestScheme(t))
	if cm.ttl < 30*time.Minute {
		t.Fatalf("client TTL = %s, want at least 30m", cm.ttl)
	}
}

// isDiscovery reports the API discovery paths: /api, /apis, /api/<v> and
// /apis/<group>/<version>. Object paths are longer.
func isDiscovery(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(segs) == 1 && (segs[0] == "api" || segs[0] == "apis"):
		return true
	case len(segs) == 2 && segs[0] == "api":
		return true
	case len(segs) <= 3 && segs[0] == "apis":
		return true
	}
	return false
}

var rbacV1 = metav1.GroupVersionForDiscovery{GroupVersion: "rbac.authorization.k8s.io/v1", Version: "v1"}

// discoveryDocs are the legacy discovery answers for the three kinds the
// operator writes.
var discoveryDocs = map[string]any{
	"/api": &metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"},
		ServerAddressByClientCIDRs: []metav1.ServerAddressByClientCIDR{{ClientCIDR: "0.0.0.0/0", ServerAddress: "target"}}},
	"/apis": &metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"},
		Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io", Versions: []metav1.GroupVersionForDiscovery{rbacV1}, PreferredVersion: rbacV1}}},
	"/api/v1": &metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList"}, GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get"}},
			{Name: "serviceaccounts", Namespaced: true, Kind: "ServiceAccount", Verbs: metav1.Verbs{"get"}},
		}},
	"/apis/rbac.authorization.k8s.io/v1": &metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
		GroupVersion: "rbac.authorization.k8s.io/v1",
		APIResources: []metav1.APIResource{{Name: "clusterrolebindings", Kind: "ClusterRoleBinding", Verbs: metav1.Verbs{"get"}}}},
}

// The kinds the operator writes in a target cluster are known in advance;
// reaching them must not cost discovery round-trips to every cluster.
func TestClusterManager_TargetClientNeedsNoDiscovery(t *testing.T) {
	var mu sync.Mutex
	var discovery []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isDiscovery(r.URL.Path) {
			mu.Lock()
			discovery = append(discovery, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/ns/serviceaccounts/sa" {
			_ = json.NewEncoder(w).Encode(&corev1.ServiceAccount{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
				ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"},
			})
			return
		}
		if doc, ok := discoveryDocs[r.URL.Path]; ok {
			// Answered as an apiserver would: the property is that nothing asks.
			_ = json.NewEncoder(w).Encode(doc)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(&metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound,
		})
	}))
	t.Cleanup(srv.Close)

	kubeconfig := strings.Replace(sampleKubeconfig, "https://example.invalid:6443", srv.URL, 1)
	cm := NewClusterManager(newTargetTestScheme(t))
	cs, err := cm.Get(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc", Namespace: "ns"},
		Data:       map[string][]byte{KubeconfigKey: []byte(kubeconfig)},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ctx := context.Background()
	if err := cs.Client.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "sa"}, &corev1.ServiceAccount{}); err != nil {
		t.Fatalf("get ServiceAccount: %v", err)
	}
	if err := cs.Client.Get(ctx, client.ObjectKey{Name: "ns"}, &corev1.Namespace{}); !apierrors.IsNotFound(err) {
		t.Fatalf("get Namespace = %v, want NotFound", err)
	}
	if err := cs.Client.Get(ctx, client.ObjectKey{Name: "crb"}, &rbacv1.ClusterRoleBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("get ClusterRoleBinding = %v, want NotFound", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(discovery) != 0 {
		t.Fatalf("discovery requests = %v, want none", discovery)
	}
}
