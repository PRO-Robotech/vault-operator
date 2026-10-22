/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// verbList is how calls() writes a GET ?list=true.
const verbList = "LIST"

// httpVault is a Vault HTTP API with a fixed content, for tests that need the
// real vault.Client: what it asks for and how often is the property under test.
type httpVault struct {
	*httptest.Server

	logins atomic.Int32

	mu       sync.Mutex
	requests []string
	// authMounts is sys/auth keyed by "<mount>/".
	authMounts map[string]map[string]any
	// authReadDenied makes GET sys/auth/<mount> answer 403.
	authReadDenied bool
	policies       map[string]string
	roles          map[string]map[string]any
}

func newHTTPVault() *httpVault {
	return &httpVault{
		authMounts: map[string]map[string]any{},
		policies:   map[string]string{},
		roles:      map[string]map[string]any{},
	}
}

// start serves plain HTTP.
func (v *httpVault) start() *httpVault {
	v.Server = httptest.NewServer(http.HandlerFunc(v.serve))
	return v
}

// startTLS serves HTTPS with whatever certificate cert holds at handshake time.
func (v *httpVault) startTLS(cert *atomic.Pointer[tls.Certificate]) *httpVault {
	v.Server = httptest.NewUnstartedServer(http.HandlerFunc(v.serve))
	v.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cert.Load(), nil
	}}
	v.Listener = tls.NewListener(v.Listener, v.TLS)
	v.Start()
	v.URL = strings.Replace(v.URL, "http://", "https://", 1)
	return v
}

// calls returns "METHOD path" for every request but logins, in arrival order;
// a LIST (GET ?list=true) is written "LIST path".
func (v *httpVault) calls() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.requests)
}

func (v *httpVault) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.requests = nil
}

func (v *httpVault) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/login") {
		n := v.logins.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
			"client_token": fmt.Sprintf("tok-%d", n), "lease_duration": 3600, "renewable": true,
		}})
		return
	}
	verb := r.Method
	if r.URL.Query().Get("list") == "true" {
		verb = verbList
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.requests = append(v.requests, verb+" "+path)

	switch {
	case path == "sys/seal-status":
		writeJSON(w, map[string]any{"sealed": false, "initialized": true, "version": "1.20.1", "t": 1, "n": 1})
	case path == "auth/token/lookup-self":
		writeJSON(w, map[string]any{"data": map[string]any{"ttl": 3600}})
	case path == "auth/token/renew-self":
		writeJSON(w, map[string]any{"auth": map[string]any{"lease_duration": 3600, "renewable": true}})
	case path == "auth/token/revoke-self":
		w.WriteHeader(http.StatusNoContent)
	case path == "sys/mounts":
		writeJSON(w, map[string]any{"data": map[string]any{"secret/": map[string]any{"type": "kv"}}})
	case path == "sys/auth":
		data := map[string]any{}
		for k, m := range v.authMounts {
			data[k] = m
		}
		writeJSON(w, map[string]any{"data": data})
	case strings.HasPrefix(path, "sys/auth/"):
		if v.authReadDenied {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		m, ok := v.authMounts[strings.TrimPrefix(path, "sys/auth/")+"/"]
		if !ok {
			http.Error(w, `{"errors":["No auth engine at `+strings.TrimPrefix(path, "sys/auth/")+`/"]}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"data": m})
	case strings.HasPrefix(path, "auth/") && strings.HasSuffix(path, "/config"):
		writeJSON(w, map[string]any{"data": map[string]any{"kubernetes_host": "https://target", "token_reviewer_jwt_set": true}})
	case verb == verbList && path == "sys/policies/acl":
		writeJSON(w, map[string]any{"data": map[string]any{"keys": sortedKeys(v.policies)}})
	case strings.HasPrefix(path, "sys/policies/acl/"):
		body, ok := v.policies[strings.TrimPrefix(path, "sys/policies/acl/")]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"policy": body}})
	case verb == verbList && strings.HasSuffix(path, "/role"):
		writeJSON(w, map[string]any{"data": map[string]any{"keys": sortedKeys(v.roles)}})
	case strings.HasPrefix(path, "auth/") && strings.Contains(path, "/role/"):
		role, ok := v.roles[path[strings.LastIndex(path, "/")+1:]]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"data": role})
	default:
		http.Error(w, `{"errors":["unsupported by the test Vault"]}`, http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// testCA is a self-signed CA that signs a leaf for 127.0.0.1.
type testCA struct {
	pem  []byte
	leaf *tls.Certificate
}

func newTestCA(cn string) (*testCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vault"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &testCA{
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf: &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}, nil
}
