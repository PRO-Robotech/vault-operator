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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OIDCDiscoveryPath is the kube-apiserver OIDC well-known endpoint
// (anonymous access via the system:public-info-viewer ClusterRole).
const OIDCDiscoveryPath = "/.well-known/openid-configuration"

const oidcDiscoveryHTTPTimeout = 5 * time.Second

type oidcDiscoveryResponse struct {
	Issuer string `json:"issuer"`
}

// DiscoverIssuer fetches OIDC config from the kube-apiserver and returns the
// `issuer` claim. Uses net/http directly rather than Kubernetes.Discovery()
// because the well-known endpoint is unauthenticated and Discovery's
// RESTClient is not exposed by the fake clientset (panics on nil RESTClient).
// When CABundle is empty (kubeconfig with insecure-skip-tls-verify), TLS
// verification is disabled to mirror the kubeconfig's intent.
func DiscoverIssuer(ctx context.Context, cs *ClientSet) (string, error) {
	if cs == nil || cs.Host == "" {
		return "", fmt.Errorf("target ClientSet has no Host configured")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(cs.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cs.CABundle) {
			return "", fmt.Errorf("CABundle is not valid PEM")
		}
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // matches kubeconfig intent
	}

	httpClient := &http.Client{
		Timeout:   oidcDiscoveryHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
	}

	url := strings.TrimRight(cs.Host, "/") + OIDCDiscoveryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("GET %s: %d %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var parsed oidcDiscoveryResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode %s: %w", OIDCDiscoveryPath, err)
	}
	if parsed.Issuer == "" {
		return "", fmt.Errorf("%s returned no issuer field", OIDCDiscoveryPath)
	}
	return parsed.Issuer, nil
}
