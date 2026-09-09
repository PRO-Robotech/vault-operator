/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	ResultSuccess      = "success"
	ResultClientError  = "client_error"
	ResultServerError  = "server_error"
	ResultTransportErr = "transport_error"
	ResultLoginSuccess = "login_success"
	ResultLoginFailed  = "login_failed"
	ResultRenewSuccess = "renew_success"
	ResultRenewFailed  = "renew_failed"
)

// PathOther is the catch-all bucket so dashboards detect surprise endpoints
// without losing cardinality control.
const PathOther = "other"

// Transit path buckets.
const (
	PathTransitKey       = "transit_key"
	PathTransitKeyConfig = "transit_key_config"
)

var APIResponsesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_api_responses_total",
		Help: "Total HTTP responses from Vault, labelled by verb, normalised path bucket, and status code.",
	},
	[]string{"verb", "path", "code"},
)

var APICallsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_api_calls_total",
		Help: "Total Vault API calls attempted from the operator, labelled by verb, path bucket, and outcome.",
	},
	[]string{"verb", "path", "result"},
)

var ClientTokenRenewalTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_client_token_renewal_total",
		Help: "Operator's Vault client_token lifecycle events (login/renew, success/failure).",
	},
	[]string{"result"},
)

func init() {
	ctrlmetrics.Registry.MustRegister(APIResponsesTotal, APICallsTotal, ClientTokenRenewalTotal)
}

// normalizePath collapses a Vault HTTP path to a bounded label set: variable
// mount/role names would otherwise explode cardinality (one series per cluster
// × role).
func normalizePath(p string) string {
	p = strings.Trim(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) > 0 && parts[0] == "v1" {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return PathOther
	}

	switch parts[0] {
	case "sys":
		return normalizeSysPath(parts)
	case "auth":
		return normalizeAuthPath(parts)
	}

	// The mount path is configurable, so match {mount}/keys/{name}[/config] by shape.
	if len(parts) >= 3 && parts[1] == "keys" {
		if len(parts) >= 4 && parts[3] == "config" {
			return PathTransitKeyConfig
		}
		return PathTransitKey
	}
	return PathOther
}

func normalizeSysPath(parts []string) string {
	if len(parts) < 2 {
		return PathOther
	}
	switch parts[1] {
	case "seal-status":
		return "sys_seal_status"
	case "mounts":
		return "sys_mounts"
	case "auth":
		switch len(parts) {
		case 2:
			return "sys_auth_list"
		case 3:
			return "sys_auth"
		case 4:
			if parts[3] == "tune" {
				return "sys_auth_tune"
			}
		}
	case "policies":
		if len(parts) >= 3 && parts[2] == "acl" {
			if len(parts) == 3 {
				return "sys_policies_acl_list"
			}
			return "sys_policies_acl"
		}
	}
	return PathOther
}

func normalizeAuthPath(parts []string) string {
	if len(parts) >= 3 && parts[1] == "token" {
		switch parts[2] {
		case "renew-self":
			return "auth_token_renew"
		case "lookup-self":
			return "auth_token_lookup"
		}
	}
	if len(parts) < 3 {
		return PathOther
	}
	switch parts[2] {
	case "login":
		return "auth_login"
	case "config":
		return "auth_config"
	case "role":
		if len(parts) == 3 {
			return "auth_role_list"
		}
		return "auth_role"
	}
	return PathOther
}

// resultFromStatusCode mirrors the circuit-breaker decision in Client.Do
// (4xx = caller bug, 5xx = breaker trip, no err = success).
func resultFromStatusCode(code int) string {
	switch {
	case code >= 200 && code < 300:
		return ResultSuccess
	case code >= 400 && code < 500:
		return ResultClientError
	case code >= 500:
		return ResultServerError
	}
	return ResultTransportErr
}

// codeLabel buckets HTTP codes for cardinality. 401/403/404 are kept distinct
// because they fire specific alert paths (auth / permission / missing).
func codeLabel(code int) string {
	switch code {
	case 401, 403, 404:
		return strconv.Itoa(code)
	}
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	}
	return "unknown"
}
