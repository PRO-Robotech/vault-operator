/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	DriftTypeMount      = "mount"
	DriftTypePolicy     = "policy"
	DriftTypeRole       = "role"
	DriftTypeTransitKey = "transit_key"
	DriftTypeRoleBody   = "role_body"
	DriftTypePolicyBody = "policy_body"
)

var driftDetectedCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vaultclaim_drift_detected_total",
		Help: "Total drift events detected per Vault object category since process start.",
	},
	[]string{"drift_type"},
)

const (
	ReviewerJWTResultRotated = "rotated"
	ReviewerJWTResultSkipped = "skipped"
	ReviewerJWTResultFailed  = "failed"
)

var reviewerJWTRenewalCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_reviewer_jwt_renewal_total",
		Help: "Token-reviewer JWT lifecycle events at Step 4 of the VaultClaim pipeline (rotated/skipped/failed).",
	},
	[]string{"result"},
)

var reviewerJWTExpirySeconds = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "vault_reviewer_jwt_expiry_seconds",
		Help: "Seconds until the token-reviewer JWT expires (negative once expired), per VaultClaim.",
	},
	[]string{"namespace", "claim"},
)

func init() {
	ctrlmetrics.Registry.MustRegister(driftDetectedCounter, reviewerJWTRenewalCounter, reviewerJWTExpirySeconds)
}
