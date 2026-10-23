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
	DriftTypeAuthConfig = "auth_config"
	DriftTypeAccessor   = "auth_mount_accessor"
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

// policyGuardViolations counts refused or audited policy stanzas and role
// references, by guard mode and rule. The rollout gate for enforce reads it.
var policyGuardViolations = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_operator_policy_guard_violations_total",
		Help: "Policy stanzas and role references outside the claim's scope, by guard mode and rule.",
	},
	[]string{"mode", "rule"},
)

// pipelineStepTotal counts VaultClaim pipeline step outcomes. The outcome is
// Proceed, Wait, Refused or the failure cause from the closed set: both label
// sets are bounded, whatever the number of claims.
var pipelineStepTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "vault_operator_pipeline_step_total",
		Help: "VaultClaim pipeline step outcomes by step and outcome (Proceed, Wait, Refused, or the failure cause).",
	},
	[]string{"step", "outcome"},
)

// Step outcomes other than a failure cause.
const (
	stepOutcomeProceed = "Proceed"
	stepOutcomeWait    = "Wait"
	stepOutcomeRefused = "Refused"
)

func countStep(step string, res StepResult, err error) {
	outcome := stepOutcomeProceed
	switch {
	case err != nil:
		outcome = string(classifyFailure(err))
	case res == Wait:
		outcome = stepOutcomeWait
	case res == Refuse:
		outcome = stepOutcomeRefused
	}
	pipelineStepTotal.WithLabelValues(step, outcome).Inc()
}

func init() {
	ctrlmetrics.Registry.MustRegister(driftDetectedCounter, reviewerJWTRenewalCounter, reviewerJWTExpirySeconds,
		policyGuardViolations, pipelineStepTotal)
}
