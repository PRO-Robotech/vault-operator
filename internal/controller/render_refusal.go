/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"sync"
	"time"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// RequeueClaimRenderRefused re-checks a claim whose rules do not render. The
// outcome depends on spec and on the auth mount accessor alone: an edit of
// spec enqueues the claim by itself, and a recreated mount is picked up at the
// cadence a Ready claim is checked for drift.
const RequeueClaimRenderRefused = RequeueClaimDriftReady

// renderRefusals remembers, per claim, the generation whose rules did not
// render and when, so that no pass of that generation renders them again
// before RequeueClaimRenderRefused has passed, whatever enqueued it. In
// memory, like stepBackoff: a restart renders once more.
type renderRefusals struct {
	mu      sync.Mutex
	entries map[types.NamespacedName]renderRefusal
}

type renderRefusal struct {
	generation int64
	at         time.Time
}

func (m *renderRefusals) record(key types.NamespacedName, generation int64, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[types.NamespacedName]renderRefusal)
	}
	m.entries[key] = renderRefusal{generation: generation, at: at}
}

func (m *renderRefusals) forget(key types.NamespacedName) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

// pending reports how long a pass over claim is still to be skipped: this
// generation was refused for rules that do not render less than
// RequeueClaimRenderRefused ago, and the status as persisted shows that
// refusal. The status check keeps a pass whose refusal never reached the API
// server from being skipped.
func (m *renderRefusals) pending(key types.NamespacedName, claim *vaultv1alpha1.VaultClaim, now time.Time) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return 0, false
	}
	if e.generation != claim.Generation {
		delete(m.entries, key)
		return 0, false
	}
	left := RequeueClaimRenderRefused - now.Sub(e.at)
	if left <= 0 || !renderRefusalPersisted(claim) {
		return 0, false
	}
	return min(left, RequeueClaimRenderRefused), true
}

func renderRefusalPersisted(claim *vaultv1alpha1.VaultClaim) bool {
	if claim.Status.Phase != vaultv1alpha1.PhaseFailed {
		return false
	}
	c := apimeta.FindStatusCondition(claim.Status.Conditions, vaultv1alpha1.ConditionPoliciesApplied)
	return c != nil && c.Status == metav1.ConditionFalse && c.Reason == ReasonRenderFailed &&
		c.ObservedGeneration == claim.Generation
}
