/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// Claim kinds the inventory reports, as the kind label spells them.
const (
	KindVaultClaim       = "VaultClaim"
	KindS3BucketClaim    = "S3BucketClaim"
	KindVaultSecretClaim = "VaultSecretClaim"
)

// Object types of vault_operator_managed_objects.
const (
	managedPolicy     = "policy"
	managedRole       = "role"
	managedTransitKey = "transit_key"
	managedBucket     = "bucket"
	managedSecretItem = "secret_item"
)

// phaseUnknown counts a claim whose phase is empty or outside the known set,
// so the series stay the fixed set below.
const phaseUnknown = "Unknown"

var inventoryPhases = map[string][]string{
	KindVaultClaim: {vaultv1alpha1.PhasePending, vaultv1alpha1.PhaseConfiguring, vaultv1alpha1.PhaseReady,
		vaultv1alpha1.PhaseFailed, vaultv1alpha1.PhaseDeleting, phaseUnknown},
	KindS3BucketClaim: {vaultv1alpha1.PhasePending, vaultv1alpha1.PhaseReady, vaultv1alpha1.PhaseFailed,
		vaultv1alpha1.PhaseDeleting, phaseUnknown},
	KindVaultSecretClaim: {vaultv1alpha1.PhasePending, vaultv1alpha1.PhaseReady, vaultv1alpha1.PhaseFailed,
		vaultv1alpha1.PhaseDeleting, phaseUnknown},
}

var inventoryTypes = map[string][]string{
	KindVaultClaim:       {managedPolicy, managedRole, managedTransitKey},
	KindS3BucketClaim:    {managedBucket},
	KindVaultSecretClaim: {managedSecretItem},
}

var (
	claimsDesc = prometheus.NewDesc("vault_operator_claims",
		"Claims by kind and phase, read from the informer cache at scrape time.", []string{"kind", "phase"}, nil)
	managedObjectsDesc = prometheus.NewDesc("vault_operator_managed_objects",
		"Objects the claims' ledgers record, by claim kind and object type.", []string{"kind", "type"}, nil)
	inventoryErrorsDesc = prometheus.NewDesc("vault_operator_inventory_errors",
		"1 when the last scrape could not list a claim kind, else 0.", []string{"kind"}, nil)
)

// inventoryTimeout bounds one scrape's list of a kind.
const inventoryTimeout = 5 * time.Second

// claimInventory is a collector: it counts claims at scrape time, so its
// series are the fixed kind × phase and kind × type sets, whatever the number
// of claims.
type claimInventory struct {
	reader client.Reader
	kinds  []string
}

// RegisterInventory registers the claim inventory of kinds on reg. reader is
// the manager's cached client.
func RegisterInventory(reg prometheus.Registerer, reader client.Reader, kinds ...string) error {
	for _, k := range kinds {
		if _, ok := inventoryPhases[k]; !ok {
			return fmt.Errorf("inventory: unknown claim kind %q", k)
		}
	}
	return reg.Register(&claimInventory{reader: reader, kinds: kinds})
}

func (c *claimInventory) Describe(ch chan<- *prometheus.Desc) {
	ch <- claimsDesc
	ch <- managedObjectsDesc
	ch <- inventoryErrorsDesc
}

func (c *claimInventory) Collect(ch chan<- prometheus.Metric) {
	for _, kind := range c.kinds {
		phases, managed, err := c.count(kind)
		failed := 0.0
		if err != nil {
			failed = 1
		}
		ch <- prometheus.MustNewConstMetric(inventoryErrorsDesc, prometheus.GaugeValue, failed, kind)
		if err != nil {
			continue
		}
		for _, p := range inventoryPhases[kind] {
			ch <- prometheus.MustNewConstMetric(claimsDesc, prometheus.GaugeValue, float64(phases[p]), kind, p)
		}
		for _, t := range inventoryTypes[kind] {
			ch <- prometheus.MustNewConstMetric(managedObjectsDesc, prometheus.GaugeValue, float64(managed[t]), kind, t)
		}
	}
}

// count lists kind and returns the claims per phase and the ledger entries
// per object type.
func (c *claimInventory) count(kind string) (map[string]int, map[string]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), inventoryTimeout)
	defer cancel()
	phases := map[string]int{}
	managed := map[string]int{}
	known := map[string]bool{}
	for _, p := range inventoryPhases[kind] {
		known[p] = true
	}
	addPhase := func(p string) {
		if !known[p] || p == phaseUnknown {
			p = phaseUnknown
		}
		phases[p]++
	}
	switch kind {
	case KindVaultClaim:
		var list vaultv1alpha1.VaultClaimList
		if err := c.reader.List(ctx, &list); err != nil {
			return nil, nil, err
		}
		for i := range list.Items {
			addPhase(list.Items[i].Status.Phase)
			if v := list.Items[i].Status.Vault; v != nil {
				managed[managedPolicy] += len(v.AppliedPolicies)
				managed[managedRole] += len(v.AppliedRoles)
				managed[managedTransitKey] += len(v.TransitKeys)
			}
		}
	case KindS3BucketClaim:
		var list vaultv1alpha1.S3BucketClaimList
		if err := c.reader.List(ctx, &list); err != nil {
			return nil, nil, err
		}
		for i := range list.Items {
			addPhase(list.Items[i].Status.Phase)
			if list.Items[i].Status.BucketName != "" {
				managed[managedBucket]++
			}
		}
	case KindVaultSecretClaim:
		var list vaultv1alpha1.VaultSecretClaimList
		if err := c.reader.List(ctx, &list); err != nil {
			return nil, nil, err
		}
		for i := range list.Items {
			addPhase(list.Items[i].Status.Phase)
			managed[managedSecretItem] += len(list.Items[i].Status.Items)
		}
	}
	return phases, managed, nil
}
