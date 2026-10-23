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

// bucketOwnerUnverifiedCounter counts passes where cloud-manager returned the
// recorded bucket without an owner login. Purge and adoption refuse such a
// bucket; provisioning of an existing claim only counts it, so a zero rate on
// production is the precondition for making provisioning strict as well.
var bucketOwnerUnverifiedCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "vault_operator_s3bucketclaim_owner_unverified_total",
	Help: "Passes where cloud-manager returned the recorded bucket without an owner login.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(bucketOwnerUnverifiedCounter)
}
