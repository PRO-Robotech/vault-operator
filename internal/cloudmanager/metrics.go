/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cloudmanager

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// removeUnknownResponseCounter counts removeBucket answers outside the known
// vocabulary ("Not found", "Already removed"): a non-zero rate means the server
// wording changed and the classification needs a look.
var removeUnknownResponseCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "vault_operator_cloudmanager_remove_unknown_response_total",
	Help: "removeBucket answers whose text is outside the known vocabulary.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(removeUnknownResponseCounter)
}
