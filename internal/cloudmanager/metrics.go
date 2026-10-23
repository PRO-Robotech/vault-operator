/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cloudmanager

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/status"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// removeUnknownResponseCounter counts removeBucket answers outside the known
// vocabulary ("Not found", "Already removed"): a non-zero rate means the server
// wording changed and the classification needs a look.
var removeUnknownResponseCounter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "vault_operator_cloudmanager_remove_unknown_response_total",
	Help: "removeBucket answers whose text is outside the known vocabulary.",
})

// createRejectedCounter counts create answers with an error code outside the
// mapped set, by code (the enum is closed, so the label set is bounded).
var createRejectedCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "vault_operator_cloudmanager_create_rejected_total",
	Help: "create answers whose error code is outside the mapped set, CODE_RESERVED included.",
}, []string{"code"})

// requestDuration is the latency of cloud-manager calls by RPC and gRPC
// code; both label sets are fixed, whatever the number of claims. The buckets
// reach the create deadline: a create past 15s is the case to measure.
var requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "vault_operator_cloudmanager_request_duration_seconds",
	Help:    "Latency of cloud-manager calls by method and gRPC code.",
	Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30, 60, 120},
}, []string{"method", "code"})

func init() {
	ctrlmetrics.Registry.MustRegister(removeUnknownResponseCounter, createRejectedCounter, requestDuration)
}

// observe records one call to method that started at start.
func observe(method string, start time.Time, err error) {
	requestDuration.WithLabelValues(method, status.Code(err).String()).Observe(time.Since(start).Seconds())
}
