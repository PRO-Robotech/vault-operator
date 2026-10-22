/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Command bucket-operator runs the S3BucketClaim controller.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/controller"
	"github.com/PRO-Robotech/vault-operator/internal/operator"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// tokenRevokeTimeout bounds the revoke of the Vault tokens at shutdown.
const tokenRevokeTimeout = 10 * time.Second

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vaultv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var probeAddr string
	var enableLeaderElection bool
	var secureMetrics bool
	var enableHTTP2 bool
	var pprofAddr string
	var cloudManagerAddr string
	var defaultS3ConfigurationID string
	var cmTimeout, cmCreateTimeout, cmKeepalive time.Duration
	var cmFindByBucket bool
	var cmFindRetries int
	var concurrentReconciles int
	var kubeQPS float64
	var kubeBurst int
	var cmQPS float64
	var cmBurst int
	var run operator.Flags
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election to ensure only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics server")
	flag.StringVar(&pprofAddr, "pprof-bind-address", "",
		"Address for the pprof/diagnostics endpoint. Empty (default) disables it.")
	flag.StringVar(&cloudManagerAddr, "cloud-manager-addr", "grpc-internal.svc-cloud-manager.service.consul:50051",
		"gRPC address of svc-cloud-manager (bucket create/find/remove).")
	flag.StringVar(&defaultS3ConfigurationID, "default-s3-configuration-id", "s3_v1",
		"cloud-manager S3 configuration id used when spec.bucket.configurationId is empty.")
	flag.DurationVar(&cmTimeout, "cloud-manager-timeout", 15*time.Second,
		"Deadline of a cloud-manager findAll or removeBucket call.")
	flag.DurationVar(&cmCreateTimeout, "cloud-manager-create-timeout", cloudmanager.DefaultOptions().CreateTimeout,
		"Deadline of a cloud-manager create. Kept above the server's create latency: a create cut by the "+
			"client still runs on the server, and a repeat of the same name may meet its half-made state.")
	flag.DurationVar(&cmKeepalive, "cloud-manager-keepalive", 0,
		"gRPC keepalive ping interval while a cloud-manager call is active; 0 disables pings.")
	flag.BoolVar(&cmFindByBucket, "cloud-manager-find-by-bucket", true,
		"Look a known bucket up with a ByBucket scope; false falls back to the ByCustomer query. "+
			"Results are filtered by exact name and owner on the client either way.")
	flag.IntVar(&cmFindRetries, "cloud-manager-find-retries", 1,
		"Extra attempts of a findAll call that failed with UNAVAILABLE (create and remove are never retried).")
	flag.IntVar(&concurrentReconciles, "s3bucketclaim-concurrent-reconciles", 2,
		"S3BucketClaims reconciled in parallel; one claim is never reconciled twice at once.")
	flag.Float64Var(&kubeQPS, "kube-api-qps", 0, "Kubernetes API client QPS; 0 keeps the library default.")
	flag.IntVar(&kubeBurst, "kube-api-burst", 0, "Kubernetes API client burst; 0 keeps the library default.")
	flag.Float64Var(&cmQPS, "cloud-manager-qps", cloudmanager.DefaultQPS,
		"Calls per second to cloud-manager; a negative value disables the limit.")
	flag.IntVar(&cmBurst, "cloud-manager-burst", cloudmanager.DefaultBurst, "Burst of the cloud-manager call limit.")
	run.Bind(flag.CommandLine)
	opts := operator.LogOptions()
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Disable HTTP/2 by default to avoid the Stream Cancellation and Rapid
	// Reset CVEs (GHSA-qppj-fm5r-hxr3, GHSA-4374-p667-p6c8).
	if !enableHTTP2 {
		tlsOpts = append(
			tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	restCfg := ctrl.GetConfigOrDie()
	if kubeQPS > 0 {
		restCfg.QPS = float32(kubeQPS)
	}
	if kubeBurst > 0 {
		restCfg.Burst = kubeBurst
	}
	mgrOpts := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "bucket-operator.in-cloud.io",
		PprofBindAddress:       pprofAddr,
	}
	run.Apply(&mgrOpts)
	mgr, err := ctrl.NewManager(restCfg, mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	buckets, err := cloudmanager.NewWithOptions(cloudManagerAddr, cloudmanager.Options{
		CallTimeout:   cmTimeout,
		CreateTimeout: cmCreateTimeout,
		Keepalive:     cmKeepalive,
		FindByBucket:  cmFindByBucket,
		FindRetries:   cmFindRetries,
		QPS:           cmQPS,
		Burst:         cmBurst,
	})
	if err != nil {
		setupLog.Error(err, "unable to create cloud-manager client", "addr", cloudManagerAddr)
		os.Exit(1)
	}

	// One client cache for both controllers: one Vault token per VaultConfig.
	vaultClients := &controller.DefaultVaultClientFactory{Options: run.VaultOptions(concurrentReconciles)}
	progress := run.NewWatchdog()
	rt := run.Runtime(progress)

	if err := (&controller.S3BucketClaimReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		Recorder:                mgr.GetEventRecorderFor("s3bucketclaim-controller"),
		VaultFactory:            &controller.DefaultSecretVaultClientFactory{Shared: vaultClients},
		Runtime:                 rt,
		Buckets:                 buckets,
		DefaultConfigurationID:  defaultS3ConfigurationID,
		MaxConcurrentReconciles: concurrentReconciles,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "S3BucketClaim")
		os.Exit(1)
	}

	// Reconcile only this operator's own VaultConfig.
	if err := (&controller.VaultConfigReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		Recorder:         mgr.GetEventRecorderFor("vaultconfig-controller"),
		VaultFactory:     vaultClients,
		VaultConfigOwner: vaultv1alpha1.OwnerBucketOperator,
		Runtime:          rt,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultConfig")
		os.Exit(1)
	}

	if err := operator.AddProbes(mgr, progress); err != nil {
		setupLog.Error(err, "unable to set up probes")
		os.Exit(1)
	}
	err = controller.RegisterInventory(ctrlmetrics.Registry, mgr.GetClient(), controller.KindS3BucketClaim)
	if err != nil {
		setupLog.Error(err, "unable to register the claim inventory metrics")
		os.Exit(1)
	}

	setupLog.Info("starting bucket-operator", "cloud-manager-addr", cloudManagerAddr)
	err = mgr.Start(ctrl.SetupSignalHandler())
	// The controllers have stopped: give the Vault tokens back.
	revokeCtx, cancel := context.WithTimeout(context.Background(), tokenRevokeTimeout)
	vaultClients.RevokeAll(revokeCtx)
	cancel()
	if err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
