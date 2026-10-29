/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmfake

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// DefaultShutdownTimeout — сколько остановка ждёт идущие вызовы, прежде чем
// оборвать их.
const DefaultShutdownTimeout = 20 * time.Second

// Started — поднятая служба: адрес слушателя и её хранилище.
type Started struct {
	Addr  net.Addr
	Store *Store
}

// RunOptions — необязательное к Run.
type RunOptions struct {
	// Ready вызывается, когда слушатель открыт и вызовы принимаются.
	Ready func(Started)
	// ShutdownTimeout — 0 означает DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
}

// Run поднимает службу по конфигу и держит её до конца ctx: хранилище S3,
// состояние в памяти, gRPC на контракте cloud-manager и проверка здоровья
// gRPC. Остановка: здоровье NOT_SERVING, мягкая остановка gRPC в пределах
// ShutdownTimeout, затем закрытие хранилища.
func Run(ctx context.Context, cfg *Config, log *slog.Logger, opts RunOptions) error {
	backend, err := NewS3Backend(cfg.S3)
	if err != nil {
		return err
	}
	store, err := NewStore(cfg.Store, backend, log)
	if err != nil {
		return err
	}
	defer store.Close()

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddress, err)
	}
	srv := grpc.NewServer()
	NewService(store).Register(srv)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	log.Info("cmfake serving", "addr", lis.Addr().String(), "clients", len(cfg.Store.Clients),
		"configurations", len(cfg.Store.Configurations), "bucketKeys", cfg.Store.BucketKeys)
	if opts.Ready != nil {
		opts.Ready(Started{Addr: lis.Addr(), Store: store})
	}

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	}

	log.Info("cmfake stopping")
	hs.Shutdown()
	timeout := opts.ShutdownTimeout
	if timeout <= 0 {
		timeout = DefaultShutdownTimeout
	}
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-stopped:
	case <-t.C:
		log.Warn("cmfake shutdown timeout; cutting in-flight calls", "timeout", timeout.String())
		srv.Stop()
		<-stopped
	}
	if err := <-serveErr; err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
