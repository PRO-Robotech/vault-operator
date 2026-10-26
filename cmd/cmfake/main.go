/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Команда cmfake — двойник cloud-manager самостоятельной службой для стенда:
// gRPC на контракте internal/cloudmanager/proto, состояние в памяти, бакеты в
// S3-совместимом хранилище стенда. Форма конфига — cmfake.LoadConfig.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager/cmfake"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "/etc/cmfake/config.yaml", "Path to the cmfake config file.")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := cmfake.LoadConfig(*configPath)
	if err != nil {
		log.Error("cmfake config refused", "err", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := cmfake.Run(ctx, cfg, log, cmfake.RunOptions{}); err != nil {
		log.Error("cmfake failed", "err", err.Error())
		return 1
	}
	return 0
}
