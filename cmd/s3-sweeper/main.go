/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Команда s3-sweeper — уборщик бакетов прогонов CI вне кластера
// (internal/s3sweeper).
//
//	s3-sweeper job   --login L [--login L2] --job-id N [общие флаги]
//	s3-sweeper sweep --login L [--login L2] --job-alive https://…/jobs/{job} [общие флаги]
//
// job снимает бакеты задания N и ждёт их REMOVED; sweep — бакеты заданий,
// которые API CI называет завершёнными. Адрес cloud-manager — флагом
// --cloud-manager-addr либо переменной CLOUD_MANAGER_ADDR; токен API CI —
// S3_SWEEPER_GITLAB_TOKEN (заголовок PRIVATE-TOKEN) либо CI_JOB_TOKEN
// (JOB-TOKEN). Код выхода: 0 — целей не осталось; 1 — остаток, отказ службы,
// неклассифицированное задание или строка нашей формы без владельца;
// 2 — неверный вызов.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
	"github.com/PRO-Robotech/vault-operator/internal/s3sweeper"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2

	envAddr     = "CLOUD_MANAGER_ADDR"
	envGLToken  = "S3_SWEEPER_GITLAB_TOKEN"
	envJobToken = "CI_JOB_TOKEN"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// logins — повторяемый флаг --login.
type logins []string

func (l *logins) String() string { return strings.Join(*l, ",") }

func (l *logins) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// common — флаги обоих режимов.
type common struct {
	addr        string
	logins      logins
	dryRun      bool
	timeout     time.Duration
	poll        time.Duration
	maxRemovals int
	callTimeout time.Duration
}

func (c *common) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.addr, "cloud-manager-addr", "", "cloud-manager gRPC address (default: $"+envAddr+").")
	fs.Var(&c.logins, "login", "Customer login whose CI buckets are swept; repeatable.")
	fs.BoolVar(&c.dryRun, "dry-run", false, "Print the plan, remove nothing.")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Minute, "How long to wait for every target to become REMOVED.")
	fs.DurationVar(&c.poll, "poll-interval", 10*time.Second, "Pause between listings.")
	fs.IntVar(&c.maxRemovals, "max-removals", 20, "Refuse without removing anything when more buckets are targeted.")
	fs.DurationVar(&c.callTimeout, "call-timeout", 15*time.Second, "Deadline of one cloud-manager call.")
}

func (c *common) options(log *slog.Logger) s3sweeper.Options {
	return s3sweeper.Options{
		Logins:       c.logins,
		DryRun:       c.dryRun,
		Timeout:      c.timeout,
		PollInterval: c.poll,
		MaxRemovals:  c.maxRemovals,
		Log:          log,
	}
}

// run — тело команды; hc — HTTP-клиент API CI (nil — по умолчанию).
func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, hc *http.Client) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	if len(args) == 0 {
		log.Error("usage: s3-sweeper job|sweep [flags]")
		return exitUsage
	}
	mode, rest := args[0], args[1:]
	fs := flag.NewFlagSet("s3-sweeper "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.bind(fs)
	var jobID, jobAlive string
	switch mode {
	case "job":
		fs.StringVar(&jobID, "job-id", "", "CI job id whose buckets are removed.")
	case "sweep":
		fs.StringVar(&jobAlive, "job-alive", "", "CI API URL of a job with {job} in place of its id, https only.")
	default:
		log.Error("unknown mode, want job or sweep", "mode", mode)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		log.Error("unexpected arguments", "count", fs.NArg())
		return exitUsage
	}
	if c.addr == "" {
		c.addr = getenv(envAddr)
	}
	if c.addr == "" {
		log.Error("cloud-manager address not set: --cloud-manager-addr or $" + envAddr)
		return exitUsage
	}

	var exec func(cloud s3sweeper.Cloud) (s3sweeper.Report, error)
	switch mode {
	case "job":
		id, err := s3sweeper.ParseJobID(jobID)
		if err != nil {
			log.Error("refused", "err", err.Error())
			return exitUsage
		}
		exec = func(cloud s3sweeper.Cloud) (s3sweeper.Report, error) {
			return s3sweeper.RunJob(ctx, cloud, id, c.options(log))
		}
	case "sweep":
		jobs, err := gitlabJobs(jobAlive, getenv, hc)
		if err != nil {
			log.Error("refused", "err", err.Error())
			return exitUsage
		}
		exec = func(cloud s3sweeper.Cloud) (s3sweeper.Report, error) {
			return s3sweeper.RunSweep(ctx, cloud, jobs, c.options(log))
		}
	}
	return dialAndRun(c, log, exec)
}

func gitlabJobs(tmpl string, getenv func(string) string, hc *http.Client) (*s3sweeper.GitLabJobs, error) {
	if tmpl == "" {
		return nil, errors.New("--job-alive is required in sweep mode")
	}
	header, token := s3sweeper.HeaderPrivateToken, getenv(envGLToken)
	if token == "" {
		if jt := getenv(envJobToken); jt != "" {
			header, token = s3sweeper.HeaderJobToken, jt
		}
	}
	return s3sweeper.NewGitLabJobs(tmpl, header, token, hc)
}

func dialAndRun(c common, log *slog.Logger, exec func(s3sweeper.Cloud) (s3sweeper.Report, error)) int {
	opts := cloudmanager.DefaultOptions()
	opts.CallTimeout = c.callTimeout
	cloud, err := cloudmanager.NewWithOptions(c.addr, opts)
	if err != nil {
		// Текст отказа разбора несёт адрес — в журнал он не идёт.
		log.Error("cloud-manager address refused")
		return exitUsage
	}
	defer func() { _ = cloud.Close() }()
	_, err = exec(cloud)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, s3sweeper.ErrBadOptions):
		log.Error("refused", "err", err.Error())
		return exitUsage
	default:
		log.Error("sweep failed", "err", err.Error())
		return exitFail
	}
}
