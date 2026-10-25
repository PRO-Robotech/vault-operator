/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package s3sweeper — уборщик бакетов CI вне кластера (каркас красной пробы).
package s3sweeper

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

var (
	ErrLeftovers       = errors.New("s3sweeper: buckets left")
	ErrTooManyRemovals = errors.New("s3sweeper: too many removals")
	ErrJobUnclassified = errors.New("s3sweeper: job unclassified")
	ErrJobNotFound     = errors.New("s3sweeper: job not found")
	ErrJobLookup       = errors.New("s3sweeper: job lookup failed")
)

type Cloud interface {
	ListByCustomer(ctx context.Context, login string) ([]*cloudmanager.Bucket, error)
	Remove(ctx context.Context, bucketName string) error
}

type JobStatusSource interface {
	JobStatus(ctx context.Context, jobID uint64) (string, error)
}

type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type Options struct {
	Logins       []string
	DryRun       bool
	Timeout      time.Duration
	PollInterval time.Duration
	MaxRemovals  int
	Log          *slog.Logger
	Clock        Clock
}

type Leftover struct{ Login, Name, Status string }

type Report struct {
	Rows    int
	Removed []string
	Left    []Leftover
}

func RunJob(context.Context, Cloud, uint64, Options) (Report, error) { return Report{}, nil }

func RunSweep(context.Context, Cloud, JobStatusSource, Options) (Report, error) { return Report{}, nil }

func ParseJobID(string) (uint64, error) { return 0, nil }

type JobClass int

const (
	JobUnknown JobClass = iota
	JobAlive
	JobFinished
)

func ClassifyJobStatus(string) JobClass { return JobUnknown }

type GitLabJobs struct{}

func NewGitLabJobs(string, string, string, *http.Client) (*GitLabJobs, error) {
	return &GitLabJobs{}, nil
}

func (*GitLabJobs) JobStatus(context.Context, uint64) (string, error) { return "", nil }
