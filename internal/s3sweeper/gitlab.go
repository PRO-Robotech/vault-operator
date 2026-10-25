/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package s3sweeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrJobNotFound: API CI не знает задания (404) — бакеты не трогаются.
	ErrJobNotFound = errors.New("s3sweeper: job not found")
	// ErrJobLookup: статус задания не получен. Текст несёт лишь вид отказа и
	// код HTTP — ни адреса, ни токена.
	ErrJobLookup = errors.New("s3sweeper: job lookup failed")
)

// JobClass — класс статуса задания CI.
type JobClass int

const (
	// JobUnknown — статус вне словаря: бакеты не трогаются, исход красный.
	JobUnknown JobClass = iota
	// JobAlive — задание ещё может создать или использовать бакет.
	JobAlive
	// JobFinished — задание завершено: его бакеты — сироты.
	JobFinished
)

// Словарь статусов задания API CI. Завершённых четыре; прочее — живое либо
// неизвестное, и то и другое не снимается.
var jobClasses = map[string]JobClass{
	"success":              JobFinished,
	"failed":               JobFinished,
	"canceled":             JobFinished,
	"skipped":              JobFinished,
	"created":              JobAlive,
	"pending":              JobAlive,
	"running":              JobAlive,
	"preparing":            JobAlive,
	"scheduled":            JobAlive,
	"manual":               JobAlive,
	"waiting_for_resource": JobAlive,
	"waiting_for_callback": JobAlive,
	"canceling":            JobAlive,
}

// ClassifyJobStatus относит статус задания к классу; регистр значим.
func ClassifyJobStatus(s string) JobClass {
	return jobClasses[s]
}

// Заголовки токена API CI: личный (проектный) токен и токен задания.
const (
	HeaderPrivateToken = "PRIVATE-TOKEN"
	HeaderJobToken     = "JOB-TOKEN"
)

const (
	jobPlaceholder    = "{job}"
	maxJobBody        = 1 << 20
	defaultJobTimeout = 15 * time.Second
)

// GitLabJobs читает статус задания GET-запросом к API CI по шаблону адреса.
type GitLabJobs struct {
	tmpl   string
	header string
	token  string
	hc     *http.Client
}

// NewGitLabJobs проверяет шаблон адреса: https, хост, без учётки в адресе,
// ровно одна подстановка {job}. hc nil — клиент с пределом 15 с. Клиент не
// следует перенаправлениям: токен не уходит по адресу из ответа.
func NewGitLabJobs(tmpl, header, token string, hc *http.Client) (*GitLabJobs, error) {
	if strings.Count(tmpl, jobPlaceholder) != 1 {
		return nil, fmt.Errorf("%w: job status URL must carry exactly one %s", ErrBadOptions, jobPlaceholder)
	}
	u, err := url.Parse(strings.Replace(tmpl, jobPlaceholder, "1", 1))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: job status URL must be https with a host and no credentials", ErrBadOptions)
	}
	if header != HeaderPrivateToken && header != HeaderJobToken {
		return nil, fmt.Errorf("%w: token header must be %s or %s", ErrBadOptions, HeaderPrivateToken, HeaderJobToken)
	}
	c := &http.Client{Timeout: defaultJobTimeout}
	if hc != nil {
		cp := *hc
		c = &cp
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &GitLabJobs{tmpl: tmpl, header: header, token: token, hc: c}, nil
}

// JobStatus — статус задания словом API CI.
func (g *GitLabJobs) JobStatus(ctx context.Context, jobID uint64) (string, error) {
	id := strconv.FormatUint(jobID, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.Replace(g.tmpl, jobPlaceholder, id, 1), nil)
	if err != nil {
		return "", fmt.Errorf("%w: request not built", ErrJobLookup)
	}
	if g.token != "" {
		req.Header.Set(g.header, g.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		// Текст *url.Error несёт адрес — в ошибку идёт лишь вид отказа.
		kind := "transport error"
		if errors.Is(err, context.DeadlineExceeded) {
			kind = "timeout"
		}
		return "", fmt.Errorf("%w: %s", ErrJobLookup, kind)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", ErrJobNotFound
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("%w: http %d", ErrJobLookup, resp.StatusCode)
	}
	var body struct {
		ID     uint64 `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJobBody)).Decode(&body); err != nil {
		return "", fmt.Errorf("%w: answer is not a job", ErrJobLookup)
	}
	if body.ID != jobID || body.Status == "" {
		return "", fmt.Errorf("%w: answer names another job or no status", ErrJobLookup)
	}
	return body.Status, nil
}
