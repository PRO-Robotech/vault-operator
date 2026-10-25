/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package s3sweeper — уборщик бакетов, которые заказал прогон CI, вне
// кластера. Финализатор S3BucketClaim снимает бакет, только пока кластер жив;
// задание, оборванное до снятия заявок (отмена, срок, гибель узла kind),
// оставляет бакет в облаке навсегда, и опознать его можно лишь по имени: у
// записи бакета нет ни времени создания, ни метки.
//
// Имя бакета прогона: «<hex>-k8s-<логин>-ci-<номер задания>» и, если имя было
// занято, «…-<N>» (clusterRef.name = ci-<номер задания>). Префикс <hex>
// принадлежит логину и может смениться после снятия последнего бакета логина,
// поэтому сопоставление идёт по форме «^[0-9a-f]+-», а не по значению.
//
// Снимается строка, у которой одновременно владелец (cust_login) равен
// логину и имя целиком подходит под форму — у того же логина живут чужие
// бакеты (ai-test-*), их уборщик не трогает никогда. removeBucket не
// принимает логина и вызывающего не проверяет, поэтому оба условия судятся
// здесь, на каждой строке каждого перечня.
package s3sweeper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"time"

	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

var (
	// ErrLeftovers: по сроку у цели остался бакет вне REMOVED либо перечень
	// не читался.
	ErrLeftovers = errors.New("s3sweeper: buckets left after the deadline")
	// ErrTooManyRemovals: целей больше предела за запуск — ни одного снятия.
	ErrTooManyRemovals = errors.New("s3sweeper: more removals than allowed")
	// ErrJobUnclassified: статус задания CI не получен либо не из словаря —
	// его бакеты не тронуты, исход красный.
	ErrJobUnclassified = errors.New("s3sweeper: job status unclassified")
	// ErrBadOptions: опции отвергнуты до первого вызова службы.
	ErrBadOptions = errors.New("s3sweeper: bad options")
)

// Cloud — то, что уборщику нужно от cloud-manager.
type Cloud interface {
	// ListByCustomer — строки области ByCustomer как есть: любой статус, без
	// суждения о владельце.
	ListByCustomer(ctx context.Context, login string) ([]*cloudmanager.Bucket, error)
	// Remove принимает снятие: nil — бакет ушёл в REMOVING;
	// cloudmanager.ErrAlreadyRemoved и ErrBucketNotFound — конечные ответы.
	Remove(ctx context.Context, bucketName string) error
}

// JobStatusSource отдаёт статус задания CI словом API CI.
type JobStatusSource interface {
	JobStatus(ctx context.Context, jobID uint64) (string, error)
}

// Clock — часы ожидания; nil в Options — настоящие.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// Options — общие опции обоих режимов.
type Options struct {
	// Logins — логины, чьи бакеты убираются; каждый судится отдельно.
	Logins []string
	// DryRun печатает план и ничего не снимает.
	DryRun bool
	// Timeout — сколько ждать REMOVED у всех целей.
	Timeout time.Duration
	// PollInterval — пауза между перечнями.
	PollInterval time.Duration
	// MaxRemovals — предел различных бакетов, снимаемых за запуск: больше —
	// отказ до первого снятия (защита от массового сноса при ошибке формы).
	MaxRemovals int
	Log         *slog.Logger
	Clock       Clock
}

// Leftover — бакет, оставшийся вне REMOVED по сроку.
type Leftover struct {
	Login, Name, Status string
}

// Report — итог запуска.
type Report struct {
	// Rows — строк прочитано первым перечнем по всем логинам (знаменатель).
	Rows int
	// Removed — бакеты, чьё снятие служба приняла.
	Removed []string
	// Left — остаток по сроку.
	Left []Leftover
}

const maxLoginLen = 32

// loginRe — логин клиента: строчные латинские буквы и цифры, сегменты через
// дефис; ровно то, что допускает имя бакета.
var loginRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// jobIDRe — номер задания CI: десятичное число без ведущего нуля.
var jobIDRe = regexp.MustCompile(`^[1-9][0-9]*$`)

// ParseJobID разбирает номер задания CI; пустой, нулевой, с ведущим нулём или
// нечисловой номер отвергается (пустой $CI_JOB_ID не превращается в широкую
// форму имени).
func ParseJobID(s string) (uint64, error) {
	if !jobIDRe.MatchString(s) {
		return 0, fmt.Errorf("%w: job id %q is not a positive decimal number", ErrBadOptions, s)
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: job id %q is out of range", ErrBadOptions, s)
	}
	return id, nil
}

// ValidateLogin отвергает логин, которого не может быть в имени бакета.
func ValidateLogin(login string) error {
	if len(login) > maxLoginLen || !loginRe.MatchString(login) {
		return fmt.Errorf("%w: login %q is not a customer login", ErrBadOptions, login)
	}
	return nil
}

// ciNameRe — форма имени бакета прогона CI данного логина; номер задания —
// первая группа.
func ciNameRe(login string) *regexp.Regexp {
	return regexp.MustCompile(`^[0-9a-f]+-k8s-` + regexp.QuoteMeta(login) + `-ci-([1-9][0-9]*)(?:-[0-9]+)?$`)
}

// matcher судит строку перечня: она наша, только если владелец — этот логин
// и имя целиком нашей формы. Возвращает номер задания из имени.
type matcher map[string]*regexp.Regexp

func newMatcher(logins []string) matcher {
	m := make(matcher, len(logins))
	for _, l := range logins {
		m[l] = ciNameRe(l)
	}
	return m
}

func (m matcher) job(login string, b *cloudmanager.Bucket) (uint64, bool) {
	if b.CustLogin != login {
		return 0, false
	}
	sub := m[login].FindStringSubmatch(b.Name)
	if sub == nil {
		return 0, false
	}
	id, err := strconv.ParseUint(sub[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func (o *Options) validate() error {
	if len(o.Logins) == 0 {
		return fmt.Errorf("%w: no login", ErrBadOptions)
	}
	seen := map[string]bool{}
	logins := make([]string, 0, len(o.Logins))
	for _, l := range o.Logins {
		if err := ValidateLogin(l); err != nil {
			return err
		}
		if !seen[l] {
			seen[l] = true
			logins = append(logins, l)
		}
	}
	o.Logins = logins
	switch {
	case o.Timeout <= 0:
		return fmt.Errorf("%w: timeout must be positive", ErrBadOptions)
	case o.PollInterval <= 0:
		return fmt.Errorf("%w: poll interval must be positive", ErrBadOptions)
	case o.MaxRemovals <= 0:
		return fmt.Errorf("%w: max removals must be positive", ErrBadOptions)
	case o.Log == nil:
		return fmt.Errorf("%w: no logger", ErrBadOptions)
	}
	if o.Clock == nil {
		o.Clock = realClock{}
	}
	return nil
}

// RunJob снимает бакеты задания jobID у логинов o.Logins и ждёт их REMOVED.
func RunJob(ctx context.Context, cloud Cloud, jobID uint64, o Options) (Report, error) {
	if jobID == 0 {
		return Report{}, fmt.Errorf("%w: job id 0", ErrBadOptions)
	}
	if err := o.validate(); err != nil {
		return Report{}, err
	}
	m := newMatcher(o.Logins)
	o.Log.Info("job sweep started", "job", jobID, "logins", o.Logins, "dryRun", o.DryRun)
	want := func(login string, b *cloudmanager.Bucket) bool {
		id, ok := m.job(login, b)
		return ok && id == jobID
	}
	if o.DryRun {
		return plan(ctx, cloud, o, want)
	}
	return drain(ctx, cloud, o, want)
}

// RunSweep снимает бакеты заданий CI, которые API CI называет завершёнными.
// Задания идущие не трогаются; задания без статуса или со статусом вне
// словаря не трогаются и делают исход красным (ErrJobUnclassified).
func RunSweep(ctx context.Context, cloud Cloud, jobs JobStatusSource, o Options) (Report, error) {
	if err := o.validate(); err != nil {
		return Report{}, err
	}
	m := newMatcher(o.Logins)
	o.Log.Info("scheduled sweep started", "logins", o.Logins, "dryRun", o.DryRun)
	live := map[uint64]bool{}
	for _, login := range o.Logins {
		rows, err := cloud.ListByCustomer(ctx, login)
		if err != nil {
			o.Log.Error("listing failed", "login", login, "reason", reason(err))
			return Report{}, fmt.Errorf("list buckets of %s: %s", login, reason(err))
		}
		for _, b := range rows {
			if id, ok := m.job(login, b); ok && b.Status != cloudmanager.StatusRemoved {
				live[id] = true
			}
		}
	}
	finished, unclassified := classifyJobs(ctx, jobs, live, o.Log)
	want := func(login string, b *cloudmanager.Bucket) bool {
		id, ok := m.job(login, b)
		return ok && finished[id]
	}
	var (
		rep Report
		err error
	)
	if len(finished) > 0 {
		if o.DryRun {
			rep, err = plan(ctx, cloud, o, want)
		} else {
			rep, err = drain(ctx, cloud, o, want)
		}
	}
	if err == nil && unclassified > 0 {
		err = fmt.Errorf("%w: %d job(s)", ErrJobUnclassified, unclassified)
	}
	return rep, err
}

// classifyJobs спрашивает статус каждого задания один раз; возвращает
// завершённые и число неклассифицированных.
func classifyJobs(ctx context.Context, jobs JobStatusSource, live map[uint64]bool,
	log *slog.Logger) (map[uint64]bool, int) {
	ids := make([]uint64, 0, len(live))
	for id := range live {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	finished := map[uint64]bool{}
	unclassified := 0
	for _, id := range ids {
		st, err := jobs.JobStatus(ctx, id)
		if err != nil {
			unclassified++
			log.Warn("job status unknown, buckets kept", "job", id, "reason", reason(err))
			continue
		}
		switch ClassifyJobStatus(st) {
		case JobFinished:
			finished[id] = true
			log.Info("job finished, buckets to remove", "job", id, "jobStatus", st)
		case JobAlive:
			log.Info("job not finished, buckets kept", "job", id, "jobStatus", st)
		default:
			unclassified++
			log.Warn("job status outside the vocabulary, buckets kept", "job", id)
		}
	}
	return finished, unclassified
}

type wantFunc func(login string, b *cloudmanager.Bucket) bool

// plan печатает, что сделал бы запуск, одним перечнем.
func plan(ctx context.Context, cloud Cloud, o Options, want wantFunc) (Report, error) {
	var rep Report
	for _, login := range o.Logins {
		rows, err := cloud.ListByCustomer(ctx, login)
		if err != nil {
			o.Log.Error("listing failed", "login", login, "reason", reason(err))
			return rep, fmt.Errorf("list buckets of %s: %s", login, reason(err))
		}
		rep.Rows += len(rows)
		for _, b := range rows {
			if !want(login, b) {
				continue
			}
			o.Log.Info("plan", "login", login, "bucket", b.Name, "status", b.Status, "action", actionOf(b.Status))
		}
	}
	o.Log.Info("summary", "dryRun", true, "rows", rep.Rows)
	return rep, nil
}

func actionOf(st string) string {
	switch st {
	case cloudmanager.StatusRemoved:
		return "none"
	case cloudmanager.StatusRemoving, cloudmanager.StatusCreating:
		return "wait"
	default:
		return "remove"
	}
}

// pass — один проход: перечень всех логинов, снятие живых целей.
type pass struct {
	pending []Leftover
	listErr error
	rows    int
}

// drain снимает цели и ждёт REMOVED до срока. Цели выбираются заново
// каждым перечнем: бакет задания, вышедший из CREATING, снимается следующим
// проходом. Снятие уже ушедшего в REMOVING не повторяется.
func drain(ctx context.Context, cloud Cloud, o Options, want wantFunc) (Report, error) {
	var rep Report
	accepted := map[string]bool{}
	deadline := o.Clock.Now().Add(o.Timeout)
	for first := true; ; first = false {
		p, err := runPass(ctx, cloud, o, want, accepted, &rep)
		if first {
			rep.Rows = p.rows
		}
		if err != nil {
			return rep, err
		}
		if p.listErr == nil && len(p.pending) == 0 {
			o.Log.Info("summary", "rows", rep.Rows, "removed", len(rep.Removed), "left", 0)
			return rep, nil
		}
		if !o.Clock.Now().Before(deadline) {
			rep.Left = p.pending
			for _, l := range p.pending {
				o.Log.Error("bucket left", "login", l.Login, "bucket", l.Name, "status", l.Status)
			}
			o.Log.Error("summary", "rows", rep.Rows, "removed", len(rep.Removed), "left", len(p.pending))
			if p.listErr != nil {
				return rep, fmt.Errorf("%w: listing failed: %s", ErrLeftovers, reason(p.listErr))
			}
			return rep, fmt.Errorf("%w: %d bucket(s)", ErrLeftovers, len(p.pending))
		}
		if err := o.Clock.Sleep(ctx, o.PollInterval); err != nil {
			return rep, fmt.Errorf("wait for REMOVED: %w", err)
		}
	}
}

type target struct {
	login string
	b     *cloudmanager.Bucket
}

func runPass(ctx context.Context, cloud Cloud, o Options, want wantFunc, accepted map[string]bool,
	rep *Report) (pass, error) {
	var p pass
	var toRemove []target
	for _, login := range o.Logins {
		rows, err := cloud.ListByCustomer(ctx, login)
		if err != nil {
			p.listErr = err
			o.Log.Warn("listing failed", "login", login, "reason", reason(err))
			continue
		}
		p.rows += len(rows)
		for _, b := range rows {
			if !want(login, b) {
				continue
			}
			switch b.Status {
			case cloudmanager.StatusRemoved:
			case cloudmanager.StatusRemoving, cloudmanager.StatusCreating:
				p.pending = append(p.pending, Leftover{Login: login, Name: b.Name, Status: b.Status})
			default:
				toRemove = append(toRemove, target{login: login, b: b})
			}
		}
	}
	if n := distinctAfter(accepted, toRemove); n > o.MaxRemovals {
		o.Log.Error("too many removals, nothing removed", "planned", n, "max", o.MaxRemovals)
		return p, fmt.Errorf("%w: %d planned, max %d", ErrTooManyRemovals, n, o.MaxRemovals)
	}
	for _, t := range toRemove {
		if left, keep := removeOne(ctx, cloud, o.Log, t, accepted, rep); keep {
			p.pending = append(p.pending, left)
		}
	}
	return p, nil
}

// distinctAfter — сколько различных бакетов окажется снятым после прохода.
func distinctAfter(accepted map[string]bool, toRemove []target) int {
	n := len(accepted)
	for _, t := range toRemove {
		if !accepted[t.b.Name] {
			n++
		}
	}
	return n
}

// removeOne снимает бакет; keep — ждать ли его дальше.
func removeOne(ctx context.Context, cloud Cloud, log *slog.Logger, t target, accepted map[string]bool,
	rep *Report) (Leftover, bool) {
	left := Leftover{Login: t.login, Name: t.b.Name, Status: t.b.Status}
	err := cloud.Remove(ctx, t.b.Name)
	switch {
	case err == nil:
		if !accepted[t.b.Name] {
			accepted[t.b.Name] = true
			rep.Removed = append(rep.Removed, t.b.Name)
		}
		log.Info("remove accepted", "login", t.login, "bucket", t.b.Name, "status", t.b.Status)
		left.Status = cloudmanager.StatusRemoving
		return left, true
	case errors.Is(err, cloudmanager.ErrAlreadyRemoved):
		log.Info("already removed", "login", t.login, "bucket", t.b.Name)
		return left, false
	case errors.Is(err, cloudmanager.ErrBucketNotFound):
		log.Info("not found", "login", t.login, "bucket", t.b.Name)
		return left, false
	default:
		log.Warn("remove failed", "login", t.login, "bucket", t.b.Name, "reason", reason(err))
		return left, true
	}
}

// reason — причина отказа без свободного текста: код gRPC, имя ошибки
// словаря либо вид. Текст отказа транспорта несёт адрес службы, а ответ
// службы — произвольный текст; в журнал не идёт ни то, ни другое.
func reason(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, cloudmanager.ErrRemoveFailed):
		return "remove answer outside the vocabulary"
	case errors.Is(err, ErrJobNotFound):
		return "job not found"
	case errors.Is(err, ErrJobLookup):
		return err.Error()
	}
	// FromError разворачивает обёртки %w клиента до статуса gRPC.
	if st, ok := status.FromError(err); ok {
		return "grpc " + st.Code().String()
	}
	return "error"
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
