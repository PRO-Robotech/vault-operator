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
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/vault-operator/internal/cloudmanager"
)

// runningService — поднятый двойник: тот же путь, что у cmd/cmfake (файл
// конфига → Run), на настоящем TCP-слушателе.
type runningService struct {
	addr  string
	store *Store
	s3    *s3Stub
	done  chan error
}

func startService(t *testing.T) *runningService {
	t.Helper()
	st := newS3Stub(t, credA, credB)
	endpoint, caFile := startS3Stub(t, st)

	dir := t.TempDir()
	y := configYAML(t, dir)
	y = strings.Replace(y, "https://s3.stand.test:9000", endpoint, 1)
	y = strings.Replace(y, "caFile: "+dir+"/ca.crt", "caFile: "+caFile, 1)
	y = strings.Replace(y, "retryDelay: 3s", "retryDelay: 10ms", 1)
	cfg, err := LoadConfig(writeFile(t, dir, "config.yaml", y))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan Started, 1)
	rs := &runningService{s3: st, done: make(chan error, 1)}
	go func() {
		rs.done <- Run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), RunOptions{
			Ready: func(s Started) { started <- s },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-rs.done:
			if err != nil {
				t.Errorf("Run returned %v after cancel", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("Run did not stop after cancel")
		}
	})
	select {
	case s := <-started:
		rs.addr, rs.store = s.Addr.String(), s.Store
	case err := <-rs.done:
		t.Fatalf("Run: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("service did not start")
	}
	return rs
}

func newRealClient(t *testing.T, addr string) *cloudmanager.Client {
	t.Helper()
	c, err := cloudmanager.NewWithOptions(addr, cloudmanager.DefaultOptions())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func systemCreate(login, name string) cloudmanager.CreateInput {
	return cloudmanager.CreateInput{CustomerLogin: login, BucketName: name, ConfigurationID: "s3_v1",
		Region: "ru1", ManagedBy: cloudmanager.ManagedBySystem}
}

// Настоящий клиент оператора против поднятой службы: заказ, повторный заказ,
// поиск своего и чужого, лимит, удаление, неизвестный логин и конфигурация.
// Шаги идут по порядку на одной службе: каждый опирается на состояние,
// оставленное предыдущими (лимит — на два бакета заказа, удаление — на
// суффиксный бакет, повторный заказ после удаления — на освобождённое место).
func TestIntegration_RealClientAgainstTheRunningService(t *testing.T) {
	rs := startService(t)
	c := newRealClient(t, rs.addr)
	ctx := context.Background()
	base := Prefix("tenant-a") + "-k8s-a-c1"

	name := checkCreate(ctx, t, rs, c, base)
	second := checkRepeatCreate(ctx, t, c, base)
	checkForeignTenant(ctx, t, c, name)
	checkLimit(ctx, t, c)
	checkRemove(ctx, t, rs, c, second)
	checkUnknownLogin(ctx, t, c)
	checkCreateCodes(ctx, t, c)
}

// checkCreate — заказ: имя по форме службы, клиент узнаёт в нём запрошенное,
// поиск своего отдаёт ключи арендатора, бакет заведён на S3-сервере.
func checkCreate(ctx context.Context, t *testing.T, rs *runningService, c *cloudmanager.Client, base string) string {
	t.Helper()
	name, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-c1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if name != base {
		t.Fatalf("name = %q, want %q", name, base)
	}
	if !cloudmanager.MatchesRequestedName(name, "k8s-a-c1", false) {
		t.Fatalf("the client does not recognise %q as its requested name", name)
	}
	b, err := c.FindByBucket(ctx, "tenant-a", name)
	if err != nil {
		t.Fatalf("find own: %v", err)
	}
	if b.Status != cloudmanager.StatusRunning || b.AccessKey != credA.AccessKey || b.SecretKey != credA.SecretKey ||
		b.ManagedBy != cloudmanager.ManagedBySystem {
		t.Fatalf("own bucket = %+v", b)
	}
	if !rs.s3.hasBucket(name) {
		t.Fatal("bucket not provisioned on the S3 server")
	}
	return name
}

// checkRepeatCreate — повторный заказ: суффикс, оба видны поиском по
// запрошенному имени. Возвращает имя суффиксного бакета.
func checkRepeatCreate(ctx context.Context, t *testing.T, c *cloudmanager.Client, base string) string {
	t.Helper()
	second, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-c1"))
	if err != nil || second != base+"-1" {
		t.Fatalf("repeat create = %q, %v; want %q", second, err, base+"-1")
	}
	found, err := c.FindByRequested(ctx, "tenant-a", "k8s-a-c1", true)
	if err != nil || len(found) != 2 || found[0].Name != base || found[1].Name != base+"-1" {
		t.Fatalf("FindByRequested = %+v, %v", found, err)
	}
	return second
}

// checkForeignTenant — арендатор B чужого бакета не получает: клиент видит
// чужого владельца.
func checkForeignTenant(ctx context.Context, t *testing.T, c *cloudmanager.Client, name string) {
	t.Helper()
	if _, err := c.FindByBucket(ctx, "tenant-b", name); !errors.Is(err, cloudmanager.ErrForeignBucket) {
		t.Fatalf("tenant-b find of tenant-a bucket: %v, want ErrForeignBucket", err)
	}
	if got, err := c.FindByRequested(ctx, "tenant-b", "k8s-a-c1", true); err != nil || len(got) != 0 {
		t.Fatalf("tenant-b FindByRequested = %+v, %v; want none", got, err)
	}
}

// checkLimit — лимит tenant-a — 2: третий заказ — тот же отказ, что у
// настоящей службы.
func checkLimit(ctx context.Context, t *testing.T, c *cloudmanager.Client) {
	t.Helper()
	_, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-c2"))
	if !errors.Is(err, cloudmanager.ErrBucketLimitReached) {
		t.Fatalf("over the limit: %v, want ErrBucketLimitReached", err)
	}
}

// checkRemove — удаление: REMOVING → REMOVED, бакет снят с S3-сервера,
// повтор — «уже снят», отсутствующий — «не найден», снятый бакет место
// освободил.
func checkRemove(ctx context.Context, t *testing.T, rs *runningService, c *cloudmanager.Client, second string) {
	t.Helper()
	if err := c.Remove(ctx, second); err != nil {
		t.Fatalf("remove: %v", err)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := rs.store.WaitRemovals(wctx); err != nil {
		t.Fatalf("WaitRemovals: %v", err)
	}
	gone, err := c.FindByBucket(ctx, "tenant-a", second)
	if err != nil || gone.Status != cloudmanager.StatusRemoved {
		t.Fatalf("after removal: %+v, %v", gone, err)
	}
	if rs.s3.hasBucket(second) {
		t.Fatal("bucket still on the S3 server")
	}
	if err := c.Remove(ctx, second); !errors.Is(err, cloudmanager.ErrAlreadyRemoved) {
		t.Fatalf("remove again: %v, want ErrAlreadyRemoved", err)
	}
	if err := c.Remove(ctx, "never-existed"); !errors.Is(err, cloudmanager.ErrBucketNotFound) {
		t.Fatalf("remove absent: %v, want ErrBucketNotFound", err)
	}
	// Снятый бакет место освободил.
	if _, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-c2")); err != nil {
		t.Fatalf("create after removal: %v", err)
	}
}

// checkUnknownLogin — неизвестный логин — ошибка gRPC с кодом INTERNAL, как у
// настоящей службы (поиск клиента идёт вне перехвата ошибок S3), а не ответ
// s3_error.
func checkUnknownLogin(ctx context.Context, t *testing.T, c *cloudmanager.Client) {
	t.Helper()
	_, err := c.Create(ctx, systemCreate("nobody", "k8s-x"))
	if status.Code(errors.Unwrap(err)) != codes.Internal {
		t.Fatalf("unknown login: %v, want gRPC INTERNAL", err)
	}
	for _, sentinel := range []error{cloudmanager.ErrCreateRejected, cloudmanager.ErrBucketLimitReached,
		cloudmanager.ErrConfigurationNotFound, cloudmanager.ErrInvalidBucketName} {
		if errors.Is(err, sentinel) {
			t.Fatalf("unknown login mapped to %v", sentinel)
		}
	}
}

// checkCreateCodes — неизвестная конфигурация и недопустимое имя — коды
// ответа create.
func checkCreateCodes(ctx context.Context, t *testing.T, c *cloudmanager.Client) {
	t.Helper()
	in := systemCreate("tenant-b", "k8s-b-c1")
	in.ConfigurationID = "s3_v9"
	if _, err := c.Create(ctx, in); !errors.Is(err, cloudmanager.ErrConfigurationNotFound) {
		t.Fatalf("unknown configuration: %v", err)
	}
	if _, err := c.Create(ctx, systemCreate("tenant-b", "bad--name")); !errors.Is(err, cloudmanager.ErrInvalidBucketName) {
		t.Fatalf("invalid name: %v", err)
	}
}

// Служба отвечает на проверку здоровья gRPC — по ней стенд судит готовность.
func TestIntegration_HealthIsServing(t *testing.T) {
	rs := startService(t)
	conn, err := grpc.NewClient(rs.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v", resp, err)
	}
}
