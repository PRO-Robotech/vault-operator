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
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Режим ключей «на бакет» (bucketKeys: bucket) повторяет настоящую службу:
// у каждого бакета — своя пара ключей S3, и ключи одного бакета не открывают
// другой бакет того же логина. Пробы ниже краснеют на двойнике, отдающем всем
// бакетам логина ключи логина.

var credAdmin = Credentials{AccessKey: "ak-admin", SecretKey: "sk-admin"}

// usersBackend — подставное хранилище с вопросами администратора: заведение и
// снятие пользователя пишутся в общий журнал вызовов рядом с бакетами.
type usersBackend struct {
	*fakeBackend
	umu            sync.Mutex
	createUserErrs []error
}

func (b *usersBackend) CreateUser(_ context.Context, cred Credentials) error {
	b.mu.Lock()
	b.calls = append(b.calls, backendCall{op: "create-user", cred: cred})
	b.mu.Unlock()
	b.umu.Lock()
	defer b.umu.Unlock()
	if len(b.createUserErrs) > 0 {
		err := b.createUserErrs[0]
		b.createUserErrs = b.createUserErrs[1:]
		return err
	}
	return nil
}

func (b *usersBackend) DeleteUser(_ context.Context, accessKey string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, backendCall{op: "delete-user", cred: Credentials{AccessKey: accessKey}})
	return nil
}

func (b *usersBackend) ops() []backendCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]backendCall(nil), b.calls...)
}

func bucketKeysStoreConfig() StoreConfig {
	cfg := testStoreConfig()
	cfg.BucketKeys = BucketKeysPerBucket
	return cfg
}

// Два бакета одного логина получают разные пары ключей, и ни одна не равна
// ключам логина; пользователь хранилища заводится раньше бакета и ровно теми
// ключами, которыми бакет заводится. Снятие — бакет его ключами, затем его
// пользователь.
func TestStore_BucketKeysGiveEachBucketItsOwnUser(t *testing.T) {
	be := &usersBackend{fakeBackend: &fakeBackend{}}
	s := newTestStore(t, bucketKeysStoreConfig(), be)
	ctx := context.Background()

	one, err := s.Create(ctx, createIn("tenant-a", "one"))
	if err != nil {
		t.Fatalf("Create one: %v", err)
	}
	two, err := s.Create(ctx, createIn("tenant-a", "two"))
	if err != nil {
		t.Fatalf("Create two: %v", err)
	}
	k1 := Credentials{AccessKey: one.AccessKey, SecretKey: one.SecretKey}
	k2 := Credentials{AccessKey: two.AccessKey, SecretKey: two.SecretKey}
	if k1.AccessKey == "" || k1.SecretKey == "" || k2.AccessKey == "" || k2.SecretKey == "" {
		t.Fatalf("empty bucket keys: %+v %+v", k1, k2)
	}
	if k1 == credA || k2 == credA || k1.AccessKey == credA.AccessKey || k2.AccessKey == credA.AccessKey {
		t.Fatalf("a bucket carries the login keys: %+v %+v", k1, k2)
	}
	if k1.AccessKey == k2.AccessKey || k1.SecretKey == k2.SecretKey {
		t.Fatalf("two buckets of one login share a key: %+v %+v", k1, k2)
	}
	ops := be.ops()
	want := []backendCall{
		{op: "create-user", cred: k1}, {op: "create", cred: k1, bucket: one.Name},
		{op: "create-user", cred: k2}, {op: "create", cred: k2, bucket: two.Name},
	}
	if len(ops) != len(want) {
		t.Fatalf("backend calls = %+v, want %+v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("backend call %d = %+v, want %+v", i, ops[i], want[i])
		}
	}
	// findAll отдаёт ключи бакета, а не логина.
	got := s.FindAll([]Scope{{Names: []string{one.Name}}})
	if len(got) != 1 || got[0].AccessKey != k1.AccessKey || got[0].SecretKey != k1.SecretKey {
		t.Fatalf("findAll = %+v, want keys of bucket one", got)
	}

	if msg, err := s.Remove(one.Name); err != nil || msg != "" {
		t.Fatalf("Remove = %q, %v", msg, err)
	}
	waitRemovals(t, s)
	ops = be.ops()[len(want):]
	wantRm := []backendCall{{op: "delete", cred: k1, bucket: one.Name}, {op: "delete-user", cred: Credentials{AccessKey: k1.AccessKey}}}
	if len(ops) != 2 || ops[0] != wantRm[0] || ops[1] != wantRm[1] {
		t.Fatalf("removal calls = %+v, want %+v", ops, wantRm)
	}
}

// Близнец режима: ключи логина (умолчание) — бакет несёт ключи арендатора,
// вопросов администратора нет.
func TestStore_LoginKeysModeAsksNoAdmin(t *testing.T) {
	be := &usersBackend{fakeBackend: &fakeBackend{}}
	s := newTestStore(t, testStoreConfig(), be)
	b, err := s.Create(context.Background(), createIn("tenant-a", "one"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if b.AccessKey != credA.AccessKey || b.SecretKey != credA.SecretKey {
		t.Fatalf("keys = %q/%q, want the login keys", b.AccessKey, b.SecretKey)
	}
	for _, c := range be.ops() {
		if c.op == "create-user" || c.op == "delete-user" {
			t.Fatalf("login mode asked the admin: %+v", c)
		}
	}
}

// Неудачное заведение бакета не оставляет пользователя: он снимается тем же
// заходом, строка не остаётся.
func TestStore_BucketKeysFailedProvisioningLeavesNoUser(t *testing.T) {
	be := &usersBackend{fakeBackend: &fakeBackend{createErrs: []error{errors.New("boom")}}}
	s := newTestStore(t, bucketKeysStoreConfig(), be)

	_, err := s.Create(context.Background(), createIn("tenant-a", "one"))
	wantCreateCode(t, err, CodeReserved)
	ops := be.ops()
	if len(ops) != 3 || ops[0].op != "create-user" || ops[1].op != "create" || ops[2].op != "delete-user" ||
		ops[2].cred.AccessKey != ops[0].cred.AccessKey {
		t.Fatalf("calls = %+v, want create-user, create, delete-user of the same key", ops)
	}
	if got := s.FindAll(nil); len(got) != 0 {
		t.Fatalf("buckets = %+v, want none", got)
	}
}

// Отказ заведения пользователя — отказ create без обращения за бакетом.
func TestStore_BucketKeysUserRefusalCreatesNoBucket(t *testing.T) {
	be := &usersBackend{fakeBackend: &fakeBackend{}, createUserErrs: []error{errors.New("refused")}}
	s := newTestStore(t, bucketKeysStoreConfig(), be)

	_, err := s.Create(context.Background(), createIn("tenant-a", "one"))
	wantCreateCode(t, err, CodeReserved)
	if got := be.callsOf("create"); len(got) != 0 {
		t.Fatalf("bucket created after the user was refused: %+v", got)
	}
	if got := s.FindAll(nil); len(got) != 0 {
		t.Fatalf("buckets = %+v, want none", got)
	}
}

// Режим ключей на бакет без хранилища с вопросами администратора — отказ
// старта, а не тихий откат к ключам логина.
func TestNewStore_BucketKeysNeedAnAdminBackend(t *testing.T) {
	_, err := NewStore(bucketKeysStoreConfig(), &fakeBackend{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "bucketKeys") {
		t.Fatalf("NewStore = %v, want a refusal naming bucketKeys", err)
	}
	cfg := testStoreConfig()
	cfg.BucketKeys = "nonsense"
	if _, err := NewStore(cfg, &usersBackend{fakeBackend: &fakeBackend{}},
		slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("an unknown bucketKeys mode is accepted")
	}
}

// Вопросы администратора: заведение пользователя — PATCH /create-user с телом
// XML учётной записи, подписанным ключами администратора вместе с хешем тела;
// снятие — PATCH /delete-user?access=. Ключи арендатора администратором не
// являются.
func TestS3Backend_AdminCreatesAndDeletesAUser(t *testing.T) {
	st := newS3Stub(t, credA, credAdmin)
	st.admin = credAdmin.AccessKey
	endpoint, caFile := startS3Stub(t, st)
	ctx := context.Background()
	newBE := func(admin *Credentials) *S3Backend {
		be, err := NewS3Backend(S3Config{Endpoint: endpoint, SigningRegion: "us-east-1", CAFile: caFile,
			RequestTimeout: 5 * time.Second, Admin: admin})
		if err != nil {
			t.Fatalf("NewS3Backend: %v", err)
		}
		return be
	}
	be := newBE(&credAdmin)
	user := Credentials{AccessKey: "ak-bucket-1", SecretKey: "sk-bucket-1"}

	if err := be.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if role := st.roleOf(user.AccessKey); role != "userplus" {
		t.Fatalf("role of the new user = %q, want userplus", role)
	}
	if err := be.CreateBucket(ctx, user, "aa-one"); err != nil {
		t.Fatalf("the new user cannot create its bucket: %v", err)
	}
	if err := be.DeleteBucket(ctx, user, "aa-one"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if err := be.DeleteUser(ctx, user.AccessKey); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if st.roleOf(user.AccessKey) != "" {
		t.Fatal("the user is still on the server")
	}
	// Ключи арендатора вопросов администратора не задают.
	tenantBE := newBE(&credA)
	if err := tenantBE.CreateUser(ctx, user); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("tenant keys as admin: %v, want AccessDenied", err)
	}
	// Хранилище без ключей администратора — отказ, а не запрос без подписи.
	if err := newBE(nil).CreateUser(ctx, user); err == nil {
		t.Fatal("CreateUser without admin keys succeeded")
	}
}

// Конфиг: bucketKeys: bucket требует ключи администратора хранилища файлами;
// без них, с неизвестным режимом и с ключами администратора в режиме логина —
// отказ старта.
func TestLoadConfig_BucketKeys(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "admin/accessKey", "ak-admin\n")
	writeFile(t, dir, "admin/secretKey", "sk-admin")
	admin := "  adminAccessKeyFile: " + filepath.Join(dir, "admin/accessKey") + "\n" +
		"  adminSecretKeyFile: " + filepath.Join(dir, "admin/secretKey") + "\n"
	withS3 := func(y, extra string) string {
		return strings.Replace(y, "  requestTimeout: 20s\n", "  requestTimeout: 20s\n"+extra, 1)
	}

	y := "bucketKeys: bucket\n" + withS3(configYAML(t, dir), admin)
	cfg, err := LoadConfig(writeFile(t, dir, "ok.yaml", y))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Store.BucketKeys != BucketKeysPerBucket || cfg.S3.Admin == nil || *cfg.S3.Admin != credAdmin {
		t.Fatalf("bucket keys = %q, admin = %+v", cfg.Store.BucketKeys, cfg.S3.Admin)
	}
	// Близнец: без поля — ключи логина, администратора нет.
	cfg, err = LoadConfig(writeFile(t, dir, "default.yaml", configYAML(t, dir)))
	if err != nil || cfg.Store.BucketKeys != BucketKeysPerLogin || cfg.S3.Admin != nil {
		t.Fatalf("default: %v, %+v", err, cfg)
	}
	for name, body := range map[string]string{
		"no-admin":   "bucketKeys: bucket\n" + configYAML(t, dir),
		"half-admin": "bucketKeys: bucket\n" + withS3(configYAML(t, dir), "  adminAccessKeyFile: "+filepath.Join(dir, "admin/accessKey")+"\n"),
		"unknown":    "bucketKeys: order\n" + withS3(configYAML(t, dir), admin),
		"login-adm":  "bucketKeys: login\n" + withS3(configYAML(t, dir), admin),
	} {
		if _, err := LoadConfig(writeFile(t, dir, name+".yaml", body)); err == nil {
			t.Errorf("%s: config accepted", name)
		} else if strings.Contains(err.Error(), "sk-admin") || strings.Contains(err.Error(), "ak-admin") {
			t.Errorf("%s: refusal prints a key: %v", name, err)
		}
	}
}

// Служба целиком, настоящий клиент оператора: два заказа одного логина —
// разные ключи, и ключи второго бакета на листинг первого получают
// AccessDenied, а свой бакет листают (близнец). На двойнике с ключами логина
// листинг чужого бакета проходит — проба красная.
func TestIntegration_BucketKeysIsolateBucketsOfOneLogin(t *testing.T) {
	rs := startServiceWith(t, func(dir, y string) string {
		writeFile(t, dir, "admin/accessKey", credAdmin.AccessKey)
		writeFile(t, dir, "admin/secretKey", credAdmin.SecretKey)
		return "bucketKeys: bucket\n" + strings.Replace(y, "  requestTimeout: 20s\n", "  requestTimeout: 20s\n"+
			"  adminAccessKeyFile: "+filepath.Join(dir, "admin/accessKey")+"\n"+
			"  adminSecretKeyFile: "+filepath.Join(dir, "admin/secretKey")+"\n", 1)
	})
	c := newRealClient(t, rs.addr)
	ctx := context.Background()

	n1, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-r"))
	if err != nil {
		t.Fatalf("create R: %v", err)
	}
	n2, err := c.Create(ctx, systemCreate("tenant-a", "k8s-a-s"))
	if err != nil {
		t.Fatalf("create S: %v", err)
	}
	r, err := c.FindByBucket(ctx, "tenant-a", n1)
	if err != nil {
		t.Fatalf("find R: %v", err)
	}
	s, err := c.FindByBucket(ctx, "tenant-a", n2)
	if err != nil {
		t.Fatalf("find S: %v", err)
	}
	if r.AccessKey == s.AccessKey || r.AccessKey == credA.AccessKey || s.AccessKey == credA.AccessKey {
		t.Fatalf("keys R %q, S %q, login %q: want three different keys", r.AccessKey, s.AccessKey, credA.AccessKey)
	}
	keysS := Credentials{AccessKey: s.AccessKey, SecretKey: s.SecretKey}
	if code, s3code := rs.list(t, keysS, n2); code != http.StatusOK {
		t.Fatalf("S lists its own bucket: %d %s, want 200", code, s3code)
	}
	if code, s3code := rs.list(t, keysS, n1); code != http.StatusForbidden || s3code != "AccessDenied" {
		t.Fatalf("S lists the bucket of R: %d %s, want 403 AccessDenied", code, s3code)
	}
}
