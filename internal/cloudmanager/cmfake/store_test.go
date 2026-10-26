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
	"sync"
	"testing"
	"time"
)

// backendCall — один вызов хранилища S3 двойником.
type backendCall struct {
	op     string
	cred   Credentials
	bucket string
}

// fakeBackend — подставное хранилище S3: записывает вызовы, отдаёт заданные
// ошибки по одной на вызов, по желанию держит удаление до отмены контекста.
type fakeBackend struct {
	mu         sync.Mutex
	calls      []backendCall
	createErrs []error
	deleteErrs []error
	// holdDelete держит DeleteBucket, пока контекст не отменён.
	holdDelete bool
	// deleteEntered закрывается при первом входе в DeleteBucket.
	deleteEntered chan struct{}
	enteredOnce   sync.Once
}

func (b *fakeBackend) CreateBucket(_ context.Context, cred Credentials, bucket string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, backendCall{op: "create", cred: cred, bucket: bucket})
	if len(b.createErrs) > 0 {
		err := b.createErrs[0]
		b.createErrs = b.createErrs[1:]
		return err
	}
	return nil
}

func (b *fakeBackend) DeleteBucket(ctx context.Context, cred Credentials, bucket string) error {
	b.mu.Lock()
	b.calls = append(b.calls, backendCall{op: "delete", cred: cred, bucket: bucket})
	hold := b.holdDelete
	var injected error
	if len(b.deleteErrs) > 0 {
		injected = b.deleteErrs[0]
		b.deleteErrs = b.deleteErrs[1:]
	}
	b.mu.Unlock()
	if b.deleteEntered != nil {
		b.enteredOnce.Do(func() { close(b.deleteEntered) })
	}
	if hold {
		<-ctx.Done()
		return ctx.Err()
	}
	return injected
}

func (b *fakeBackend) callsOf(op string) []backendCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []backendCall
	for _, c := range b.calls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

var (
	credA = Credentials{AccessKey: "ak-tenant-a", SecretKey: "sk-tenant-a"}
	credB = Credentials{AccessKey: "ak-tenant-b", SecretKey: "sk-tenant-b"}
)

func testStoreConfig() StoreConfig {
	return StoreConfig{
		DefaultRegion:    "ru1",
		Configurations:   []Configuration{{ID: "s3_v1", Region: "ru1"}},
		BucketFqdnSuffix: "s3.stand.test",
		Clients: []ClientConfig{
			{Login: "tenant-a", MaxBuckets: 3, Credentials: credA},
			{Login: "tenant-b", MaxBuckets: 3, Credentials: credB},
		},
		BackendTimeout:   5 * time.Second,
		RemoveAttempts:   3,
		RemoveRetryDelay: time.Millisecond,
	}
}

func newTestStore(t *testing.T, cfg StoreConfig, be Backend) *Store {
	t.Helper()
	s, err := NewStore(cfg, be, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func createIn(login, name string) CreateInput {
	return CreateInput{Login: login, ConfigurationID: "s3_v1", Region: "ru1", BucketName: name, ManagedBy: ManagedBySystem}
}

func wantCreateCode(t *testing.T, err error, code CreateCode) {
	t.Helper()
	var ce *CreateError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CreateError with code %v", err, code)
	}
	if ce.Code != code {
		t.Fatalf("code = %v (%q), want %v", ce.Code, ce.Message, code)
	}
}

func waitRemovals(t *testing.T, s *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.WaitRemovals(ctx); err != nil {
		t.Fatalf("WaitRemovals: %v", err)
	}
}

// Заказ даёт серверное имя «префикс логина-запрошенное», статус RUNNING, ключи
// своего клиента из конфига, и заводит бакет в хранилище этими ключами.
func TestStore_CreateNamesTheBucketAndProvisionsItWithTheClientKeys(t *testing.T) {
	be := &fakeBackend{}
	s := newTestStore(t, testStoreConfig(), be)

	b, err := s.Create(context.Background(), createIn("tenant-a", "k8s-a-c1"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := Prefix("tenant-a") + "-k8s-a-c1"
	if b.Name != want {
		t.Fatalf("name = %q, want %q", b.Name, want)
	}
	if b.Status != StatusRunning || b.CustLogin != "tenant-a" || b.ManagedBy != ManagedBySystem {
		t.Fatalf("bucket = %+v", b)
	}
	if b.AccessKey != credA.AccessKey || b.SecretKey != credA.SecretKey {
		t.Fatalf("keys = %q/%q, want tenant-a keys", b.AccessKey, b.SecretKey)
	}
	if b.Fqdn != want+".s3.stand.test" {
		t.Fatalf("fqdn = %q", b.Fqdn)
	}
	if b.ServiceID == "" {
		t.Fatal("service id is empty")
	}
	created := be.callsOf("create")
	if len(created) != 1 || created[0].bucket != want || created[0].cred != credA {
		t.Fatalf("backend creates = %+v, want one of %q with tenant-a keys", created, want)
	}
	// Близнец: второй арендатор получает свои ключи, а не ключи первого.
	bb, err := s.Create(context.Background(), createIn("tenant-b", "k8s-b-c1"))
	if err != nil {
		t.Fatalf("Create tenant-b: %v", err)
	}
	if bb.AccessKey != credB.AccessKey || bb.SecretKey != credB.SecretKey {
		t.Fatalf("tenant-b keys = %q/%q", bb.AccessKey, bb.SecretKey)
	}
}

// Повторный заказ того же имени — суффикс «-N», а не отказ; занятым считается
// имя в любом статусе, REMOVED тоже.
func TestStore_RepeatedCreateGetsASuffixAndRemovedNamesStayTaken(t *testing.T) {
	be := &fakeBackend{}
	s := newTestStore(t, testStoreConfig(), be)
	base := Prefix("tenant-a") + "-k8s-a-c1"

	first, err := s.Create(context.Background(), createIn("tenant-a", "k8s-a-c1"))
	if err != nil || first.Name != base {
		t.Fatalf("first = %q, %v", first.Name, err)
	}
	second, err := s.Create(context.Background(), createIn("tenant-a", "k8s-a-c1"))
	if err != nil || second.Name != base+"-1" {
		t.Fatalf("second = %q, %v; want %q", second.Name, err, base+"-1")
	}
	if msg, err := s.Remove(second.Name); err != nil || msg != "" {
		t.Fatalf("Remove = %q, %v", msg, err)
	}
	waitRemovals(t, s)
	third, err := s.Create(context.Background(), createIn("tenant-a", "k8s-a-c1"))
	if err != nil || third.Name != base+"-2" {
		t.Fatalf("third = %q, %v; want %q (the REMOVED -1 stays taken)", third.Name, err, base+"-2")
	}
}

// Потолок считает живые бакеты логина; REMOVED в счёт не идёт, чужой логин —
// тоже.
func TestStore_LimitCountsTheLoginsLiveBuckets(t *testing.T) {
	cfg := testStoreConfig()
	cfg.Clients[0].MaxBuckets = 2
	s := newTestStore(t, cfg, &fakeBackend{})

	one, err := s.Create(context.Background(), createIn("tenant-a", "one"))
	if err != nil {
		t.Fatalf("one: %v", err)
	}
	if _, err := s.Create(context.Background(), createIn("tenant-a", "two")); err != nil {
		t.Fatalf("two: %v", err)
	}
	_, err = s.Create(context.Background(), createIn("tenant-a", "three"))
	wantCreateCode(t, err, CodeBucketLimitReached)
	if !strings.Contains(err.Error(), "Maximum number of buckets reached") {
		t.Fatalf("message = %q", err.Error())
	}
	// Чужой логин потолком первого не задет.
	if _, err := s.Create(context.Background(), createIn("tenant-b", "three")); err != nil {
		t.Fatalf("tenant-b: %v", err)
	}
	// Снятый бакет место освобождает.
	if _, err := s.Remove(one.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitRemovals(t, s)
	if _, err := s.Create(context.Background(), createIn("tenant-a", "three")); err != nil {
		t.Fatalf("after removal: %v", err)
	}
}

// Неизвестный логин — отказ до любой работы: строки нет, хранилище не тронуто.
func TestStore_UnknownLoginIsRefusedBeforeAnyWork(t *testing.T) {
	be := &fakeBackend{}
	s := newTestStore(t, testStoreConfig(), be)

	_, err := s.Create(context.Background(), createIn("nobody", "k8s-x"))
	if !errors.Is(err, ErrUnknownCustomer) {
		t.Fatalf("err = %v, want ErrUnknownCustomer", err)
	}
	if got := s.FindAll(nil); len(got) != 0 {
		t.Fatalf("buckets = %+v, want none", got)
	}
	if got := be.callsOf("create"); len(got) != 0 {
		t.Fatalf("backend creates = %+v, want none", got)
	}
}

// Конфигурация ищется по паре (id, регион); пустой регион — регион по
// умолчанию.
func TestStore_ConfigurationIsMatchedByIDAndRegion(t *testing.T) {
	s := newTestStore(t, testStoreConfig(), &fakeBackend{})

	in := createIn("tenant-a", "c1")
	in.ConfigurationID = "s3_v2"
	_, err := s.Create(context.Background(), in)
	wantCreateCode(t, err, CodeConfigurationNotFound)

	in = createIn("tenant-a", "c2")
	in.Region = "ru2"
	_, err = s.Create(context.Background(), in)
	wantCreateCode(t, err, CodeConfigurationNotFound)

	in = createIn("tenant-a", "c3")
	in.Region = ""
	if _, err := s.Create(context.Background(), in); err != nil {
		t.Fatalf("default region: %v", err)
	}
}

// Правила имени: латиница, цифры, «-», не в начале и не в конце, не дважды
// подряд; полное серверное имя не длиннее 63.
func TestStore_InvalidBucketNamesAreRefused(t *testing.T) {
	s := newTestStore(t, testStoreConfig(), &fakeBackend{})
	long := strings.Repeat("a", 63-len(Prefix("tenant-a"))) // с «-» префикса — 64
	for _, name := range []string{"", "-a", "a-", "a--b", "a_b", "a.b", "ы", long} {
		_, err := s.Create(context.Background(), createIn("tenant-a", name))
		wantCreateCode(t, err, CodeInvalidBucketName)
	}
	// Близнец: допустимое имя предельной длины проходит.
	ok := strings.Repeat("a", 62-len(Prefix("tenant-a")))
	if _, err := s.Create(context.Background(), createIn("tenant-a", ok)); err != nil {
		t.Fatalf("valid name of 63: %v", err)
	}
}

// Отказ хранилища — ответ create с кодом CODE_RESERVED, строка не остаётся и
// места под потолком не занимает.
func TestStore_BackendFailureAnswersReservedAndKeepsNoRow(t *testing.T) {
	cfg := testStoreConfig()
	cfg.Clients[0].MaxBuckets = 1
	be := &fakeBackend{createErrs: []error{errors.New("storage down")}}
	s := newTestStore(t, cfg, be)

	_, err := s.Create(context.Background(), createIn("tenant-a", "c1"))
	wantCreateCode(t, err, CodeReserved)
	if got := s.FindAll(nil); len(got) != 0 {
		t.Fatalf("buckets = %+v, want none", got)
	}
	b, err := s.Create(context.Background(), createIn("tenant-a", "c1"))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if b.Name != Prefix("tenant-a")+"-c1" {
		t.Fatalf("retry name = %q, the failed row must not have taken the name", b.Name)
	}
}

// Поиск: области через И, значения внутри области через ИЛИ, без области —
// всё, REMOVED возвращается тоже.
func TestStore_FindAllScopes(t *testing.T) {
	s := newTestStore(t, testStoreConfig(), &fakeBackend{})
	a1, _ := s.Create(context.Background(), createIn("tenant-a", "x1"))
	a2, _ := s.Create(context.Background(), createIn("tenant-a", "x2"))
	b1, _ := s.Create(context.Background(), createIn("tenant-b", "x1"))
	if _, err := s.Remove(a2.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitRemovals(t, s)

	names := func(bs []Bucket) []string {
		out := make([]string, 0, len(bs))
		for _, b := range bs {
			out = append(out, b.Name)
		}
		return out
	}
	cases := []struct {
		name   string
		scopes []Scope
		want   []string
	}{
		{"none", nil, []string{a1.Name, a2.Name, b1.Name}},
		{"login", []Scope{{Logins: []string{"tenant-a"}}}, []string{a1.Name, a2.Name}},
		{"logins or", []Scope{{Logins: []string{"tenant-a", "tenant-b"}}}, []string{a1.Name, a2.Name, b1.Name}},
		{"name", []Scope{{Names: []string{b1.Name}}}, []string{b1.Name}},
		{"and", []Scope{{Logins: []string{"tenant-a"}}, {Names: []string{b1.Name}}}, []string{}},
		{"and hit", []Scope{{Logins: []string{"tenant-b"}}, {Names: []string{b1.Name, a1.Name}}}, []string{b1.Name}},
		{"empty scope", []Scope{{}}, []string{}},
	}
	for _, tc := range cases {
		got := names(s.FindAll(tc.scopes))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	for _, b := range s.FindAll([]Scope{{Names: []string{a2.Name}}}) {
		if b.Status != StatusRemoved {
			t.Fatalf("removed bucket status = %v", b.Status)
		}
	}
}

// Удаление: «Not found» для никогда не бывшего, REMOVING → REMOVED асинхронно
// ключами владельца, затем «Already removed».
func TestStore_RemoveLifecycle(t *testing.T) {
	be := &fakeBackend{}
	s := newTestStore(t, testStoreConfig(), be)

	if msg, err := s.Remove("never-existed"); err != nil || msg != RemoveMsgNotFound {
		t.Fatalf("absent: %q, %v", msg, err)
	}
	b, _ := s.Create(context.Background(), createIn("tenant-b", "gone"))
	if msg, err := s.Remove(b.Name); err != nil || msg != "" {
		t.Fatalf("Remove: %q, %v", msg, err)
	}
	waitRemovals(t, s)
	got := s.FindAll([]Scope{{Names: []string{b.Name}}})
	if len(got) != 1 || got[0].Status != StatusRemoved {
		t.Fatalf("after removal: %+v", got)
	}
	deleted := be.callsOf("delete")
	if len(deleted) != 1 || deleted[0].bucket != b.Name || deleted[0].cred != credB {
		t.Fatalf("backend deletes = %+v, want one of %q with tenant-b keys", deleted, b.Name)
	}
	if msg, err := s.Remove(b.Name); err != nil || msg != RemoveMsgAlreadyRemoved {
		t.Fatalf("again: %q, %v", msg, err)
	}
}

// Пока идёт удаление, бакет виден REMOVING, повторный вызов принимается и
// второго удаления в хранилище не заводит.
func TestStore_RemovingIsVisibleAndARepeatDoesNotRequeue(t *testing.T) {
	be := &fakeBackend{holdDelete: true, deleteEntered: make(chan struct{})}
	s := newTestStore(t, testStoreConfig(), be)
	b, _ := s.Create(context.Background(), createIn("tenant-a", "slow"))

	if _, err := s.Remove(b.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	<-be.deleteEntered
	got := s.FindAll([]Scope{{Names: []string{b.Name}}})
	if len(got) != 1 || got[0].Status != StatusRemoving {
		t.Fatalf("during removal: %+v", got)
	}
	if msg, err := s.Remove(b.Name); err != nil || msg != "" {
		t.Fatalf("repeat: %q, %v", msg, err)
	}
	s.Close()
	if n := len(be.callsOf("delete")); n != 1 {
		t.Fatalf("backend deletes = %d, want 1", n)
	}
}

// Сбой хранилища при удалении повторяется; исчерпав попытки, бакет уходит в
// ERROR, а не остаётся REMOVING навсегда.
func TestStore_RemovalRetriesThenErrors(t *testing.T) {
	be := &fakeBackend{deleteErrs: []error{errors.New("t1"), errors.New("t2")}}
	s := newTestStore(t, testStoreConfig(), be)
	ok, _ := s.Create(context.Background(), createIn("tenant-a", "retried"))
	if _, err := s.Remove(ok.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitRemovals(t, s)
	if got := s.FindAll([]Scope{{Names: []string{ok.Name}}}); got[0].Status != StatusRemoved {
		t.Fatalf("after two failures and a success: %v", got[0].Status)
	}

	be.mu.Lock()
	be.deleteErrs = []error{errors.New("f1"), errors.New("f2"), errors.New("f3")}
	be.mu.Unlock()
	bad, _ := s.Create(context.Background(), createIn("tenant-a", "stuck"))
	if _, err := s.Remove(bad.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	waitRemovals(t, s)
	if got := s.FindAll([]Scope{{Names: []string{bad.Name}}}); got[0].Status != StatusError {
		t.Fatalf("after %d failures: %v, want ERROR", 3, got[0].Status)
	}
}

// Параллельные заказы одного имени получают разные имена.
func TestStore_ConcurrentCreatesGetDistinctNames(t *testing.T) {
	cfg := testStoreConfig()
	const n = 16
	cfg.Clients[0].MaxBuckets = n
	s := newTestStore(t, cfg, &fakeBackend{})

	var wg sync.WaitGroup
	names := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := s.Create(context.Background(), createIn("tenant-a", "same"))
			names[i], errs[i] = b.Name, err
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("create %d: %v", i, errs[i])
		}
		if seen[names[i]] {
			t.Fatalf("name %q handed out twice", names[i])
		}
		seen[names[i]] = true
	}
	// Близнец: сверх потолка — отказ, а не лишний бакет.
	_, err := s.Create(context.Background(), createIn("tenant-a", "same"))
	wantCreateCode(t, err, CodeBucketLimitReached)
}

// Close дожидается начатых удалений (отменив их) и отвергает новые.
func TestStore_CloseDrainsRemovalsAndRefusesNewOnes(t *testing.T) {
	be := &fakeBackend{holdDelete: true, deleteEntered: make(chan struct{})}
	s := newTestStore(t, testStoreConfig(), be)
	b1, _ := s.Create(context.Background(), createIn("tenant-a", "b1"))
	b2, _ := s.Create(context.Background(), createIn("tenant-a", "b2"))
	if _, err := s.Remove(b1.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	<-be.deleteEntered

	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return: the in-flight removal was not cancelled")
	}
	if _, err := s.Remove(b2.Name); !errors.Is(err, ErrStopped) {
		t.Fatalf("Remove after Close: %v, want ErrStopped", err)
	}
	if _, err := s.Create(context.Background(), createIn("tenant-a", "b3")); !errors.Is(err, ErrStopped) {
		t.Fatalf("Create after Close: %v, want ErrStopped", err)
	}
}

// Конфиг без клиентов, с повтором логина или с общими ключами двух арендаторов
// не принимается.
func TestNewStore_RefusesAnUnsafeConfig(t *testing.T) {
	mut := map[string]func(*StoreConfig){
		"no clients":         func(c *StoreConfig) { c.Clients = nil },
		"no configurations":  func(c *StoreConfig) { c.Configurations = nil },
		"duplicate login":    func(c *StoreConfig) { c.Clients[1].Login = c.Clients[0].Login },
		"empty login":        func(c *StoreConfig) { c.Clients[0].Login = "" },
		"shared access key":  func(c *StoreConfig) { c.Clients[1].Credentials.AccessKey = credA.AccessKey },
		"empty secret key":   func(c *StoreConfig) { c.Clients[0].Credentials.SecretKey = "" },
		"zero limit":         func(c *StoreConfig) { c.Clients[0].MaxBuckets = 0 },
		"no fqdn suffix":     func(c *StoreConfig) { c.BucketFqdnSuffix = "" },
		"no default region":  func(c *StoreConfig) { c.DefaultRegion = "" },
		"zero attempts":      func(c *StoreConfig) { c.RemoveAttempts = 0 },
		"zero backend limit": func(c *StoreConfig) { c.BackendTimeout = 0 },
	}
	for name, m := range mut {
		cfg := testStoreConfig()
		m(&cfg)
		if _, err := NewStore(cfg, &fakeBackend{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewStore(testStoreConfig(), nil, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("nil backend: accepted")
	}
	// Близнец: исходный конфиг принимается.
	s, err := NewStore(testStoreConfig(), &fakeBackend{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	s.Close()
}
