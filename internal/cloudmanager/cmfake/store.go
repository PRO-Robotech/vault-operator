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
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status — статус бакета; порядок значений совпадает с перечислением Status
// контракта cloud-manager (RUNNING = 0 … STOPPED = 5).
type Status int

// Статусы бакета.
const (
	StatusRunning Status = iota
	StatusCreating
	StatusRemoving
	StatusRemoved
	StatusError
	StatusStopped
)

var statusNames = [...]string{"RUNNING", "CREATING", "REMOVING", "REMOVED", "ERROR", "STOPPED"}

func (s Status) String() string {
	if s >= 0 && int(s) < len(statusNames) {
		return statusNames[s]
	}
	return "Status(" + strconv.Itoa(int(s)) + ")"
}

// Владелец бакета — значения S3BucketManagedBy контракта.
const (
	ManagedBySystem   = "SYSTEM"
	ManagedByCustomer = "CUSTOMER"
)

// Тексты ответа removeBucket настоящей службы: словарь закрыт, клиент
// оператора сверяет их дословно.
const (
	RemoveMsgNotFound       = "Not found"
	RemoveMsgAlreadyRemoved = "Already removed"
	// removeMsgCreating — бакет ещё заводится в хранилище; клиент оператора
	// читает этот текст как сбой удаления и повторяет позже.
	removeMsgCreating = "Bucket is being created"
)

// maxBucketNameLen — предел длины полного имени бакета (стандарт S3).
const maxBucketNameLen = 63

// CreateCode — код отказа create; значения отображаются на CreateError.Code
// контракта в service.go.
type CreateCode int

// Коды отказа create.
const (
	// CodeReserved — отказ вне именованных кодов (у настоящей службы — любое
	// исключение внутри создания: ответ несёт только текст).
	CodeReserved CreateCode = iota
	CodeInsufficientFunds
	CodeConfigurationNotFound
	CodeInvalidBucketName
	CodeBucketLimitReached
)

var createCodeNames = [...]string{"CODE_RESERVED", "INSUFFICIENT_FUNDS", "CONFIGURATION_NOT_FOUND",
	"INVALID_BUCKET_NAME", "BUCKET_LIMIT_REACHED"}

func (c CreateCode) String() string {
	if c >= 0 && int(c) < len(createCodeNames) {
		return createCodeNames[c]
	}
	return "CreateCode(" + strconv.Itoa(int(c)) + ")"
}

// Тексты отказов create — дословно тексты настоящей службы.
const (
	msgInvalidBucketName     = "Invalid bucket name"
	msgConfigurationNotFound = "Configurations not available or not found"
	msgBucketLimitReached    = "Maximum number of buckets reached"
	msgStorageFailed         = "failed to create bucket on storage"
)

// CreateError — отказ create, который служба отдаёт полем s3_error ответа.
type CreateError struct {
	Code    CreateCode
	Message string
}

func (e *CreateError) Error() string {
	return fmt.Sprintf("cmfake create: %s: %s", e.Code, e.Message)
}

var (
	// ErrUnknownCustomer — логина нет в конфиге. Настоящая служба ищет клиента
	// до перехвата ошибок S3, поэтому отказ уходит ошибкой gRPC, а не s3_error.
	ErrUnknownCustomer = errors.New("customer not found")
	// ErrStopped — хранилище закрыто: процесс останавливается.
	ErrStopped = errors.New("cmfake: store is stopped")
)

// Credentials — пара ключей S3 арендатора.
type Credentials struct {
	AccessKey string
	SecretKey string
}

// Backend — S3-совместимое хранилище стенда, где бакет заводится и снимается.
type Backend interface {
	// CreateBucket заводит бакет ключами арендатора; бакет, уже заведённый
	// этими же ключами, — успех.
	CreateBucket(ctx context.Context, cred Credentials, bucket string) error
	// DeleteBucket снимает объекты бакета и сам бакет; отсутствующий бакет —
	// успех.
	DeleteBucket(ctx context.Context, cred Credentials, bucket string) error
}

// ClientConfig — арендатор: логин, потолок бакетов и ключи S3.
type ClientConfig struct {
	Login       string
	MaxBuckets  int
	Credentials Credentials
}

// Configuration — тариф S3: настоящая служба ищет его по паре (id, регион).
type Configuration struct {
	ID     string
	Region string
}

// StoreConfig — всё, что хранилищу нужно знать о стенде.
type StoreConfig struct {
	// DefaultRegion подставляется, когда create пришёл без региона.
	DefaultRegion  string
	Configurations []Configuration
	Clients        []ClientConfig
	// BucketFqdnSuffix — хвост поля fqdn бакета: <имя>.<хвост>.
	BucketFqdnSuffix string
	// BackendTimeout — срок одного обращения к хранилищу.
	BackendTimeout time.Duration
	// RemoveAttempts — попыток снять бакет, после которых он уходит в ERROR.
	RemoveAttempts int
	// RemoveRetryDelay — пауза между попытками снятия.
	RemoveRetryDelay time.Duration
}

// validate отвергает конфиг, с которым двойник вёл бы себя не как служба
// либо смешал бы арендаторов.
func (c StoreConfig) validate() error {
	var errs []error
	if c.DefaultRegion == "" {
		errs = append(errs, errors.New("defaultRegion is empty"))
	}
	if len(c.Configurations) == 0 {
		errs = append(errs, errors.New("no configurations"))
	}
	for i, cf := range c.Configurations {
		if cf.ID == "" || cf.Region == "" {
			errs = append(errs, fmt.Errorf("configurations[%d]: id and region are required", i))
		}
	}
	if c.BucketFqdnSuffix == "" {
		errs = append(errs, errors.New("s3.bucketFqdnSuffix is empty"))
	}
	if c.BackendTimeout <= 0 {
		errs = append(errs, errors.New("backend timeout must be positive"))
	}
	if c.RemoveAttempts < 1 {
		errs = append(errs, errors.New("removal.attempts must be at least 1"))
	}
	if c.RemoveRetryDelay < 0 {
		errs = append(errs, errors.New("removal.retryDelay is negative"))
	}
	if len(c.Clients) == 0 {
		errs = append(errs, errors.New("no clients"))
	}
	logins := map[string]bool{}
	keyOwner := map[string]string{}
	for i, cl := range c.Clients {
		switch {
		case cl.Login == "":
			errs = append(errs, fmt.Errorf("clients[%d]: login is empty", i))
		case logins[cl.Login]:
			errs = append(errs, fmt.Errorf("clients[%d]: login %q repeats", i, cl.Login))
		}
		logins[cl.Login] = true
		if cl.MaxBuckets < 1 {
			errs = append(errs, fmt.Errorf("client %q: maxBuckets must be at least 1", cl.Login))
		}
		if cl.Credentials.AccessKey == "" || cl.Credentials.SecretKey == "" {
			errs = append(errs, fmt.Errorf("client %q: access and secret keys are required", cl.Login))
			continue
		}
		// Общий ключ двух арендаторов отдал бы бакеты одного другому на
		// стороне хранилища.
		if other, ok := keyOwner[cl.Credentials.AccessKey]; ok {
			errs = append(errs, fmt.Errorf("clients %q and %q share an access key", other, cl.Login))
		}
		keyOwner[cl.Credentials.AccessKey] = cl.Login
	}
	return errors.Join(errs...)
}

// Bucket — строка бакета в памяти двойника.
type Bucket struct {
	Name      string
	CustLogin string
	AccessKey string
	SecretKey string
	Fqdn      string
	Status    Status
	ManagedBy string
	Public    bool
	ServiceID string
}

// CreateInput — параметры create.
type CreateInput struct {
	Login           string
	ConfigurationID string
	Region          string
	BucketName      string
	ManagedBy       string
	Public          bool
}

// Scope — одна область поиска findAll: ровно одно из полей задано. Области
// соединяются через И, значения внутри области — через ИЛИ.
type Scope struct {
	Logins []string
	Names  []string
}

func (sc Scope) matches(b *Bucket) bool {
	switch {
	case sc.Logins != nil:
		return slices.Contains(sc.Logins, b.CustLogin)
	case sc.Names != nil:
		return slices.Contains(sc.Names, b.Name)
	default:
		return false
	}
}

// Store — состояние двойника в памяти: заказ, поиск, удаление бакетов по
// семантике настоящей службы. Безопасен для одновременных вызовов.
type Store struct {
	cfg     StoreConfig
	backend Backend
	log     *slog.Logger
	clients map[string]ClientConfig
	configs map[Configuration]bool

	// ctx отменяется при Close: обращения к хранилищу и снятия обрываются.
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	buckets []*Bucket // в порядке заведения
	byName  map[string]*Bucket
	nextID  int
	stopped bool
	// inflight — идущих снятий; idle закрывается, когда их становится ноль.
	inflight int
	idle     chan struct{}
}

// NewStore проверяет конфиг и возвращает пустое хранилище.
func NewStore(cfg StoreConfig, backend Backend, log *slog.Logger) (*Store, error) {
	if backend == nil {
		return nil, errors.New("cmfake: backend is nil")
	}
	if log == nil {
		return nil, errors.New("cmfake: logger is nil")
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("cmfake config: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{
		cfg: cfg, backend: backend, log: log,
		clients: make(map[string]ClientConfig, len(cfg.Clients)),
		configs: make(map[Configuration]bool, len(cfg.Configurations)),
		ctx:     ctx, cancel: cancel,
		byName: map[string]*Bucket{},
		idle:   closedChan(),
	}
	for _, cl := range cfg.Clients {
		s.clients[cl.Login] = cl
	}
	for _, cf := range cfg.Configurations {
		s.configs[cf] = true
	}
	return s, nil
}

func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Knows сообщает, есть ли логин в конфиге.
func (s *Store) Knows(login string) bool {
	_, ok := s.clients[login]
	return ok
}

// Create заводит бакет: проверки в порядке настоящей службы (клиент,
// конфигурация, имя, потолок), затем имя с суффиксом «-N» при занятом и
// заведение в хранилище. Обращение к хранилищу переживает уход вызывающего,
// как create настоящей службы: его обрывает лишь срок и Close. Вызывающий,
// ушедший до резерва имени, бакета не заводит.
func (s *Store) Create(ctx context.Context, in CreateInput) (Bucket, error) {
	client, ok := s.clients[in.Login]
	if !ok {
		return Bucket{}, fmt.Errorf("%w: %q", ErrUnknownCustomer, in.Login)
	}
	region := in.Region
	if region == "" {
		region = s.cfg.DefaultRegion
	}
	if !s.configs[Configuration{ID: in.ConfigurationID, Region: region}] {
		return Bucket{}, &CreateError{Code: CodeConfigurationNotFound, Message: msgConfigurationNotFound}
	}
	full := strings.ToLower(Prefix(in.Login) + "-" + in.BucketName)
	if !validRequestedName(in.BucketName) || len(full) > maxBucketNameLen {
		return Bucket{}, &CreateError{Code: CodeInvalidBucketName, Message: msgInvalidBucketName}
	}

	if err := ctx.Err(); err != nil {
		return Bucket{}, err
	}
	b, err := s.reserve(client, full, in)
	if err != nil {
		return Bucket{}, err
	}

	bctx, cancel := context.WithTimeout(s.ctx, s.cfg.BackendTimeout)
	err = s.backend.CreateBucket(bctx, client.Credentials, b.Name)
	cancel()

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.drop(b)
		s.log.Warn("bucket provisioning failed", "bucket", b.Name, "login", in.Login, "err", err.Error())
		return Bucket{}, &CreateError{Code: CodeReserved, Message: msgStorageFailed}
	}
	b.Status = StatusRunning
	s.log.Info("bucket created", "bucket", b.Name, "login", in.Login, "managedBy", b.ManagedBy)
	return *b, nil
}

// reserve под замком проверяет потолок, выбирает свободное имя и заводит
// строку CREATING: имя занято раньше обращения к хранилищу.
func (s *Store) reserve(client ClientConfig, full string, in CreateInput) (*Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, ErrStopped
	}
	if s.liveCount(client.Login) >= client.MaxBuckets {
		return nil, &CreateError{Code: CodeBucketLimitReached, Message: msgBucketLimitReached}
	}
	name := nextFreeName(full, func(n string) bool { return s.byName[n] != nil })
	if len(name) > maxBucketNameLen {
		return nil, &CreateError{Code: CodeInvalidBucketName, Message: msgInvalidBucketName}
	}
	managedBy := ManagedBySystem
	if in.ManagedBy == ManagedByCustomer {
		managedBy = ManagedByCustomer
	}
	s.nextID++
	b := &Bucket{
		Name:      name,
		CustLogin: client.Login,
		AccessKey: client.Credentials.AccessKey,
		SecretKey: client.Credentials.SecretKey,
		Fqdn:      name + "." + s.cfg.BucketFqdnSuffix,
		Status:    StatusCreating,
		ManagedBy: managedBy,
		Public:    in.Public,
		ServiceID: "svc-" + strconv.Itoa(s.nextID),
	}
	s.buckets = append(s.buckets, b)
	s.byName[name] = b
	return b, nil
}

// liveCount — бакетов логина, идущих в потолок: всё, кроме REMOVED.
func (s *Store) liveCount(login string) int {
	n := 0
	for _, b := range s.buckets {
		if b.CustLogin == login && b.Status != StatusRemoved {
			n++
		}
	}
	return n
}

// drop снимает строку, чьё заведение в хранилище не удалось.
func (s *Store) drop(b *Bucket) {
	delete(s.byName, b.Name)
	s.buckets = slices.DeleteFunc(s.buckets, func(x *Bucket) bool { return x == b })
}

// FindAll возвращает копии бакетов, подходящих под все области, в порядке
// заведения; без областей — все. REMOVED возвращается тоже.
func (s *Store) FindAll(scopes []Scope) []Bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Bucket, 0, len(s.buckets))
	for _, b := range s.buckets {
		hit := true
		for _, sc := range scopes {
			if !sc.matches(b) {
				hit = false
				break
			}
		}
		if hit {
			out = append(out, *b)
		}
	}
	return out
}

// Remove принимает снятие бакета: ответ — текст словаря настоящей службы
// (пустой — принято, бакет REMOVING), само снятие идёт асинхронно.
func (s *Store) Remove(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return "", ErrStopped
	}
	b := s.byName[name]
	switch {
	case b == nil:
		return RemoveMsgNotFound, nil
	case b.Status == StatusRemoved:
		return RemoveMsgAlreadyRemoved, nil
	case b.Status == StatusRemoving:
		return "", nil
	case b.Status == StatusCreating:
		return removeMsgCreating, nil
	}
	b.Status = StatusRemoving
	if s.inflight == 0 {
		s.idle = make(chan struct{})
	}
	s.inflight++
	go s.remove(b.Name, Credentials{AccessKey: b.AccessKey, SecretKey: b.SecretKey})
	s.log.Info("bucket removal accepted", "bucket", b.Name, "login", b.CustLogin)
	return "", nil
}

// remove снимает бакет в хранилище с повторами; исчерпав попытки, ставит
// ERROR. При Close выходит, оставив REMOVING: состояние в памяти уходит
// вместе с процессом.
func (s *Store) remove(name string, cred Credentials) {
	defer s.removalDone()
	for attempt := 1; attempt <= s.cfg.RemoveAttempts; attempt++ {
		if attempt > 1 {
			t := time.NewTimer(s.cfg.RemoveRetryDelay)
			select {
			case <-s.ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.BackendTimeout)
		err := s.backend.DeleteBucket(ctx, cred, name)
		cancel()
		if err == nil {
			s.finishRemoval(name, StatusRemoved)
			s.log.Info("bucket removed", "bucket", name)
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		s.log.Warn("bucket removal failed", "bucket", name, "attempt", attempt, "err", err.Error())
	}
	s.finishRemoval(name, StatusError)
	s.log.Error("bucket removal gave up", "bucket", name, "attempts", s.cfg.RemoveAttempts)
}

func (s *Store) finishRemoval(name string, st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.byName[name]; b != nil && b.Status == StatusRemoving {
		b.Status = st
	}
}

func (s *Store) removalDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight--
	if s.inflight == 0 {
		close(s.idle)
	}
}

// WaitRemovals ждёт, пока не останется идущих снятий, либо конца ctx.
func (s *Store) WaitRemovals(ctx context.Context) error {
	s.mu.Lock()
	idle := s.idle
	s.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close отвергает новые вызовы, обрывает идущие снятия и дожидается их
// выхода. Повторный вызов безопасен.
func (s *Store) Close() {
	s.mu.Lock()
	s.stopped = true
	idle := s.idle
	s.mu.Unlock()
	s.cancel()
	<-idle
}

// requestedNameRe — правила имени настоящей службы: латиница, цифры, «-»,
// «-» не в начале, не в конце и не дважды подряд.
var requestedNameRe = regexp.MustCompile(`^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)

func validRequestedName(name string) bool {
	return requestedNameRe.MatchString(name)
}

var suffixRe = regexp.MustCompile(`-([0-9]+)$`)

// nextFreeName повторяет getUniqBucketName настоящей службы: пока имя занято
// (в любом статусе), дописывает «-1» либо увеличивает хвостовое «-N».
func nextFreeName(name string, taken func(string) bool) string {
	for taken(name) {
		if m := suffixRe.FindStringSubmatchIndex(name); m != nil {
			n, _ := strconv.Atoi(name[m[2]:m[3]])
			name = name[:m[0]] + "-" + strconv.Itoa(n+1)
			continue
		}
		name += "-1"
	}
	return name
}
