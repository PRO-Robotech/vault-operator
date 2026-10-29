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
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Подпись сверяется с опубликованным эталоном протокола (набор get-vanilla):
// эталон посчитан не этим кодом, поэтому совпадение — свидетельство, а не
// тавтология.
func TestSignV4_MatchesThePublishedVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	cred := Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	signV4(req, cred, "us-east-1", "service", now, emptyPayloadHash, false)

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n %s\nwant\n %s", got, want)
	}
	// Близнец: другой секрет — другая подпись.
	req2, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	signV4(req2, Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "other"}, "us-east-1", "service", now, emptyPayloadHash, false)
	if req2.Header.Get("Authorization") == want {
		t.Fatal("a different secret produced the same signature")
	}
}

// s3Stub — S3-совместимый сервер в памяти: принимает только запросы,
// подписанные известной парой ключей, бакет принадлежит ключу, создавшему его.
type s3Stub struct {
	t       *testing.T
	secrets map[string]string // ключ доступа → секрет

	mu      sync.Mutex
	buckets map[string]string              // бакет → ключ доступа владельца
	objects map[string]map[string]struct{} // бакет → ключи объектов
	// pageSize — объектов на страницу листинга (проверка продолжения).
	pageSize int
	requests []string
	// admin — ключ доступа администратора: только он задаёт вопросы
	// /create-user и /delete-user; roles — роль пользователя, заведённого
	// администратором.
	admin string
	roles map[string]string
}

// roleOf — роль пользователя, заведённого вопросом администратора; пусто —
// такого нет.
func (st *s3Stub) roleOf(access string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.roles[access]
}

// serveAdmin отвечает на вопросы администратора в форме versitygw:
// PATCH /create-user с телом XML учётной записи и PATCH /delete-user?access=.
func (st *s3Stub) serveAdmin(w http.ResponseWriter, r *http.Request, ak string, body []byte) {
	if st.admin == "" || ak != st.admin {
		writeS3Error(w, http.StatusForbidden, "AccessDenied")
		return
	}
	switch r.URL.Path {
	case "/create-user":
		var acc struct {
			Access string `xml:"Access"`
			Secret string `xml:"Secret"`
			Role   string `xml:"Role"`
		}
		if err := xml.Unmarshal(body, &acc); err != nil || acc.Access == "" || acc.Secret == "" {
			writeS3Error(w, http.StatusBadRequest, "MalformedXML")
			return
		}
		if _, ok := st.secrets[acc.Access]; ok {
			writeS3Error(w, http.StatusConflict, "XAdminUserExists")
			return
		}
		st.secrets[acc.Access] = acc.Secret
		st.roles[acc.Access] = acc.Role
		w.WriteHeader(http.StatusCreated)
	case "/delete-user":
		access := r.URL.Query().Get("access")
		delete(st.secrets, access)
		delete(st.roles, access)
		w.WriteHeader(http.StatusOK)
	default:
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented")
	}
}

func newS3Stub(t *testing.T, creds ...Credentials) *s3Stub {
	st := &s3Stub{t: t, secrets: map[string]string{}, buckets: map[string]string{},
		objects: map[string]map[string]struct{}{}, pageSize: 1000, roles: map[string]string{}}
	for _, c := range creds {
		st.secrets[c.AccessKey] = c.SecretKey
	}
	return st
}

// authenticate пересчитывает подпись запроса секретом названного ключа.
func (st *s3Stub) authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const credPrefix = "AWS4-HMAC-SHA256 Credential="
	if !strings.HasPrefix(auth, credPrefix) {
		return "", false
	}
	ak, _, _ := strings.Cut(strings.TrimPrefix(auth, credPrefix), "/")
	secret, ok := st.secrets[ak]
	if !ok {
		return "", false
	}
	now, err := time.Parse(amzDateFormat, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "", false
	}
	check, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), nil)
	check.Host = r.Host
	signV4(check, Credentials{AccessKey: ak, SecretKey: secret}, "us-east-1", "s3", now,
		r.Header.Get("X-Amz-Content-Sha256"), true)
	return ak, check.Header.Get("Authorization") == auth
}

func (st *s3Stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.requests = append(st.requests, r.Method+" "+r.URL.RequestURI())
	// Подписанный хеш тела обязан совпасть с телом: иначе подпись не
	// свидетельствует о том, что пришло.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeS3Error(w, http.StatusBadRequest, "IncompleteBody")
		return
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		writeS3Error(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
		return
	}
	ak, ok := st.authenticate(r)
	if !ok {
		writeS3Error(w, http.StatusForbidden, "SignatureDoesNotMatch")
		return
	}
	if r.Method == http.MethodPatch {
		st.serveAdmin(w, r, ak, body)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	owner, exists := st.buckets[bucket]
	switch {
	case r.Method == http.MethodPut && key == "":
		switch {
		case exists && owner == ak:
			writeS3Error(w, http.StatusConflict, "BucketAlreadyOwnedByYou")
		case exists:
			writeS3Error(w, http.StatusConflict, "BucketAlreadyExists")
		default:
			st.buckets[bucket] = ak
			st.objects[bucket] = map[string]struct{}{}
			w.WriteHeader(http.StatusOK)
		}
	case !exists:
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket")
	case owner != ak:
		writeS3Error(w, http.StatusForbidden, "AccessDenied")
	case r.Method == http.MethodPut:
		st.objects[bucket][key] = struct{}{}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		st.list(w, bucket, r.URL.Query().Get("continuation-token"))
	case r.Method == http.MethodDelete && key != "":
		delete(st.objects[bucket], key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		if len(st.objects[bucket]) > 0 {
			writeS3Error(w, http.StatusConflict, "BucketNotEmpty")
			return
		}
		delete(st.buckets, bucket)
		delete(st.objects, bucket)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented")
	}
}

func (st *s3Stub) list(w http.ResponseWriter, bucket, token string) {
	keys := make([]string, 0, len(st.objects[bucket]))
	for k := range st.objects[bucket] {
		if k > token {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	truncated := len(keys) > st.pageSize
	if truncated {
		keys = keys[:st.pageSize]
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key></Contents>", k)
	}
	fmt.Fprintf(&b, "<IsTruncated>%t</IsTruncated>", truncated)
	if truncated {
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", keys[len(keys)-1])
	}
	b.WriteString("</ListBucketResult>")
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(b.String()))
}

func writeS3Error(w http.ResponseWriter, code int, s3code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>m</Message></Error>`, s3code)
}

func (st *s3Stub) hasBucket(name string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, ok := st.buckets[name]
	return ok
}

func (st *s3Stub) putObject(bucket, key string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.objects[bucket][key] = struct{}{}
}

// startS3Stub поднимает заглушку по TLS и пишет её сертификат в файл УЦ.
func startS3Stub(t *testing.T, st *s3Stub) (endpoint, caFile string) {
	t.Helper()
	srv := httptest.NewTLSServer(st)
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, caFile
}

func newTestS3Backend(t *testing.T, st *s3Stub) *S3Backend {
	t.Helper()
	endpoint, caFile := startS3Stub(t, st)
	be, err := NewS3Backend(S3Config{Endpoint: endpoint, SigningRegion: "us-east-1", CAFile: caFile,
		RequestTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewS3Backend: %v", err)
	}
	return be
}

// Бакет заводится ключами арендатора; повторное заведение своим же ключом —
// успех, чужое имя — отказ с кодом хранилища.
func TestS3Backend_CreateBucket(t *testing.T) {
	st := newS3Stub(t, credA, credB)
	be := newTestS3Backend(t, st)
	ctx := context.Background()

	if err := be.CreateBucket(ctx, credA, "aa-one"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !st.hasBucket("aa-one") {
		t.Fatal("bucket not on the server")
	}
	if err := be.CreateBucket(ctx, credA, "aa-one"); err != nil {
		t.Fatalf("own repeat: %v", err)
	}
	err := be.CreateBucket(ctx, credB, "aa-one")
	if err == nil || !strings.Contains(err.Error(), "BucketAlreadyExists") {
		t.Fatalf("foreign name: %v, want BucketAlreadyExists", err)
	}
	// Неизвестные серверу ключи — отказ подписи, а не тихий успех.
	err = be.CreateBucket(ctx, Credentials{AccessKey: "nobody", SecretKey: "x"}, "aa-two")
	if err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("unknown keys: %v", err)
	}
}

// Удаление снимает объекты постранично, затем сам бакет; отсутствующий бакет —
// уже снят.
func TestS3Backend_DeleteBucketEmptiesItFirst(t *testing.T) {
	st := newS3Stub(t, credA)
	st.pageSize = 2
	be := newTestS3Backend(t, st)
	ctx := context.Background()

	if err := be.CreateBucket(ctx, credA, "aa-full"); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, k := range []string{"a", "b/c", "d e", "f"} {
		st.putObject("aa-full", k)
	}
	if err := be.DeleteBucket(ctx, credA, "aa-full"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st.hasBucket("aa-full") {
		t.Fatal("bucket still on the server")
	}
	if err := be.DeleteBucket(ctx, credA, "aa-full"); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
}

// Адрес хранилища — только https.
func TestNewS3Backend_RefusesPlainHTTP(t *testing.T) {
	if _, err := NewS3Backend(S3Config{Endpoint: "http://s3.stand.test", SigningRegion: "us-east-1",
		RequestTimeout: time.Second}); err == nil {
		t.Fatal("plain http accepted")
	}
}
