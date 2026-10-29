/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmfake

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	amzDateFormat = "20060102T150405Z"
	// emptyPayloadHash — SHA-256 пустого тела: все запросы двойника без тела.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// maxErrorBody — сколько байт тела отказа читается ради кода ошибки.
	maxErrorBody = 64 << 10
)

// S3Backend заводит и снимает бакеты в S3-совместимом хранилище стенда
// запросами в стиле пути, подписанными ключами арендатора (подпись V4).
type S3Backend struct {
	endpoint *url.URL
	region   string
	client   *http.Client
	now      func() time.Time
	// admin — ключи администратора хранилища; nil — вопросов администратора
	// нет.
	admin *Credentials
}

var (
	_ Backend   = (*S3Backend)(nil)
	_ UserAdmin = (*S3Backend)(nil)
)

// NewS3Backend проверяет адрес (только https) и УЦ хранилища.
func NewS3Backend(cfg S3Config) (*S3Backend, error) {
	if err := checkEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	u, _ := url.Parse(cfg.Endpoint)
	u.Path, u.RawPath = "", ""
	if cfg.SigningRegion == "" {
		return nil, errors.New("s3: signing region is empty")
	}
	if cfg.RequestTimeout <= 0 {
		return nil, errors.New("s3: request timeout must be positive")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("s3 ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("s3 ca %s: no certificate read", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &S3Backend{
		endpoint: u,
		region:   cfg.SigningRegion,
		client:   &http.Client{Transport: transport, Timeout: cfg.RequestTimeout},
		now:      time.Now,
		admin:    cfg.Admin,
	}, nil
}

// userAccount — учётная запись вопроса администратора /create-user в форме
// versitygw (auth.Account: элементы по именам полей).
type userAccount struct {
	XMLName xml.Name `xml:"Account"`
	Access  string   `xml:"Access"`
	Secret  string   `xml:"Secret"`
	Role    string   `xml:"Role"`
}

// roleUserPlus — роль versitygw: заводит и снимает свои бакеты, к чужим
// доступа не имеет.
const roleUserPlus = "userplus"

// CreateUser — PATCH /create-user: пользователь хранилища с ключами cred и
// ролью userplus, вопрос подписан ключами администратора вместе с хешем тела.
func (b *S3Backend) CreateUser(ctx context.Context, cred Credentials) error {
	if b.admin == nil {
		return errors.New("s3 create user: no admin keys configured")
	}
	body, err := xml.Marshal(userAccount{Access: cred.AccessKey, Secret: cred.SecretKey, Role: roleUserPlus})
	if err != nil {
		return fmt.Errorf("s3 create user: %w", err)
	}
	status, code, _, err := b.doBody(ctx, *b.admin, http.MethodPatch, "/create-user", nil, body)
	if err != nil {
		return fmt.Errorf("s3 create user: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return fmt.Errorf("s3 create user: %d %s", status, code)
	}
	return nil
}

// DeleteUser — PATCH /delete-user?access=<ключ>; хранилище принимает снятие
// отсутствующего пользователя.
func (b *S3Backend) DeleteUser(ctx context.Context, accessKey string) error {
	if b.admin == nil {
		return errors.New("s3 delete user: no admin keys configured")
	}
	status, code, _, err := b.doBody(ctx, *b.admin, http.MethodPatch, "/delete-user",
		url.Values{"access": {accessKey}}, nil)
	if err != nil {
		return fmt.Errorf("s3 delete user: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("s3 delete user: %d %s", status, code)
	}
	return nil
}

// CreateBucket — PUT /<бакет>. Ответ BucketAlreadyOwnedByYou — успех: бакет
// уже заведён этими ключами (повтор после перезапуска двойника).
func (b *S3Backend) CreateBucket(ctx context.Context, cred Credentials, bucket string) error {
	status, code, _, err := b.do(ctx, cred, http.MethodPut, "/"+bucket, nil)
	if err != nil {
		return fmt.Errorf("s3 create bucket %s: %w", bucket, err)
	}
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusConflict && code == "BucketAlreadyOwnedByYou":
		return nil
	default:
		return fmt.Errorf("s3 create bucket %s: %d %s", bucket, status, code)
	}
}

// DeleteBucket снимает объекты бакета постранично, затем сам бакет.
// NoSuchBucket на любом шаге — бакета нет, это успех.
func (b *S3Backend) DeleteBucket(ctx context.Context, cred Credentials, bucket string) error {
	token := ""
	for {
		q := url.Values{"list-type": {"2"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		status, code, body, err := b.do(ctx, cred, http.MethodGet, "/"+bucket, q)
		if err != nil {
			return fmt.Errorf("s3 list %s: %w", bucket, err)
		}
		if status == http.StatusNotFound && code == "NoSuchBucket" {
			return nil
		}
		if status != http.StatusOK {
			return fmt.Errorf("s3 list %s: %d %s", bucket, status, code)
		}
		var page listResult
		if err := xml.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("s3 list %s: %w", bucket, err)
		}
		for _, obj := range page.Contents {
			if err := b.deleteObject(ctx, cred, bucket, obj.Key); err != nil {
				return err
			}
		}
		if !page.IsTruncated {
			break
		}
		if page.NextContinuationToken == "" {
			return fmt.Errorf("s3 list %s: truncated page without a continuation token", bucket)
		}
		token = page.NextContinuationToken
	}
	status, code, _, err := b.do(ctx, cred, http.MethodDelete, "/"+bucket, nil)
	if err != nil {
		return fmt.Errorf("s3 delete bucket %s: %w", bucket, err)
	}
	switch {
	case status == http.StatusNoContent || status == http.StatusOK:
		return nil
	case status == http.StatusNotFound && code == "NoSuchBucket":
		return nil
	default:
		return fmt.Errorf("s3 delete bucket %s: %d %s", bucket, status, code)
	}
}

func (b *S3Backend) deleteObject(ctx context.Context, cred Credentials, bucket, key string) error {
	status, code, _, err := b.do(ctx, cred, http.MethodDelete, "/"+bucket+"/"+key, nil)
	if err != nil {
		return fmt.Errorf("s3 delete object in %s: %w", bucket, err)
	}
	switch status {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("s3 delete object in %s: %d %s", bucket, status, code)
	}
}

type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

type s3ErrorBody struct {
	Code string `xml:"Code"`
}

// do шлёт подписанный запрос без тела и возвращает статус, код ошибки
// хранилища (для не-2xx) и тело ответа.
func (b *S3Backend) do(ctx context.Context, cred Credentials, method, path string, query url.Values) (int, string, []byte, error) {
	return b.doBody(ctx, cred, method, path, query, nil)
}

// doBody — то же, что do, с телом запроса: хеш тела входит в подпись.
func (b *S3Backend) doBody(ctx context.Context, cred Credentials, method, path string, query url.Values,
	payload []byte) (int, string, []byte, error) {
	u := *b.endpoint
	u.Path = path
	u.RawPath = canonicalURI(path)
	u.RawQuery = canonicalQuery(query)
	var reqBody io.Reader
	payloadHash := emptyPayloadHash
	if len(payload) > 0 {
		reqBody = bytes.NewReader(payload)
		sum := sha256.Sum256(payload)
		payloadHash = hex.EncodeToString(sum[:])
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return 0, "", nil, err
	}
	signV4(req, cred, b.region, "s3", b.now(), payloadHash, true)
	resp, err := b.client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	limit := int64(maxErrorBody)
	if resp.StatusCode == http.StatusOK && method == http.MethodGet {
		// Страница листинга — до 1000 ключей по 1 КиБ.
		limit = 4 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return 0, "", nil, err
	}
	code := ""
	if resp.StatusCode >= 300 {
		var e s3ErrorBody
		if xml.Unmarshal(body, &e) == nil {
			code = e.Code
		}
	}
	return resp.StatusCode, code, body, nil
}

// signV4 подписывает запрос подписью V4 (заголовок Authorization).
// includeContentSHA добавляет подписанный X-Amz-Content-Sha256 (его требует
// S3); без него форма совпадает с эталонным набором протокола.
func signV4(req *http.Request, cred Credentials, region, service string, now time.Time,
	payloadHash string, includeContentSHA bool) {
	amzDate := now.UTC().Format(amzDateFormat)
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if includeContentSHA {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host, "x-amz-date": amzDate}
	if includeContentSHA {
		headers["x-amz-content-sha256"] = payloadHash
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.Query()),
		canonHeaders.String(),
		signed,
		payloadHash,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	key := hmacSHA256([]byte("AWS4"+cred.SecretKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cred.AccessKey+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// canonicalURI кодирует путь по правилам подписи: каждый байт вне
// A-Z a-z 0-9 - _ . ~ и «/» — %XX; пустой путь — «/».
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return uriEncode(path, false)
}

// canonicalQuery — параметры, отсортированные по имени и значению, имя и
// значение закодированы полностью.
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(q))
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, pair{uriEncode(k, true), uriEncode(v, true)})
		}
	}
	// Порядок — по закодированному имени, затем по значению: сортировка
	// склеенных «имя=значение» ошиблась бы на имени-префиксе другого.
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}
