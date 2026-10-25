/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmfake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFile пишет файл в каталог теста и возвращает путь.
func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// configYAML — конфиг двойника с двумя арендаторами; ключи лежат файлами, как
// их монтирует Secret стенда.
func configYAML(t *testing.T, dir string) string {
	t.Helper()
	writeFile(t, dir, "a/accessKey", "ak-tenant-a\n")
	writeFile(t, dir, "a/secretKey", "sk-tenant-a\n")
	writeFile(t, dir, "b/accessKey", "ak-tenant-b")
	writeFile(t, dir, "b/secretKey", "sk-tenant-b")
	writeFile(t, dir, "ca.crt", "unused by the loader")
	return `
listenAddress: "127.0.0.1:0"
defaultRegion: ru1
configurations:
  - id: s3_v1
    region: ru1
s3:
  endpoint: https://s3.stand.test:9000
  signingRegion: us-east-1
  caFile: ` + filepath.Join(dir, "ca.crt") + `
  bucketFqdnSuffix: s3.stand.test
  requestTimeout: 20s
removal:
  attempts: 4
  retryDelay: 3s
clients:
  - login: tenant-a
    maxBuckets: 2
    accessKeyFile: ` + filepath.Join(dir, "a/accessKey") + `
    secretKeyFile: ` + filepath.Join(dir, "a/secretKey") + `
  - login: tenant-b
    maxBuckets: 5
    accessKeyFile: ` + filepath.Join(dir, "b/accessKey") + `
    secretKeyFile: ` + filepath.Join(dir, "b/secretKey") + `
`
}

// Конфиг читается целиком: ключи — из файлов (без хвостового перевода
// строки), длительности — строками.
func TestLoadConfig_ReadsKeysFromFiles(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", configYAML(t, dir))

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddress != "127.0.0.1:0" {
		t.Fatalf("listen = %q", cfg.ListenAddress)
	}
	if cfg.S3.Endpoint != "https://s3.stand.test:9000" || cfg.S3.SigningRegion != "us-east-1" {
		t.Fatalf("s3 = %+v", cfg.S3)
	}
	if cfg.S3.RequestTimeout != 20*time.Second {
		t.Fatalf("request timeout = %s", cfg.S3.RequestTimeout)
	}
	st := cfg.Store
	if st.RemoveAttempts != 4 || st.RemoveRetryDelay != 3*time.Second || st.BackendTimeout != 20*time.Second {
		t.Fatalf("store timings = %+v", st)
	}
	if len(st.Clients) != 2 {
		t.Fatalf("clients = %+v", st.Clients)
	}
	a := st.Clients[0]
	if a.Login != "tenant-a" || a.MaxBuckets != 2 || a.Credentials != credA {
		t.Fatalf("tenant-a = %+v", a)
	}
	if st.Clients[1].Credentials != credB {
		t.Fatalf("tenant-b keys = %+v", st.Clients[1].Credentials)
	}
	if len(st.Configurations) != 1 || st.Configurations[0] != (Configuration{ID: "s3_v1", Region: "ru1"}) {
		t.Fatalf("configurations = %+v", st.Configurations)
	}
}

// Отказы загрузки называют причину; конфиг с открытым адресом хранилища,
// неизвестным полем или без файла ключа не принимается.
func TestLoadConfig_Refusals(t *testing.T) {
	cases := map[string]struct {
		edit func(t *testing.T, dir, yaml string) string
		want string
	}{
		"unknown field": {func(_ *testing.T, _, y string) string { return y + "surprise: true\n" }, "surprise"},
		"plain http endpoint": {func(_ *testing.T, _, y string) string {
			return strings.Replace(y, "https://s3.stand.test:9000", "http://s3.stand.test:9000", 1)
		}, "https"},
		"missing key file": {func(t *testing.T, dir, y string) string {
			return strings.Replace(y, filepath.Join(dir, "b/secretKey"), filepath.Join(dir, "b/absent"), 1)
		}, "absent"},
		"empty key file": {func(t *testing.T, dir, y string) string {
			writeFile(t, dir, "b/empty", "\n")
			return strings.Replace(y, filepath.Join(dir, "b/secretKey"), filepath.Join(dir, "b/empty"), 1)
		}, "empty"},
		"bad duration": {func(_ *testing.T, _, y string) string {
			return strings.Replace(y, "retryDelay: 3s", "retryDelay: soon", 1)
		}, "retryDelay"},
		"shared keys": {func(t *testing.T, dir, y string) string {
			return strings.Replace(y, filepath.Join(dir, "b/accessKey"), filepath.Join(dir, "a/accessKey"), 1)
		}, "access key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeFile(t, dir, "config.yaml", tc.edit(t, dir, configYAML(t, dir)))
			_, err := LoadConfig(path)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// Пропущенные необязательные поля берут умолчания.
func TestLoadConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	y := configYAML(t, dir)
	for _, drop := range []string{"  signingRegion: us-east-1\n", "  requestTimeout: 20s\n", "removal:\n  attempts: 4\n  retryDelay: 3s\n", "listenAddress: \"127.0.0.1:0\"\n"} {
		if !strings.Contains(y, drop) {
			t.Fatalf("fixture lacks %q", drop)
		}
		y = strings.Replace(y, drop, "", 1)
	}
	cfg, err := LoadConfig(writeFile(t, dir, "config.yaml", y))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenAddress != DefaultListenAddress || cfg.S3.SigningRegion != DefaultSigningRegion {
		t.Fatalf("defaults: listen %q, signing region %q", cfg.ListenAddress, cfg.S3.SigningRegion)
	}
	if cfg.S3.RequestTimeout != DefaultRequestTimeout || cfg.Store.RemoveAttempts != DefaultRemoveAttempts ||
		cfg.Store.RemoveRetryDelay != DefaultRemoveRetryDelay {
		t.Fatalf("defaults: %+v / %+v", cfg.S3, cfg.Store)
	}
}
