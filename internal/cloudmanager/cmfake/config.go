/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package cmfake

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Умолчания конфига службы.
const (
	DefaultListenAddress    = ":9090"
	DefaultSigningRegion    = "us-east-1"
	DefaultRequestTimeout   = 30 * time.Second
	DefaultRemoveAttempts   = 5
	DefaultRemoveRetryDelay = 2 * time.Second
)

// S3Config — адрес S3-совместимого хранилища стенда и как к нему ходить.
type S3Config struct {
	// Endpoint — только https.
	Endpoint string
	// SigningRegion — регион в подписи запросов.
	SigningRegion string
	// CAFile — PEM удостоверяющего центра хранилища; пусто — системные.
	CAFile string
	// RequestTimeout — срок одного запроса к хранилищу.
	RequestTimeout time.Duration
}

// Config — разобранный и проверенный конфиг службы.
type Config struct {
	ListenAddress string
	S3            S3Config
	Store         StoreConfig
}

// fileConfig — форма файла. Ключи S3 в файле не лежат: он называет файлы,
// которые монтирует Secret стенда.
type fileConfig struct {
	ListenAddress  string `json:"listenAddress"`
	DefaultRegion  string `json:"defaultRegion"`
	Configurations []struct {
		ID     string `json:"id"`
		Region string `json:"region"`
	} `json:"configurations"`
	S3 struct {
		Endpoint         string `json:"endpoint"`
		SigningRegion    string `json:"signingRegion"`
		CAFile           string `json:"caFile"`
		BucketFqdnSuffix string `json:"bucketFqdnSuffix"`
		RequestTimeout   string `json:"requestTimeout"`
	} `json:"s3"`
	Removal struct {
		Attempts   int    `json:"attempts"`
		RetryDelay string `json:"retryDelay"`
	} `json:"removal"`
	Clients []struct {
		Login         string `json:"login"`
		MaxBuckets    int    `json:"maxBuckets"`
		AccessKeyFile string `json:"accessKeyFile"`
		SecretKeyFile string `json:"secretKeyFile"`
	} `json:"clients"`
}

// LoadConfig читает файл конфига, подставляет умолчания, читает ключи
// арендаторов из их файлов и проверяет итог. Неизвестное поле — отказ.
// Тексты отказов называют поле и путь, но не значения ключей.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var fc fileConfig
	if err := yaml.UnmarshalStrict(raw, &fc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Ёмкость — верхняя граница отказов: адрес S3, две длительности и по два
	// файла ключей на арендатора.
	errs := make([]error, 0, 3+2*len(fc.Clients))
	cfg := &Config{
		ListenAddress: orDefault(fc.ListenAddress, DefaultListenAddress),
		S3: S3Config{
			Endpoint:      fc.S3.Endpoint,
			SigningRegion: orDefault(fc.S3.SigningRegion, DefaultSigningRegion),
			CAFile:        fc.S3.CAFile,
		},
	}
	if err := checkEndpoint(fc.S3.Endpoint); err != nil {
		errs = append(errs, err)
	}
	cfg.S3.RequestTimeout, err = parseDuration("s3.requestTimeout", fc.S3.RequestTimeout, DefaultRequestTimeout)
	errs = append(errs, err)
	retryDelay, err := parseDuration("removal.retryDelay", fc.Removal.RetryDelay, DefaultRemoveRetryDelay)
	errs = append(errs, err)
	attempts := fc.Removal.Attempts
	if attempts == 0 {
		attempts = DefaultRemoveAttempts
	}

	st := StoreConfig{
		DefaultRegion:    fc.DefaultRegion,
		BucketFqdnSuffix: fc.S3.BucketFqdnSuffix,
		BackendTimeout:   cfg.S3.RequestTimeout,
		RemoveAttempts:   attempts,
		RemoveRetryDelay: retryDelay,
	}
	for _, c := range fc.Configurations {
		st.Configurations = append(st.Configurations, Configuration{ID: c.ID, Region: c.Region})
	}
	for _, c := range fc.Clients {
		ak, err := readKeyFile(c.Login, "access", c.AccessKeyFile)
		errs = append(errs, err)
		sk, err := readKeyFile(c.Login, "secret", c.SecretKeyFile)
		errs = append(errs, err)
		st.Clients = append(st.Clients, ClientConfig{Login: c.Login, MaxBuckets: c.MaxBuckets,
			Credentials: Credentials{AccessKey: ak, SecretKey: sk}})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := st.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	cfg.Store = st
	return cfg, nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// checkEndpoint пропускает только https-адрес без пути: ключи арендаторов
// по открытому каналу не ходят.
func checkEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("s3.endpoint: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("s3.endpoint %q: want an https URL with a host", endpoint)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return fmt.Errorf("s3.endpoint %q: want no path or query", endpoint)
	}
	return nil
}

func parseDuration(field, v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: %s is not positive", field, v)
	}
	return d, nil
}

// readKeyFile читает ключ из файла Secret; хвостовые пробелы и перевод
// строки отбрасываются.
func readKeyFile(login, kind, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("client %q: %sKeyFile is empty", login, kind)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("client %q: %s key: %w", login, kind, err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("client %q: %s key file %s is empty", login, kind, path)
	}
	return key, nil
}
