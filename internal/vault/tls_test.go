/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func makeCert(t *testing.T, cn string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckCABundleExpiry_Valid(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pemBytes := makeCert(t, "valid-ca", now.Add(-24*time.Hour), now.Add(24*time.Hour))
	if err := checkCABundleExpiry(pemBytes, now); err != nil {
		t.Fatalf("unexpected error for valid cert: %v", err)
	}
}

func TestCheckCABundleExpiry_Expired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pemBytes := makeCert(t, "expired-ca",
		now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	err := checkCABundleExpiry(pemBytes, now)
	if err == nil {
		t.Fatalf("expected expired error, got nil")
	}
	if !strings.Contains(err.Error(), "expired-ca") {
		t.Fatalf("error should name the cert subject, got: %v", err)
	}
}

func TestCheckCABundleExpiry_SkipNonCertBlocks(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cert := makeCert(t, "valid-ca", now.Add(-time.Hour), now.Add(time.Hour))
	noise := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
	bundle := append(noise, cert...)
	if err := checkCABundleExpiry(bundle, now); err != nil {
		t.Fatalf("non-CERTIFICATE blocks should be skipped: %v", err)
	}
}

func TestCheckCABundleExpiry_EmptyInput(t *testing.T) {
	if err := checkCABundleExpiry(nil, time.Now()); err != nil {
		t.Fatalf("empty input should be a no-op, got: %v", err)
	}
}
