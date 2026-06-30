/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package secretgen

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHash_NoneIsIdentity(t *testing.T) {
	got, err := Hash(HashNone, "s3cret")
	if err != nil {
		t.Fatalf("Hash none: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("none returned %q, want identity", got)
	}
}

func TestHash_BcryptPrefixAndVerify(t *testing.T) {
	const raw = "admin-password"
	got, err := Hash(HashBcrypt, raw)
	if err != nil {
		t.Fatalf("Hash bcrypt: %v", err)
	}
	if !strings.HasPrefix(got, "$2a$") {
		t.Fatalf("bcrypt hash %q lacks $2a$ prefix", got)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(got), []byte(raw)); err != nil {
		t.Fatalf("bcrypt hash does not verify against raw: %v", err)
	}
}

func TestHash_UnknownKind(t *testing.T) {
	if _, err := Hash("sha256", "x"); err == nil {
		t.Fatalf("expected error for unknown hash kind")
	}
}
