/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticJWTSource(t *testing.T) {
	got, err := StaticJWTSource("abc").JWT()
	if err != nil || got != "abc" {
		t.Fatalf("StaticJWTSource('abc')=%q,%v", got, err)
	}
	if _, err := StaticJWTSource("").JWT(); err == nil {
		t.Fatalf("expected error for empty static source")
	}
}

func TestFileJWTSource_ReadsAndTrims(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("  jwt-content  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	src := NewFileJWTSource(p)
	got, err := src.JWT()
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if got != "jwt-content" {
		t.Fatalf("expected trimmed jwt-content, got %q", got)
	}
}

func TestFileJWTSource_EmptyFileFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty")
	if err := os.WriteFile(p, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewFileJWTSource(p).JWT(); err == nil {
		t.Fatalf("expected error for empty file")
	}
}

func TestFileJWTSource_MissingFileFails(t *testing.T) {
	src := NewFileJWTSource("/nonexistent/path")
	if _, err := src.JWT(); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNewFileJWTSource_DefaultPath(t *testing.T) {
	src := NewFileJWTSource("")
	if src.Path != DefaultProjectedTokenPath {
		t.Fatalf("expected default path, got %q", src.Path)
	}
}
