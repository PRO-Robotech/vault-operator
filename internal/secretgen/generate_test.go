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
)

func TestGenerate_LengthAndAlphabet(t *testing.T) {
	// 41 × log2(3) ≈ 65 bits: above the entropy floor.
	const charset = "abc"
	s, err := Generate(41, charset)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len([]rune(s)) != 41 {
		t.Fatalf("length = %d, want 41", len([]rune(s)))
	}
	for _, c := range s {
		if !strings.ContainsRune(charset, c) {
			t.Fatalf("char %q not in charset %q", c, charset)
		}
	}
}

func TestGenerate_BelowMinLength(t *testing.T) {
	if _, err := Generate(7, ""); err == nil {
		t.Fatalf("expected error for length 7")
	}
}

func TestGenerate_EmptyCharsetUsesDefault(t *testing.T) {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	s, err := Generate(200, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, c := range s {
		if !strings.ContainsRune(alnum, c) {
			t.Fatalf("char %q not alphanumeric", c)
		}
	}
}

func TestGenerate_RangeExpansion(t *testing.T) {
	s, err := Generate(100, "a-c")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, c := range s {
		if c != 'a' && c != 'b' && c != 'c' {
			t.Fatalf("char %q outside expanded range a-c", c)
		}
	}
}

func TestGenerate_SingleSymbolRejected(t *testing.T) {
	if _, err := Generate(16, "x"); err == nil {
		t.Fatalf("expected error for single-symbol charset")
	}
}

// TestGenerate_NoModuloBias checks the distribution over a 2-symbol alphabet is
// near-uniform across a large sample; rand.Int makes a skew here vanishingly
// unlikely, so a wide band stays non-flaky.
func TestGenerate_NoModuloBias(t *testing.T) {
	const n = 100000
	s, err := Generate(n, "ab")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	a := strings.Count(s, "a")
	frac := float64(a) / float64(n)
	if frac < 0.45 || frac > 0.55 {
		t.Fatalf("'a' fraction = %.4f, want within [0.45,0.55]", frac)
	}
}

func TestExpandCharset_DedupAndRanges(t *testing.T) {
	got := string(expandCharset("a-cabc0-1"))
	if got != "abc01" {
		t.Fatalf("expandCharset = %q, want %q", got, "abc01")
	}
}

func TestExpandCharset_LiteralTrailingDash(t *testing.T) {
	got := string(expandCharset("ab-"))
	if got != "ab-" {
		t.Fatalf("expandCharset = %q, want %q", got, "ab-")
	}
}

// The floor is on entropy, not on length: length × log2(distinct symbols).
func TestGenerate_EntropyFloor(t *testing.T) {
	cases := []struct {
		length  int
		charset string
		ok      bool
	}{
		{8, "", false},                           // 8 × log2(62) ≈ 47.6 bits
		{10, "", false},                          // ≈ 59.5
		{11, "", true},                           // ≈ 65.5
		{16, "", true},                           // ≈ 95.3: the production minimum
		{63, "ab", false},                        // 63 bits
		{64, "ab", true},                         // 64 bits
		{40, "aaaaaaaaaaaaaaaaaaaaaaaab", false}, // dedups to 2 symbols: 40 bits
		{64, "aaaaaaaaaaaaaaaaaaaaaaaab", true},
	}
	for _, c := range cases {
		_, err := Generate(c.length, c.charset)
		if (err == nil) != c.ok {
			t.Errorf("Generate(%d, %q): err=%v, want ok=%v", c.length, c.charset, err, c.ok)
		}
	}
}
