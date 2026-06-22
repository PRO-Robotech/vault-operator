/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package secretgen generates random secret values and applies hash transforms
// for VaultSecretClaim.
package secretgen

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	// DefaultCharset is [A-Za-z0-9] in X-Y range shorthand.
	DefaultCharset = "A-Za-z0-9"
	// MinLength mirrors the CRD's generate.length minimum.
	MinLength = 8
)

// Generate returns a cryptographically random string of length over charset.
// charset is an alphabet with X-Y range shorthand (e.g. "a-zA-Z0-9"); rand.Int
// rejection-samples each index, so there is no modulo bias.
func Generate(length int, charset string) (string, error) {
	if length < MinLength {
		return "", fmt.Errorf("secretgen: length %d below minimum %d", length, MinLength)
	}
	if charset == "" {
		charset = DefaultCharset
	}
	alphabet := expandCharset(charset)
	if len(alphabet) < 2 {
		return "", fmt.Errorf("secretgen: charset %q yields %d usable symbols, need >= 2", charset, len(alphabet))
	}

	n := big.NewInt(int64(len(alphabet)))
	out := make([]rune, length)
	for i := range out {
		idx, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("secretgen: read random: %w", err)
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

// expandCharset turns an alphabet string into a deduplicated rune set, treating
// "X-Y" as an inclusive range. A trailing or non-ascending "-" is literal.
func expandCharset(s string) []rune {
	r := []rune(s)
	seen := make(map[rune]bool, len(r))
	var out []rune
	add := func(c rune) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for i := 0; i < len(r); i++ {
		if i+2 < len(r) && r[i+1] == '-' && r[i] <= r[i+2] {
			for c := r[i]; c <= r[i+2]; c++ {
				add(c)
			}
			i += 2
			continue
		}
		add(r[i])
	}
	return out
}
