/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package secretgen

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Hash kinds mirror the CRD generate.hash enum.
const (
	HashNone   = "none"
	HashBcrypt = "bcrypt"
)

// HashFunc transforms a raw value into its hashed form.
type HashFunc func(raw string) (string, error)

// hashers is extensible: adding a kind does not change the API.
var hashers = map[string]HashFunc{
	HashNone:   func(raw string) (string, error) { return raw, nil },
	HashBcrypt: bcryptHash,
}

// Hash applies the named transform; "none" returns the input unchanged.
func Hash(kind, raw string) (string, error) {
	fn, ok := hashers[kind]
	if !ok {
		return "", fmt.Errorf("secretgen: unknown hash kind %q", kind)
	}
	return fn(raw)
}

// bcryptHash uses Go's default cost (10), yielding the $2a$ prefix Argo CD expects.
func bcryptHash(raw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("secretgen: bcrypt: %w", err)
	}
	return string(b), nil
}
