/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"fmt"
	"os"
	"strings"
)

// JWTSource produces a ServiceAccount JWT for Vault's Kubernetes Auth Method.
// It is invoked on every login/re-login, so implementations should be cheap —
// in-cluster pods read a kubelet-rotated projected volume on each call.
type JWTSource interface {
	JWT() (string, error)
}

// FileJWTSource reads the JWT from disk on each call so kubelet rotation
// of a projected token volume is picked up transparently.
type FileJWTSource struct {
	Path string
}

const DefaultProjectedTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// NewFileJWTSource returns a source reading the given path; an empty path
// falls back to DefaultProjectedTokenPath.
func NewFileJWTSource(path string) *FileJWTSource {
	if path == "" {
		path = DefaultProjectedTokenPath
	}
	return &FileJWTSource{Path: path}
}

func (s *FileJWTSource) JWT() (string, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return "", fmt.Errorf("read JWT from %s: %w", s.Path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("JWT file %s is empty", s.Path)
	}
	return token, nil
}

// StaticJWTSource is tests-only.
type StaticJWTSource string

func (s StaticJWTSource) JWT() (string, error) {
	if s == "" {
		return "", fmt.Errorf("static JWT is empty")
	}
	return string(s), nil
}
