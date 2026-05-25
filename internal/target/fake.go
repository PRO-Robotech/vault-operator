/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package target

import (
	"context"
	"errors"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// FakeManager is a Manager used by reconciler tests; lives in the production
// package so the controller package's integration tests can import it.
type FakeManager struct {
	Set *ClientSet
	Err error

	mu       sync.Mutex
	GetCalls int
}

func (f *FakeManager) Get(_ context.Context, _ *corev1.Secret) (*ClientSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.GetCalls++
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Set == nil {
		return nil, errors.New("FakeManager: Set is not configured")
	}
	return f.Set, nil
}
