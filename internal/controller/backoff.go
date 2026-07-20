/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// stepBackoff grows the requeue interval for a claim that keeps failing the
// same pipeline step, so an unreachable target is probed at a decaying rate
// instead of a fixed cadence (k8s-625). In-memory: a restart resets to base.
type stepBackoff struct {
	mu      sync.Mutex
	entries map[types.NamespacedName]*backoffEntry
}

type backoffEntry struct {
	step     string
	failures int
}

// Next records a failure of step and returns base doubled per consecutive
// failure of that same step, capped at max. A failure of a different step
// restarts from base — the pipeline made progress since.
func (b *stepBackoff) Next(key types.NamespacedName, step string, base, max time.Duration) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.entries == nil {
		b.entries = make(map[types.NamespacedName]*backoffEntry)
	}
	e := b.entries[key]
	if e == nil || e.step != step {
		e = &backoffEntry{step: step}
		b.entries[key] = e
	}
	e.failures++
	d := base << uint(min(e.failures-1, 16))
	if d <= 0 || d > max {
		d = max
	}
	return d
}

func (b *stepBackoff) Reset(key types.NamespacedName) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}
