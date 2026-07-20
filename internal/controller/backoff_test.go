/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("stepBackoff", func() {
	var (
		b   *stepBackoff
		key = types.NamespacedName{Namespace: "ns", Name: "claim"}
	)

	BeforeEach(func() {
		b = &stepBackoff{}
	})

	It("doubles per consecutive failure of the same step, capped at max", func() {
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(1 * time.Minute))
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(2 * time.Minute))
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(4 * time.Minute))
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(8 * time.Minute))
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(10 * time.Minute))
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(10 * time.Minute))
	})

	It("stays capped without overflowing on very long failure streaks", func() {
		for i := 0; i < 100; i++ {
			b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		}
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(10 * time.Minute))
	})

	It("restarts from base when a different step fails", func() {
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		Expect(b.Next(key, "ApplyPolicies", time.Minute, 10*time.Minute)).To(Equal(1 * time.Minute))
	})

	It("restarts from base after Reset", func() {
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		b.Reset(key)
		Expect(b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(1 * time.Minute))
	})

	It("tracks claims independently", func() {
		other := types.NamespacedName{Namespace: "ns", Name: "other"}
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		b.Next(key, "EnsureTargetSA", time.Minute, 10*time.Minute)
		Expect(b.Next(other, "EnsureTargetSA", time.Minute, 10*time.Minute)).To(Equal(1 * time.Minute))
	})
})
