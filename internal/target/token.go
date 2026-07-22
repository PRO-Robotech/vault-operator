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
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// IssuedJWT carries the result of a TokenRequest. ExpiresAt is the
// server-reported expiration (not issued-at + TTL — kube-apiserver may
// truncate to a maximum bound, so we always trust what it tells us).
type IssuedJWT struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssueReviewerJWT mints a short-lived JWT for the token-reviewer
// ServiceAccount via TokenRequest. The token bytes MUST NOT be persisted
// to VaultClaim.status; only IssuedAt / ExpiresAt are public.
//
// Audience semantics: the reviewer JWT is what Vault sends back to the
// target apiserver when it calls TokenReview. apiserver validates the
// aud claim against --api-audiences (which defaults to
// --service-account-issuer). We therefore mint WITHOUT an explicit
// audience override — TokenRequest will issue with the apiserver's default
// audience, which the apiserver itself accepts. Setting Audiences=["vault"]
// produces a JWT Vault stores happily
// but the apiserver rejects with 401 during TokenReview → consumer pods
// see "permission denied".
func IssueReviewerJWT(ctx context.Context, cs *ClientSet, claim *vaultv1alpha1.VaultClaim, now time.Time) (*IssuedJWT, error) {
	ref := claim.Spec.Auth.TokenReviewer.ServiceAccount
	if ref.Namespace == "" || ref.Name == "" {
		return nil, fmt.Errorf("tokenReviewer.serviceAccount is required")
	}

	ttl := claim.Spec.Auth.TokenReviewer.TTL.Duration
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	seconds := int64(ttl.Seconds())
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			// No Audiences override on purpose — see function docstring.
			ExpirationSeconds: &seconds,
		},
	}

	resp, err := cs.Kubernetes.CoreV1().
		ServiceAccounts(ref.Namespace).
		CreateToken(ctx, ref.Name, req, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("TokenRequest for %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	if resp.Status.Token == "" {
		return nil, fmt.Errorf("TokenRequest returned empty token for %s/%s", ref.Namespace, ref.Name)
	}

	expiresAt := resp.Status.ExpirationTimestamp.Time
	if expiresAt.IsZero() {
		// Older apiservers and fake clients without a reactor omit the
		// timestamp — fall back to issuedAt + ttl.
		expiresAt = now.Add(ttl)
	}
	return &IssuedJWT{
		Token:     resp.Status.Token,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}, nil
}

// ShouldRotateReviewerJWT returns true when the recorded reviewer JWT is past
// the 30%-of-TTL freshness threshold, is missing, or has
// expired. Pure function — pass time.Now in production, a fixed time in tests.
func ShouldRotateReviewerJWT(status *vaultv1alpha1.TokenReviewerJWTStatus, now time.Time) bool {
	if status == nil || status.IssuedAt == nil || status.ExpiresAt == nil {
		return true
	}
	issuedAt := status.IssuedAt.Time
	expiresAt := status.ExpiresAt.Time
	if !expiresAt.After(now) {
		return true
	}
	total := expiresAt.Sub(issuedAt)
	if total <= 0 {
		return true
	}
	remaining := expiresAt.Sub(now)
	return remaining*100 < total*30
}
