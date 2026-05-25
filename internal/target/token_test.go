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
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

// fakeClientsetWithToken returns a kubernetes fake.Clientset whose
// CreateToken always returns the given token + expiration.
func fakeClientsetWithToken(token string, expiresAt time.Time) *fake.Clientset {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "serviceaccounts/token", func(action ktesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(ktesting.CreateAction)
		if !ok {
			return false, nil, errors.New("unexpected action type")
		}
		tr, ok := ca.GetObject().(*authenticationv1.TokenRequest)
		if !ok {
			return false, nil, errors.New("unexpected object type")
		}
		out := tr.DeepCopy()
		out.Status.Token = token
		out.Status.ExpirationTimestamp = metav1.NewTime(expiresAt)
		return true, out, nil
	})
	return cs
}

func TestIssueReviewerJWT_HappyPath(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	kc := fakeClientsetWithToken("issued-jwt", expiresAt)
	cs := &ClientSet{Kubernetes: kc}

	claim := newSampleClaim()
	claim.Spec.Auth.TokenReviewer.TTL = metav1.Duration{Duration: 12 * time.Hour}

	got, err := IssueReviewerJWT(context.Background(), cs, claim)
	if err != nil {
		t.Fatalf("IssueReviewerJWT: %v", err)
	}
	if got.Token != "issued-jwt" {
		t.Errorf("Token = %q, want %q", got.Token, "issued-jwt")
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiresAt)
	}

	// Validate that the TTL we asked for was passed through to the apiserver.
	actions := kc.Actions()
	if len(actions) == 0 {
		t.Fatal("no actions recorded")
	}
	createAction, ok := actions[0].(ktesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[0])
	}
	tr := createAction.GetObject().(*authenticationv1.TokenRequest)
	if tr.Spec.ExpirationSeconds == nil || *tr.Spec.ExpirationSeconds != int64(12*60*60) {
		t.Errorf("ExpirationSeconds = %v, want %d", tr.Spec.ExpirationSeconds, 12*60*60)
	}
	// Reviewer JWT must be minted WITHOUT an audience override so the target
	// apiserver accepts it for TokenReview API authentication. See
	// IssueReviewerJWT docstring.
	if len(tr.Spec.Audiences) != 0 {
		t.Errorf("Audiences = %v, want empty (apiserver default)", tr.Spec.Audiences)
	}
}

func TestIssueReviewerJWT_DefaultTTL(t *testing.T) {
	kc := fakeClientsetWithToken("t", time.Now().Add(time.Hour))
	cs := &ClientSet{Kubernetes: kc}

	claim := newSampleClaim()
	// TTL left at zero value → expect 24h default.

	if _, err := IssueReviewerJWT(context.Background(), cs, claim); err != nil {
		t.Fatalf("issue: %v", err)
	}
	tr := kc.Actions()[0].(ktesting.CreateAction).GetObject().(*authenticationv1.TokenRequest)
	if tr.Spec.ExpirationSeconds == nil || *tr.Spec.ExpirationSeconds != int64(24*60*60) {
		t.Errorf("default ExpirationSeconds = %v, want %d", tr.Spec.ExpirationSeconds, 24*60*60)
	}
}

func TestIssueReviewerJWT_PropagatesAPIError(t *testing.T) {
	kc := fake.NewClientset()
	kc.PrependReactor("create", "serviceaccounts/token", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	cs := &ClientSet{Kubernetes: kc}

	claim := newSampleClaim()
	_, err := IssueReviewerJWT(context.Background(), cs, claim)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIssueReviewerJWT_ErrorsOnEmptyToken(t *testing.T) {
	kc := fake.NewClientset()
	kc.PrependReactor("create", "serviceaccounts/token", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenRequest{}, nil
	})
	cs := &ClientSet{Kubernetes: kc}

	claim := newSampleClaim()
	_, err := IssueReviewerJWT(context.Background(), cs, claim)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestShouldRotateReviewerJWT(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name   string
		status *vaultv1alpha1.TokenReviewerJWTStatus
		want   bool
	}{
		{
			name:   "nil status — must rotate",
			status: nil,
			want:   true,
		},
		{
			name: "missing issuedAt — must rotate",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				ExpiresAt: ptrTime(now.Add(time.Hour)),
			},
			want: true,
		},
		{
			name: "missing expiresAt — must rotate",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt: ptrTime(now.Add(-time.Hour)),
			},
			want: true,
		},
		{
			name: "expired — must rotate",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(now.Add(-24 * time.Hour)),
				ExpiresAt: ptrTime(now.Add(-time.Minute)),
			},
			want: true,
		},
		{
			name: "fresh (95% remaining) — keep",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(now.Add(-time.Hour)),
				ExpiresAt: ptrTime(now.Add(23 * time.Hour)),
			},
			want: false,
		},
		{
			name: "exactly 30% remaining — rotate (boundary)",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(now.Add(-70 * time.Minute)),
				ExpiresAt: ptrTime(now.Add(30 * time.Minute)),
			},
			// 30/100 = 30% remaining → not < 30% → keep
			want: false,
		},
		{
			name: "29% remaining — rotate",
			status: &vaultv1alpha1.TokenReviewerJWTStatus{
				IssuedAt:  ptrTime(now.Add(-71 * time.Minute)),
				ExpiresAt: ptrTime(now.Add(29 * time.Minute)),
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRotateReviewerJWT(tc.status, now); got != tc.want {
				t.Errorf("ShouldRotateReviewerJWT = %v, want %v", got, tc.want)
			}
		})
	}
}

func ptrTime(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}
