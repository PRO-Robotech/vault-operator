/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/PRO-Robotech/vault-operator/internal/vault"
)

// Reasons a VaultClaim is refused rather than retried. Each one means "the new
// operator declines what v0.0.9 would have applied"; a rollback to v0.0.9 is
// allowed only while no claim carries any of them (docs/user-guide/rollback.md).
const (
	// ReasonOwnershipConflict: a policy, role, Transit key or KV prefix the
	// claim declares belongs to another claim, is reserved, or already exists
	// in Vault without being in this claim's ledger.
	ReasonOwnershipConflict = "OwnershipConflict"
	// ReasonPolicyGuardViolation: a policy body is outside the claim's classes
	// and --policy-guard=enforce refused to write it.
	ReasonPolicyGuardViolation = "PolicyGuardViolation"
	// ReasonPolicyReferenceForbidden: a role references a policy the claim does
	// not declare and that is not on the external allow-list.
	ReasonPolicyReferenceForbidden = "PolicyReferenceForbidden"
	// ReasonMountConflict: the auth mount belongs to the operator, to another
	// claim, or to something that is not this claim.
	ReasonMountConflict = "MountConflict"
	// ReasonKeyAdoptionRestricted: spec asks to make exportable, or allow
	// plaintext backup of, a Transit key the claim did not create.
	ReasonKeyAdoptionRestricted = "KeyAdoptionRestricted"
	// ReasonMountNotOwned (deletion only): the mount was left in place because
	// sys/auth does not show it as this claim's.
	ReasonMountNotOwned = "MountNotOwned"
	// ReasonForeignReviewer: the token reviewer ServiceAccount or its binding
	// in the target cluster exists without this claim's labels. The legacy
	// release force-applied over it.
	ReasonForeignReviewer = "ForeignReviewer"
)

// ReasonAuthMountAccessorChanged (event): the claim's auth mount has another
// accessor than its templated policies were rendered with; they are rendered
// again. Not a refusal.
const ReasonAuthMountAccessorChanged = "AuthMountAccessorChanged"

// ReasonMountNotConfigured: a guest claim waits for its host mount to exist,
// be a kubernetes mount and carry kubernetes_host. Not a refusal: the claim
// proceeds once the owner configures the mount.
const ReasonMountNotConfigured = "MountNotConfigured"

// ReasonRenderFailed: a policy's rules do not render — a template form
// outside the closed set, rules past the length limit, a body past the size
// limit, a Vault template written unescaped, a parse error. The outcome is
// decided by spec and the auth mount accessor, so the claim is refused, not
// retried: it is rendered again when spec changes or when
// RequeueClaimRenderRefused has passed (renderRefusals).
const ReasonRenderFailed = "RenderFailed"

// ReasonReconciled: Degraded=False after a pass that completed.
const ReasonReconciled = "Reconciled"

// RefusalReasons is the closed set the rollback gate counts.
var RefusalReasons = []string{
	ReasonOwnershipConflict,
	ReasonPolicyGuardViolation,
	ReasonPolicyReferenceForbidden,
	ReasonMountConflict,
	ReasonKeyAdoptionRestricted,
	ReasonMountNotOwned,
	ReasonForeignReviewer,
}

// Failure causes, a closed set. Conditions and events carry the cause text,
// never the raw error: transport errors embed the Vault and target-cluster
// addresses, and status is readable by everyone who can read the claim. The
// raw error goes to the log at V(1).
type failureCause string

const (
	causeTimeout      failureCause = "Timeout"
	causeUnreachable  failureCause = "Unreachable"
	causeTLS          failureCause = "TLS"
	causeCircuitOpen  failureCause = "CircuitOpen"
	causeSealed       failureCause = "Sealed"
	causeNotLoggedIn  failureCause = "NotLoggedIn"
	causeForbidden    failureCause = "Forbidden"
	causeNotFound     failureCause = "NotFound"
	causeBadRequest   failureCause = "BadRequest"
	causeConflict     failureCause = "Conflict"
	causeServerError  failureCause = "ServerError"
	causeUnclassified failureCause = "Unclassified"
)

var causeText = map[failureCause]string{
	causeTimeout:      "the remote endpoint did not answer in time",
	causeUnreachable:  "the remote endpoint is unreachable",
	causeTLS:          "the TLS handshake with the remote endpoint failed",
	causeCircuitOpen:  "Vault calls are paused by the circuit breaker after repeated failures",
	causeSealed:       "Vault is sealed or not initialized",
	causeNotLoggedIn:  "the operator has no Vault token",
	causeForbidden:    "the request was denied (forbidden)",
	causeNotFound:     "the requested object does not exist",
	causeBadRequest:   "the request was rejected as invalid",
	causeConflict:     "the request conflicted with the current state",
	causeServerError:  "the remote endpoint returned a server error",
	causeUnclassified: "the request failed; see the operator log for details",
}

// classifyFailure maps an error to its cause. Order matters: a timeout is also
// a net.Error, and a breaker short-circuit wraps the last transport error.
func classifyFailure(err error) failureCause {
	switch {
	case err == nil:
		return causeUnclassified
	case vault.IsCircuitOpen(err):
		return causeCircuitOpen
	case errors.Is(err, vault.ErrSealed), errors.Is(err, vault.ErrUninitialized):
		return causeSealed
	case errors.Is(err, vault.ErrNotLoggedIn):
		return causeNotLoggedIn
	}
	var apiErr *vault.APIError
	if errors.As(err, &apiErr) {
		return classifyVaultStatus(apiErr)
	}
	if c, ok := classifyKubernetes(err); ok {
		return c
	}
	return classifyTransport(err)
}

func classifyVaultStatus(apiErr *vault.APIError) failureCause {
	switch {
	case apiErr.StatusCode == 403 || apiErr.StatusCode == 401:
		return causeForbidden
	case apiErr.StatusCode == 404:
		return causeNotFound
	case apiErr.StatusCode == 400:
		return causeBadRequest
	case apiErr.StatusCode == 409 || apiErr.StatusCode == 412:
		return causeConflict
	case apiErr.StatusCode == 503 && len(apiErr.Errors) > 0 && apiErr.Errors[0] == "Vault is sealed":
		return causeSealed
	case apiErr.StatusCode >= 500:
		return causeServerError
	}
	return causeUnclassified
}

func classifyKubernetes(err error) (failureCause, bool) {
	switch {
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return causeForbidden, true
	case apierrors.IsNotFound(err):
		return causeNotFound, true
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return causeConflict, true
	case apierrors.IsBadRequest(err), apierrors.IsInvalid(err):
		return causeBadRequest, true
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return causeTimeout, true
	case apierrors.IsInternalError(err), apierrors.IsServiceUnavailable(err):
		return causeServerError, true
	}
	return "", false
}

func classifyTransport(err error) failureCause {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return causeTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return causeTimeout
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) || errors.As(err, &certInvalid) {
		return causeTLS
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return causeUnreachable
	}
	return causeUnclassified
}

// failureText is the table message for err: the same text for every error of
// one cause, with no part of the raw error in it.
func failureText(err error) string {
	return causeText[classifyFailure(err)]
}

// statusError is an error whose text is built from the claim's spec and from
// cause texts only, so status and events may carry it as it is.
type statusError struct{ text string }

func (e *statusError) Error() string { return e.text }

func statusErrorf(format string, a ...any) error {
	return &statusError{text: fmt.Sprintf(format, a...)}
}

// statusText is what status and events say about err: a statusError as it
// is, any other error as its cause text.
func statusText(err error) string {
	var se *statusError
	if errors.As(err, &se) {
		return se.text
	}
	return failureText(err)
}
