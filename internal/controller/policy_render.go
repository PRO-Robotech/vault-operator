/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"errors"
	"strings"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
)

var errBareIdentity = errors.New("bare identity template")

func renderClaimPolicy(p vaultv1alpha1.PolicySpec, accessor string) (string, error) {
	return renderPolicy(p.Rules, map[string]string{"AuthMountAccessor": accessor})
}

func policyNeedsAccessor(p vaultv1alpha1.PolicySpec) bool {
	return strings.Contains(p.Rules, templateAccessorVar)
}
