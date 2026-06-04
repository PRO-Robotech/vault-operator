/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func setCondition(conditions *[]metav1.Condition, condType string, status metav1.ConditionStatus, observedGeneration int64, reason, message string) {
	apimeta.SetStatusCondition(conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: observedGeneration,
		Reason:             reason,
		Message:            message,
	})
}

func findConditionStatus(conditions []metav1.Condition, condType string) metav1.ConditionStatus {
	if c := apimeta.FindStatusCondition(conditions, condType); c != nil {
		return c.Status
	}
	return ""
}

func isConditionTrue(conditions []metav1.Condition, condType string) bool {
	return findConditionStatus(conditions, condType) == metav1.ConditionTrue
}
