/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	vaultv1alpha1 "github.com/PRO-Robotech/vault-operator/api/v1alpha1"
	"github.com/PRO-Robotech/vault-operator/internal/target"
)

// VaultClaimReconciler reconciles a VaultClaim through its pipeline.
// VaultFactory and TargetManager are injected so tests
// can substitute fakes.
type VaultClaimReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	VaultFactory  VaultClientFactory
	TargetManager target.Manager

	// Now is an injectable clock for tests. nil → time.Now.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=vault.in-cloud.io,resources=vaultconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *VaultClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("vaultclaim", req.NamespacedName)

	claim := &vaultv1alpha1.VaultClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get VaultClaim: %w", err)
	}

	if !claim.DeletionTimestamp.IsZero() {
		// Persist status (Phase=Deleting, conditions) even when handleDeletion
		// requeues due to a stuck Vault.
		oldStatus := claim.Status.DeepCopy()
		res, err := r.handleDeletion(ctx, claim)
		if statusErr := r.updateStatusIfChanged(ctx, claim, oldStatus); statusErr != nil {
			logger.V(1).Info("status update during deletion (will retry)", "err", statusErr.Error())
		}
		return res, err
	}

	if controllerutil.AddFinalizer(claim, vaultv1alpha1.VaultClaimFinalizer) {
		if err := r.Update(ctx, claim); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	oldStatus := claim.Status.DeepCopy()

	result := r.executePipeline(ctx, claim)

	claim.Status.ObservedGeneration = claim.Generation
	if claim.Status.Vault == nil {
		claim.Status.Vault = &vaultv1alpha1.VaultStatusSummary{}
	}
	claim.Status.Vault.LastReconcileAt = ptrTime(r.now())

	if err := r.updateStatusIfChanged(ctx, claim, oldStatus); err != nil {
		logger.V(1).Info("status update conflict (will retry)", "err", err.Error())
	}

	return result, nil
}

// updateStatusIfChanged skips no-op writes to avoid ResourceVersion churn that
// would re-trigger the For() watch.
func (r *VaultClaimReconciler) updateStatusIfChanged(ctx context.Context, claim *vaultv1alpha1.VaultClaim, old *vaultv1alpha1.VaultClaimStatus) error {
	if apiequality.Semantic.DeepEqual(old, &claim.Status) {
		return nil
	}
	return r.Status().Update(ctx, claim)
}

func (r *VaultClaimReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *VaultClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultv1alpha1.VaultClaim{}).
		Watches(
			&vaultv1alpha1.VaultConfig{},
			handler.EnqueueRequestsFromMapFunc(r.findClaimsForVaultConfig),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findClaimsForSecret),
			builder.WithPredicates(kubeconfigSecretPredicate()),
		).
		Named("vaultclaim").
		Complete(r)
}
