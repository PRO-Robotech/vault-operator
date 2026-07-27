# Pipeline reconcile VaultClaim

Каждый reconcile VaultClaim — это последовательность из 7 шагов. Шаги идемпотентны, выполняются по очереди, любой может вернуть `Wait` (ждём внешнего события) или транзиентную ошибку (повтор через `RequeueAfter`).

## Шаги

| # | Шаг | Что делает | Возможные ошибки |
|---|---|---|---|
| 1 | **ResolveConfigAndLogin** | Получает VaultConfig из spec, проверяет что он `Reachable=True` и `SharedMountFound=True`, логинится в Vault | VaultConfig не найден → `ConfigResolved=False`; sealed/network → `VaultReachable=False` |
| 2 | **WaitKubeconfig** | Достаёт Secret `{clusterRef.kubeconfigSecret}` из namespace claim'а | Secret отсутствует → `KubeconfigAvailable=False`, ждём watch-события |
| 3 | **EnsureTargetSA** | Через kubeconfig применяет (SSA) Namespace + SA `vault-token-reviewer` + ClusterRoleBinding `system:auth-delegator` в infra-кластере. Только когда `tokenReviewer.serviceAccount.autoCreate: true` | apiserver недоступен → транзиент, retry |
| 4 | **IssueReviewerJWT** | Вызывает TokenRequest API: новый JWT для reviewer SA. Только если предыдущий ближе чем 30% TTL к expiry | TokenRequest 4xx/5xx → транзиент |
| 5 | **EnableAuthMount** | `POST sys/auth/{mount}` (на 400 «уже существует» — продолжаем). Затем `POST auth/{mount}/config` с `kubernetes_host`, `kubernetes_ca_cert`, `token_reviewer_jwt`, `issuer` (или `disable_iss_validation=true`) | Vault 5xx → `AuthMountReady=False`, retry |
| 6 | **ApplyPolicies** | Для каждой `spec.policies[]` — `PUT sys/policies/acl/{name}`. Если в HCL встречается `{{ .AuthMountAccessor }}`, accessor лениво забирается из `GET sys/auth` | Невалидный HCL → 400 `PutPolicyFailed`, retry |
| 7 | **ApplyRoles** | Для каждой `spec.roles[]` — `POST auth/{mount}/role/{name}`. После — `LIST auth/{mount}/role` и удаление имён, которых нет в `spec.roles[]` (soft-purge) | Vault 5xx → `RolesApplied=False`, retry |

После 7-го шага: `Phase=Ready`, `Ready=True`, RequeueAfter **10 минут** (drift detection).

## Drift detection

Когда reconcile срабатывает уже на `Ready` claim'е и `metadata.generation` не менялся, после шага 1 запускается **read-only drift-проверка**:

| Проверка | Что считается drift |
|---|---|
| `ListAuthMounts` | Auth-mount `{spec.auth.mountPath}/` отсутствует |
| `ListPolicies` | Любое имя из `spec.policies[].name` отсутствует |
| `ListKubernetesRoles` | Любая роль из spec отсутствует или есть лишняя в Vault |

- **Нет drift** → claim сразу остаётся `Ready`, шаги 2-7 не выполняются (экономия Vault-запросов).
- **Есть drift** → событие `DriftDetected`, метрика `vaultclaim_drift_detected_total{drift_type=mount|policy|role}` инкрементируется, дальше идёт полный pipeline и идемпотентные шаги выравнивают состояние.

`status.vault.lastDriftCheckAt` обновляется в обоих случаях (персистится не чаще heartbeat-интервала, см. ниже).

## RequeueAfter интервалы

| Ситуация | RequeueAfter |
|---|---|
| Pipeline успешно завершён | 10 min (drift detection) |
| Vault API ошибка / login fail | 30 sec × 2ⁿ, cap 10 min |
| Ждём kubeconfig-секрет (есть watch, это fallback) | 5 min |
| Прочие транзиентные ошибки | 1 min × 2ⁿ, cap 10 min |
| Reverse pipeline застрял на Vault | 1 min |

Повторные транзиентные фейлы **одного и того же шага** одного claim'а удваивают интервал до cap 10 min (in-memory; сбрасывается при успехе шага, смене падающего шага или рестарте оператора). Circuit-open Vault-клиента вместо этого выравнивается на следующий probe breaker'а.

## Status heartbeat

Timestamps `lastReconcileAt` / `lastDriftCheckAt` / `tokenReviewerJWT.lastRotationAttempt` сами по себе **не** считаются изменением статуса: они персистятся вместе с содержательными изменениями либо отдельным heartbeat-патчем не чаще раза в 10 минут. Иначе status-patch каждого reconcile порождал watch-событие → немедленный re-enqueue, превращая RequeueAfter в мёртвый код (k8s-625: ретраи к мёртвому кластеру ровно каждые ~40 s без затухания).

## Watches и event-driven продвижение

Помимо периодического 10-минутного цикла, reconcile запускается на события:

- Изменение `VaultClaim` (стандартный `For()`)
- Изменение `VaultConfig` — каскад на все ссылающиеся claim'ы (cascade reconcile)
- Создание/обновление Secret `*-infra-kubeconfig` в том же namespace — реконсилит зависимые claim'ы

Это позволяет, например, сразу проснуться когда `ClusterClaim` опубликовал kubeconfig, а не ждать 5-минутный fallback.

## Reverse pipeline (удаление)

При `metadata.deletionTimestamp` запускается обратный порядок:

```
Phase=Deleting
   │
   ▼
1. Удаляем все роли по объединению (status.appliedRoles ∪ spec.roles)
2. Удаляем все политики по объединению (status.appliedPolicies ∪ spec.policies)
3. DELETE sys/auth/{mount}
4. Best-effort: удаляем SA + ClusterRoleBinding в infra-кластере
5. Снимаем finalizer
```

- Ошибки Vault на шагах 1-3 → finalizer **не снимается**, событие `DeletionStuck`, повтор через 1 min.
- Ошибки в infra-кластере на шаге 4 — события `TargetCleanupBestEffort`, но finalizer всё равно снимается (D12) — оставить SA «висеть» лучше, чем застрять в `Deleting` навсегда.

## Sealed Vault: цепная блокировка

Когда `VaultConfig.status` сообщает `VaultUnsealed=False`:

```
VaultConfig: Reachable=True, VaultUnsealed=False, ManagerLoggedIn=False
                │
                ▼ каскад
VaultClaim:    ConfigResolved=False (reason: VaultUnsealed)
                │
                ▼
               RequeueAfter 1 min (RequeueClaimTransient)
```

Шаги 2-7 даже не пытаются выполняться — это защищает Vault от 503-шторма во время расшифровки.

## Связанные документы

- [VaultClaim](vaultclaim.md) — ресурс, на котором работает pipeline
- [VaultConfig](vaultconfig.md) — источник Vault-клиента и health-статуса
- [Auth & Policies](auth-and-policies.md) — что именно создаётся в Vault на шагах 5-7
- [Troubleshooting](../troubleshooting.md) — диагностика застрявшего pipeline
