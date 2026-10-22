# Pipeline reconcile VaultClaim

Каждый reconcile VaultClaim — это последовательность шагов ниже (у гостевой заявки шаги 2–5 заменены проверкой чужого mount, см. [ownership.md](ownership.md)). Шаги идемпотентны, выполняются по очереди, любой может вернуть `Wait` (ждём внешнего события) или транзиентную ошибку (повтор через `RequeueAfter`).

## Шаги

| # | Шаг | Что делает | Возможные ошибки |
|---|---|---|---|
| 1 | **ResolveConfigAndLogin** | Получает VaultConfig из spec, проверяет что он `Reachable=True` и `SharedMountFound=True`, логинится в Vault | VaultConfig не найден → `ConfigResolved=False`; sealed/network → `VaultReachable=False` |
| 2 | **WaitKubeconfig** | Достаёт Secret `{clusterRef.kubeconfigSecret}` из namespace claim'а | Secret отсутствует → `KubeconfigAvailable=False`, ждём watch-события |
| 3 | **EnsureTargetSA** | Через kubeconfig создаёт либо применяет (SSA без force) SA `vault-token-reviewer` + ClusterRoleBinding `system:auth-delegator` в infra-кластере; namespace создаётся, только если его нет. SA или CRB без меток `vault.in-cloud.io/claim-name`/`claim-namespace` этой заявки не трогаются — отказ `ForeignReviewer`. Своё применяется с UID и resourceVersion прочитанного объекта: подменённый после проверки объект apiserver не даст записать. Удаление снимает только свои объекты, с предусловием UID и resourceVersion. Только когда `tokenReviewer.serviceAccount.autoCreate: true` | apiserver недоступен → транзиент, retry |
| 4 | **IssueReviewerJWT** | Вызывает TokenRequest API: новый JWT для reviewer SA — на **каждом** полном проходе, потому что Step 5 перезаписывает `auth/{mount}/config` целиком (запись без `token_reviewer_jwt` стирает рецензента). В `status` JWT записывается только при плановой ротации (остаток < 30% TTL): иначе повтор упавшего claim'а патчил бы статус и обходил backoff | TokenRequest 4xx/5xx → транзиент |
| 1a | **CheckOwnership** | Только Kubernetes: резерв, класс mount, индекс владения против остальных заявок | Конфликт → `Phase=Failed` с причиной из закрытого набора |
| 5 | **EnableAuthMount** | `GET sys/auth`: свой mount (описание этой заявки) — дальше; нет mount — `POST sys/auth/{mount}`; чужой — `MountConflict`. Затем `POST auth/{mount}/config` с `kubernetes_host`, `kubernetes_ca_cert`, `token_reviewer_jwt`, `issuer` (или `disable_iss_validation=true`) | Vault 5xx → `AuthMountReady=False`, retry |
| 6 | **ApplyPolicies** | Ограда правил, затем для имени не из журнала — проверка, что его нет в Vault, патч журнала и `PUT sys/policies/acl/{name}`. Если в HCL встречается `{{ .AuthMountAccessor }}`, accessor лениво забирается из `GET sys/auth` | Невалидный HCL → 400 `PutPolicyFailed`, retry |
| 7 | **ApplyRoles** | Патч журнала, затем для каждой `spec.roles[]` — `POST auth/{mount}/role/{name}` | Vault 5xx → `RolesApplied=False`, retry |
| 8 | **PruneRemoved** | Удаляет роли, затем политики, ушедшие из spec, по журналу (`Exclusive` на своём mount — ещё и роли из `LIST auth/{mount}/role`) | Vault 5xx → retry |

После 7-го шага: `Phase=Ready`, `Ready=True`, RequeueAfter **10 минут** (drift detection).

## Drift detection

Когда reconcile срабатывает уже на `Ready` claim'е и `metadata.generation` не менялся, после шага 1 запускается **read-only drift-проверка**:

| Проверка | Что считается drift |
|---|---|
| `ListAuthMounts` | Auth-mount `{spec.auth.mountPath}/` отсутствует |
| `ListPolicies` | Любое имя из `spec.policies[].name` отсутствует |
| `ListKubernetesRoles` | Любая роль из spec отсутствует или есть лишняя в Vault |
| `ReadKubernetesAuthConfig` | В `auth/{mount}/config` нет рецензента: `token_reviewer_jwt_set=false` |

- **Нет drift** → claim сразу остаётся `Ready`, шаги 2-7 не выполняются (экономия Vault-запросов).
- **Есть drift** → событие `DriftDetected`, метрика `vaultclaim_drift_detected_total{drift_type}` инкрементируется, дальше идёт полный pipeline и идемпотентные шаги выравнивают состояние.

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
1. Удаляем роли из журнала status.appliedRoles (кроме зарезервированных и чужих)
2. Удаляем политики из журнала status.appliedPolicies (кроме зарезервированных и чужих)
3. DELETE sys/auth/{mount} — только если sys/auth показывает его как mount этой заявки
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
