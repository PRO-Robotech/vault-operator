# Наблюдаемость

Что мониторить в работающем Vault Operator: conditions, события, метрики, рекомендуемые алёрты.

## Conditions

Самый быстрый путь увидеть состояние — `kubectl describe` или JSONPath:

```bash
# Все VaultClaim'ы с не-Ready состоянием
kubectl get vaultclaim -A -o json | \
  jq -r '.items[] | select(.status.phase != "Ready") | "\(.metadata.namespace)/\(.metadata.name): \(.status.phase)"'

# Конкретные False-conditions
kubectl get vaultclaim ec8a00 -n dlputi1u \
  -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}: {.reason} — {.message}{"\n"}{end}'
```

Полный список conditions — [reference/api.md](../reference/api.md#conditions-vaultclaim).

## События

```bash
kubectl get events -n dlputi1u --field-selector involvedObject.kind=VaultClaim
```

Важные события:

| Reason | Type | Что делать |
|---|---|---|
| `StepRetrying` | Warning | Транзиентная ошибка шага — обычно само пройдёт. Если повторяется часто — проверьте Vault и сеть. |
| `DriftDetected` | Warning | Кто-то менял Vault снаружи; оператор сам выровняет. Если повторяется — найдите источник. |
| `DeletionStuck` | Warning | Reverse pipeline не может удалить из Vault — проверьте доступность Vault и права оператора. |
| `TargetCleanupBestEffort` | Warning | Infra-кластер недоступен при удалении claim'а; SA останется висеть. Не критично, но стоит почистить. |
| `ReviewerJWTRotated` | Normal | Норма раз в ~16 часов (при TTL 24h и threshold 30%). |
| `RolesPurged` | Normal | Soft-purge удалил роли — норма после изменения `spec.roles[]`. |

## Метрики

Все метрики Prometheus экспонируются через `/metrics` endpoint controller-runtime. По умолчанию защищены TLS + authn/authz (`--metrics-secure=true`).

### Список метрик

| Метрика | Описание | Labels |
|---|---|---|
| `vaultclaim_drift_detected_total` | Drift events per category | `drift_type` ∈ {`mount`, `policy`, `role`, `transit_key`, `role_body`, `policy_body`, `auth_config`} |
| `vault_reviewer_jwt_renewal_total` | Reviewer JWT lifecycle | `result` ∈ {`rotated`, `skipped`, `failed`} |
| `vault_api_responses_total` | HTTP-ответы Vault | `verb`, `path`, `code` |
| `vault_api_calls_total` | Вызовы оператора в Vault | `verb`, `path`, `result` |
| `vault_client_token_renewal_total` | Лайфцикл client_token оператора: вход, renew, revoke заменённого токена, токена, сброшенного после 403 (для токена, который Vault уже не принимает, — `revoke_failed`), и токенов при останове | `result` ∈ {`login_success`, `login_failed`, `renew_success`, `renew_failed`, `revoke_success`, `revoke_failed`} |
| `vault_api_request_duration_seconds` | Гистограмма задержки вызовов Vault | `verb`, `path`, `result` |
| `vault_circuit_state` | Состояние circuit breaker клиента Vault: 0 closed, 1 half-open, 2 open | `vault_config` |
| `vault_operator_pipeline_step_total` | Исходы шагов pipeline VaultClaim: `Proceed`, `Wait`, `Refused` или причина сбоя из закрытого набора (`Timeout`, `Unreachable`, `TLS`, `CircuitOpen`, …) | `step`, `outcome` |
| `vault_operator_claims` | Заявки по фазам, считаются из кэша в момент scrape | `kind`, `phase` |
| `vault_operator_managed_objects` | Объекты Vault, записанные в журналах заявок | `kind`, `type` ∈ {`policy`, `role`, `transit_key`, `bucket`, `secret_item`} |
| `vault_operator_inventory_errors` | 1, если scrape не смог прочитать заявки вида | `kind` |
| `vault_operator_cloudmanager_request_duration_seconds` | bucket-operator: гистограмма задержки вызовов cloud-manager | `method`, `code` |
| `vault_operator_s3bucketclaim_owner_unverified_total` | bucket-operator: cloud-manager вернул записанный бакет без логина владельца. Удаление такого бакета блокируется (`DeletionBlocked`), поэтому ненулевой рост — повод разобраться до удаления кластеров | — |
| `vault_operator_cloudmanager_remove_unknown_response_total` | bucket-operator: `removeBucket` ответил текстом вне словаря (`Not found`, `Already removed`) — удаление считается неудавшимся (`DeletionStuck`) | — |
| `controller_runtime_*` | Стандартные controller-runtime | `controller`, `result` |

Число серий всех метрик ограничено видом заявки, фазой, VaultConfig и path-bucket и не растёт с числом заявок. Метрики заявок отдаёт каждая реплика, поэтому в правилах берётся `max`, а не `sum`. Готовые правила алертов — `config/prometheus/alerts.yaml`.

Path-label в `vault_api_*` нормализован через bucketing — `auth_login`, `auth_role`, `sys_mounts`, `sys_policies_acl`, и т.д. — чтобы cardinality оставалась bounded.

Code-label буцкетится в `2xx`/`3xx`/`4xx`/`5xx`, но `401`, `403`, `404` сохраняют конкретные значения (для алёртинга по auth/permission/missing).

### Полезные PromQL

```promql
# Rate ошибок 5xx по endpoint'ам
sum by (path) (rate(vault_api_responses_total{code="5xx"}[5m]))

# 403 (нет прав) — критично для diagnose
sum by (path) (rate(vault_api_responses_total{code="403"}[5m]))

# Дрейф любой категории (должен быть 0)
sum by (drift_type) (rate(vaultclaim_drift_detected_total[15m]))

# Провалы ротации reviewer JWT
rate(vault_reviewer_jwt_renewal_total{result="failed"}[5m])

# Провалы login'а оператора (если стабильно > 0 — Vault или роль сломаны)
rate(vault_client_token_renewal_total{result="login_failed"}[5m])

# Доля 5xx от всех Vault-вызовов
sum(rate(vault_api_calls_total{result="server_error"}[5m]))
  / sum(rate(vault_api_calls_total[5m]))
```

## Рекомендуемые алёрты

### Критичные (page)

```promql
# Vault недоступен — оператор вообще не может работать
- alert: VaultOperatorVaultUnreachable
  expr: |
    rate(vault_api_calls_total{result="transport_error"}[5m]) > 0.1
  for: 5m
  annotations:
    summary: "Vault unreachable from vault-operator (transport errors)"

# Provider login сломан → ни один claim не reconcilится
- alert: VaultOperatorLoginFailing
  expr: |
    rate(vault_client_token_renewal_total{result="login_failed"}[5m]) > 0
  for: 5m
  annotations:
    summary: "vault-operator cannot login to Vault"

# Reviewer JWT не ротируется → consumer pods начнут получать 401 после expiry
- alert: VaultOperatorReviewerJWTRenewalFailing
  expr: |
    rate(vault_reviewer_jwt_renewal_total{result="failed"}[15m]) > 0
  for: 15m
  annotations:
    summary: "Reviewer JWT rotation failing for at least one VaultClaim"
```

### Предупреждения (warn)

```promql
# Постоянный drift — кто-то меняет Vault снаружи
- alert: VaultOperatorPersistentDrift
  expr: |
    rate(vaultclaim_drift_detected_total[30m]) > 0
  for: 30m
  annotations:
    summary: "Persistent drift detected — external mutation of Vault state"

# 403 (нет прав) — оператор не может выполнить шаг
- alert: VaultOperatorForbidden
  expr: |
    rate(vault_api_responses_total{code="403"}[10m]) > 0
  for: 10m
  annotations:
    summary: "vault-operator getting 403 — admin policy may be insufficient"

# Не-Ready claim'ы (любые conditions False)
- alert: VaultClaimNotReady
  expr: |
    kube_customresource_vaultclaim_status_phase{phase!="Ready"} == 1
  for: 15m
  annotations:
    summary: "VaultClaim {{ $labels.name }} not Ready for 15m"
```

> Для последнего нужен `kube-state-metrics` с CRD-плагином — он экспортирует `kube_customresource_*` для любого CRD.

## Логи

Оператор пишет в stdout через zap. Уровни:

- `INFO` — переходы phase, события (тоже эмитятся в Events)
- `V(1)` (debug) — pipeline step waiting, status conflict retries
- `ERROR` — реальные ошибки (Vault недоступен и т.п.)

```bash
kubectl logs -n vault-operator-system -l control-plane=controller-manager --tail=200 -f
```

Для интенсивной диагностики:

```bash
kubectl logs -n vault-operator-system -l control-plane=controller-manager --tail=500 \
  | grep "vaultclaim=dlputi1u/ec8a00"
```

## kubectl describe — что искать

```bash
kubectl describe vaultclaim ec8a00 -n dlputi1u
```

| Секция | На что смотреть |
|---|---|
| `Status.Phase` | `Ready` норма; `Configuring` >5 min — застрял |
| `Status.Conditions` | Все 8 должны быть `True` для Ready |
| `Status.Vault.Token Reviewer JWT.Expires At` | Должно быть в будущем + Last Rotated не позже 16h назад |
| `Status.Vault.Last Drift Check At` | Должно обновляться раз в 10 min |
| `Status.Vault.Applied Policies` / `Applied Roles` | Совпадают со `spec.policies[].name` / `spec.roles[].name` |
| `Events:` | Свежие `Warning` события |

## Связанные документы

- [reference/api.md](../reference/api.md) — все conditions и метрики
- [troubleshooting.md](../troubleshooting.md) — что делать когда что-то сломалось

## Пробы, останов и лимиты

Флаги общие для трёх процессов (vault-operator, vault-secret-operator, bucket-operator).

| Флаг | Дефолт | Назначение |
|---|---|---|
| `--vault-qps`, `--vault-burst` | `100`, `200` | Лимит запросов в Vault на VaultConfig; отрицательный `--vault-qps` снимает лимит. |
| `--vault-max-conns` | `0` | Соединений к Vault на VaultConfig; `0` — большее из 6 и числа воркеров контроллера плюс 2. |
| `--vault-timeout` | `10s` | Дедлайн одного HTTP-вызова Vault. |
| `--requeue-jitter` | `0.15` | Интервал повтора растягивается на случайную долю до этой, чтобы заявки не ходили в Vault одновременно. |
| `--reconcile-timeout` | `5m` | Дедлайн одного reconcile. |
| `--priority-queue` | `false` | Очередь controller-runtime с приоритетом событий реального изменения над начальным листингом и периодическими повторами. |
| `--graceful-shutdown-timeout` | `25s` | Время на завершение reconcile при останове; держите `terminationGracePeriodSeconds` больше (в манифестах `40`). |
| `--cloud-manager-qps`, `--cloud-manager-burst` | `20`, `40` | bucket-operator: лимит вызовов cloud-manager. |

- `/readyz` проходит, когда синхронизирован кэш информеров.
- `/healthz` падает, пока какой-то reconcile идёт дольше удвоенного `--reconcile-timeout`. Простаивающий процесс здоров.
- Процесс держит один токен Vault на VaultConfig. При останове лидер уступает лидерство, а токены отзываются после остановки контроллеров.
- Лог по умолчанию — JSON уровня info; `--zap-devel` возвращает консольный формат.
