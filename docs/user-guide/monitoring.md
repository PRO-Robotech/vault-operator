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
| `vaultclaim_drift_detected_total` | Drift events per category | `drift_type` ∈ {`mount`, `policy`, `role`} |
| `vault_reviewer_jwt_renewal_total` | Reviewer JWT lifecycle | `result` ∈ {`rotated`, `skipped`, `failed`} |
| `vault_api_responses_total` | HTTP-ответы Vault | `verb`, `path`, `code` |
| `vault_api_calls_total` | Вызовы оператора в Vault | `verb`, `path`, `result` |
| `vault_client_token_renewal_total` | Лайфцикл client_token оператора | `result` |
| `controller_runtime_*` | Стандартные controller-runtime | `controller`, `result` |

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
