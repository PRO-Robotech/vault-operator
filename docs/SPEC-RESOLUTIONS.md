# SPEC-RESOLUTIONS — Принятые решения по vault-operator

> Компактная выжимка из `docs/OPERATOR-SPEC.md` §12. Используется как быстрая ссылка при code review и stories.

| # | Решение | Где в коде / специ |
|---|---------|---------------------|
| **D1** | **Vault OSS** — без Enterprise namespaces. Multi-tenancy через naming convention + path-isolation в policies. | §8 (Топология) |
| **D2** | **Один общий `secret/` KV-v2 mount**, развёрнут платформой разово. Оператор не создаёт mount, только пишет policies, ссылающиеся на `secret/data/clusters/{cluster}/...`. | §0.4, §3.3 (permissions) |
| **D3** | **TokenReview JWT** для валидации pod-токенов. Vault использует `token_reviewer_jwt` SA `vault-token-reviewer` в infra-кластере. JWKS отклонён. | §3.2 |
| **D4** | **TokenRequest API** для получения reviewer JWT, **k8s ≥ 1.34** в infra-кластерах. Audience-scoped, short-lived, автоматическая ротация. | §3.2, `auth.tokenReviewer.ttl` в spec |
| **D5** | **Один VaultClaim на кластер** (1:1 с ClusterClaim). `VaultClaim.metadata.name` = `ClusterClaim.metadata.name`. | §0.2, §0.3 |
| **D6** | **Policies называются `{cluster}-{role}`**, roles — без global prefix (scoped по auth mount). Защита от перезаписи в OSS глобальном namespace policies. | §2.4, проверяется на CEL/в reconcile |
| **D7** | **Данные в KV пишет отдельный оператор** (см. K8S-224). Vault Operator не имеет прав на `secret/data/*` и `secret/metadata/*`. | §3.3 permissions |
| **D8** | **Auto-renew client-token оператора** через `auth/token/renew-self` при достижении 60% TTL. | `internal/vault/client.go` |
| **D9** | **Reviewer JWT** для SA `vault-token-reviewer` выпускается через TokenRequest API с TTL=`spec.auth.tokenReviewer.ttl` (дефолт 24h). Оператор проактивно перевыпускает при остатке < 30%. | §3.2 п.6, `status.vault.tokenReviewerJWT.*` |
| **D10** | **Метрики**: controller-runtime defaults + `vault_api_responses_total{verb,path,code}`, `vault_api_calls_total{verb,path,result}`, `vaultclaim_drift_detected_total`, `vault_client_token_renewal_total`, `vault_reviewer_jwt_renewal_total{result}`. | Story 009 |
| **D11** | **При удалении VaultClaim данные в KV не трогаем**. Policy `vault-operator-admin` это даже технически не позволяет. | §7.2 |
| **D12** | **При удалении VaultClaim token-reviewer SA + CRB в target — best-effort cleanup**, чужие SA не трогаем. | §7.1 reverse pipeline |
| **D13** | **VaultConfig CRD** (Cluster-scoped) — глобальная конфигурация Vault: `address`, `managerAuth.{mountPath,role}`, `storage.kvMountPath`, `tls`. VaultClaim ссылается через `spec.vaultConfigRef.name`. Multi-Vault — через несколько именованных VaultConfig'ов. Finalizer блокирует удаление при ссылках. | §1.1, §2.5-2.7 |
| **D14** | **Внутреннее состояние — в `status` объектов CR**, не в отдельной БД и не в Secret'ах. Кешируем `tokenReviewerJWT.*` и `authMountAccessor` в `VaultClaim.status.vault`. Client-token самого оператора — только в памяти, re-login на startup. | `VaultStatusSummary` в types |
| **D15** | **Retry — exponential backoff с jitter** на уровне reconciler (30s → 5m, ±20% jitter, reset на success), плюс **circuit breaker** на уровне процесса (5 fail подряд на Vault → 2 min open, half-open пробник). SDK-уровень — 3 встроенных retry на transient errors. | `internal/vault/circuit.go` |
| **D16** | **При существующих SA/CRB в target-кластере с `autoCreate: true`** — переиспользуем через SSA с `fieldManager: vault-operator-controller`. Если другой fieldManager — Warning event + `Phase=Configuring`, оператор не «отбирает» владение. При `autoCreate: false` — оператор только использует существующие ресурсы. | §3.6, `internal/target/sa.go` |
| **D17** | **Sealed Vault — обрабатывается при reconcile** (§3.8): `GET sys/seal-status` перед login, conditions `VaultInitialized` и `VaultUnsealed` на VaultConfig, при sealed — пропускаем login, RequeueAfter 1m, cascade `ConfigResolved=False` на VaultClaim'ы. Авто-восстановление при разпечатывании. | `internal/vault/seal.go`, VaultConfig reconciler |

## Открытые вопросы (не блокирующие)

- **vault-token-reviewer naming convention** — есть ли в Beget существующий convention для SA c TokenReview правами? (вопрос от Дмитрия Путилина, см. историю ревью).
- **Customer dimension в `secretsPrefix`** — стоит ли иерархия `customers/{customer}/clusters/{cluster}/` вместо текущей `clusters/{cluster}/`? (вопрос от Дмитрия Путилина).
- **Story 008 — стоит ли webhook?** В spec есть CEL валидации (immutable secretsPrefix/clusterRef.name/auth.mountPath), которых может хватить. Webhook нужен только для cross-field валидаций (например, что все `roles[].policies[]` ссылаются на existing `policies[].name` или existing in Vault).
