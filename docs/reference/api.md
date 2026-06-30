# API Reference

API group: `vault.in-cloud.io/v1alpha1`

Три CRD:

- [`VaultClaim`](#vaultclaim) — namespaced, per-cluster конфигурация **доступа**
- [`VaultSecretClaim`](#vaultsecretclaim) — namespaced, per-cluster наполнение Vault **значениями**
- [`VaultConfig`](#vaultconfig) — cluster-scoped, подключение к Vault

---

## VaultClaim

| Поле | Scope | Описание |
|---|---|---|
| Kind | Namespaced | `vault.in-cloud.io/v1alpha1` |
| Short name | `vc` | `kubectl get vc` |
| Subresources | `status` | |
| Print columns | Phase, Config, Cluster, Age | |

### spec

| Поле | Тип | Обязательно | Описание |
|---|---|:---:|---|
| `vaultConfigRef.name` | `string` | Да | Имя VaultConfig (cluster-scoped). Мутируемо. |
| `clusterRef.name` | `string` | Да | Имя ClusterClaim в том же namespace. **Immutable.** |
| `clusterRef.kubeconfigSecret` | `string` | Нет | Имя Secret с kubeconfig. По умолчанию `{clusterRef.name}-infra-kubeconfig`. |
| `secretsPrefix` | `string` | Да | Путь под общим KV-mount, e.g. `clusters/ec8a00`. **Immutable.** |
| `auth.mountPath` | `string` | Да | Путь auth-mount в Vault, e.g. `kubernetes-ec8a00`. **Immutable.** |
| `auth.autoCreate` | `bool` | Нет (default `true`) | Создавать ли auth-mount через `POST sys/auth`. Если `false`, mount должен существовать. |
| `auth.issuer` | `string` | Нет | OIDC issuer infra-кластера. Пусто → автоопределение через `/.well-known/openid-configuration`. |
| `auth.tokenReviewer.serviceAccount.namespace` | `string` | Да | Namespace SA для TokenReview. |
| `auth.tokenReviewer.serviceAccount.name` | `string` | Да | Имя SA для TokenReview. |
| `auth.tokenReviewer.serviceAccount.autoCreate` | `bool` | Нет (default `true`) | Создавать ли SA + CRB `system:auth-delegator` в infra-кластере. |
| `auth.tokenReviewer.ttl` | `duration` | Нет (default `24h`) | TTL JWT, выпускаемого TokenRequest API. Оператор ротирует при остатке <30%. |
| `policies[].name` | `string` | Да | Имя ACL-policy. Префиксуйте именем claim'а — Vault OSS политики в глобальном NS. |
| `policies[].rules` | `string` | Да | HCL тело политики. Может содержать `{{ .AuthMountAccessor }}`. |
| `roles[].name` | `string` | Да | Имя роли под `auth/{mountPath}/role/`. |
| `roles[].boundServiceAccounts.name` | `string` | Да | SA в infra-кластере. |
| `roles[].boundServiceAccounts.namespace` | `string` | Да | Namespace SA в infra-кластере. |
| `roles[].policies[]` | `[]string` | Да | Имена политик из `policies[]` или существующих в Vault. |
| `roles[].tokenTTL` | `duration` | Нет | TTL client_token, выпущенного через эту роль. Пусто → system default. |
| `roles[].tokenMaxTTL` | `duration` | Нет | Max-TTL при renew. |

### status

| Поле | Тип | Описание |
|---|---|---|
| `observedGeneration` | `int64` | Последнее обработанное `metadata.generation`. |
| `phase` | `enum` | `Pending`, `Configuring`, `Ready`, `Failed`, `Deleting`. |
| `conditions[]` | `[]Condition` | См. ниже. |
| `vault.configName` | `string` | Имя резолвнутого VaultConfig. |
| `vault.authMountPath` | `string` | Зеркало `spec.auth.mountPath`. |
| `vault.secretsPrefix` | `string` | Зеркало `spec.secretsPrefix`. |
| `vault.authMountAccessor` | `string` | Кэш accessor для identity templating. |
| `vault.appliedPolicies[]` | `[]string` | Имена политик, фактически записанных в Vault. |
| `vault.appliedRoles[]` | `[]string` | Имена ролей, фактически созданных в Vault. |
| `vault.tokenReviewerJWT.issuedAt` | `time` | Когда выпущен текущий reviewer JWT. |
| `vault.tokenReviewerJWT.expiresAt` | `time` | Когда истекает. |
| `vault.tokenReviewerJWT.lastRotated` | `time` | Время последней ротации (`= issuedAt` при ротации). |
| `vault.tokenReviewerJWT.lastRotationAttempt` | `time` | Время последней попытки (успешной или нет). |
| `vault.lastReconcileAt` | `time` | Последний успешный reconcile. |
| `vault.lastDriftCheckAt` | `time` | Последняя drift-проверка. |

### Conditions VaultClaim

| Type | True значит | False значит |
|---|---|---|
| `ConfigResolved` | VaultConfig найден, `Reachable=True`, `SharedMountFound=True` | Не найден / VaultConfig недоступен / mount отсутствует |
| `VaultReachable` | Login в Vault прошёл успешно | Login failed (sealed Vault, network, неверный role) |
| `KubeconfigAvailable` | Secret kubeconfig'а существует и содержит ключ `value` | Secret отсутствует или malformed |
| `TokenReviewerJWTFresh` | Текущий reviewer JWT в пределах 30% TTL | Не выпущен, expired, или последняя попытка ротации провалилась |
| `AuthMountReady` | Auth-mount существует и `auth/{mount}/config` записан | `POST sys/auth` failed (не 400) или `POST .../config` failed |
| `PoliciesApplied` | Все `spec.policies[]` записаны | Хотя бы один `PUT sys/policies/acl` failed |
| `RolesApplied` | Все `spec.roles[]` записаны + soft-purge выполнен | Хотя бы один `POST role` failed или `LIST` failed |
| `Ready` | Все шаги прошли | Любой шаг провалился или claim в `Deleting` |

### Финализатор

`vault.in-cloud.io/finalizer` — добавляется при первом reconcile. Снимается после reverse pipeline.

### Примеры

См. [examples/basic-vaultclaim](../examples/basic-vaultclaim/) и [examples/identity-templating](../examples/identity-templating/).

---

## VaultSecretClaim

| Поле | Scope | Описание |
|---|---|---|
| Kind | Namespaced | `vault.in-cloud.io/v1alpha1` |
| Short name | `vsc` | `kubectl get vsc` |
| Subresources | `status` | |
| Print columns | Phase, Cluster, Age | |
| Контроллер | `vault-secret-operator` | отдельный процесс/SA/роль с write-правом |

### spec

| Поле | Тип | Обязательно | Описание |
|---|---|:---:|---|
| `vaultConfigRef.name` | `string` | Да | VaultConfig с write-ролью (обычно `vault-secret`). Мутируемо. |
| `clusterRef.name` | `string` | Да | Имя кластера. **Immutable.** |
| `secretsPrefix` | `string` | Да | Базовый префикс per-cluster путей, e.g. `clusters/ec8a00`. == `VaultClaim.secretsPrefix`. **Immutable.** |
| `deletionPolicy` | `enum` | Нет (default `Retain`) | `Retain` — значения остаются при удалении CR; `Purge` — удаляются. |
| `secretList[].name` | `string` | Да | Уникальный идентификатор элемента в CR. |
| `secretList[].type` | `enum` | Да | `generate` или `copy`. |
| `secretList[].destination.mount` | `string` | Нет | Override `VaultConfig.storage.kvMountPath`. |
| `secretList[].destination.path` | `string` | Да | Путь относительно `secretsPrefix`. |
| `secretList[].destination.key` | `string` | Да | Ключ в secret'е. |
| `secretList[].destination.hashedKey` | `string` | Нет | Куда класть хеш (при `generate.hash != none`). |
| `secretList[].generate.length` | `int` | Нет (default `24`, min `8`) | Длина пароля (при `type=generate`). |
| `secretList[].generate.charset` | `string` | Нет (default `[A-Za-z0-9]`) | Алфавит с range-сокращением `X-Y` (`a-zA-Z0-9`). |
| `secretList[].generate.hash` | `enum` | Нет (default `none`) | `none` или `bcrypt`. |
| `secretList[].source.path` | `string` | Да* | Путь источника (* при `type=copy`). |
| `secretList[].source.key` | `string` | Да* | Ключ источника (* при `type=copy`). |
| `secretList[].source.mount` | `string` | Нет | Override mount источника. |

CEL: `type=generate` требует `generate` и запрещает `source` (и наоборот); `generate.length >= 8`; `secretList` ≥ 1; immutable `secretsPrefix` / `clusterRef.name`.

### status

| Поле | Тип | Описание |
|---|---|---|
| `observedGeneration` | `int64` | Последнее обработанное `metadata.generation`. |
| `phase` | `enum` | `Pending`, `Ready`, `Failed`, `Deleting`. |
| `conditions[]` | `[]Condition` | См. ниже. |
| `items[].name` | `string` | Идентификатор элемента. |
| `items[].state` | `enum` | `Applied`, `Pending`, `Failed`. |
| `items[].sourceHash` | `string` | Хеш входа для детекта изменений (само **значение** секрета НЕ хранится). |
| `items[].lastAppliedAt` | `time` | Последняя запись в Vault. |
| `items[].message` | `string` | Текст ошибки при `Failed`. |

### Conditions VaultSecretClaim

| Type | True значит | False значит |
|---|---|---|
| `ConfigResolved` | VaultConfig найден, `Reachable`/`SharedMountFound` | Не найден / Vault недоступен |
| `VaultReachable` | Login в Vault прошёл | Login failed / circuit open |
| `SourcesResolved` | Все источники `copy` существуют | Хотя бы один источник отсутствует |
| `ItemsApplied` | Все элементы записаны | Дубликат destination или ошибка записи |
| `Ready` | Все элементы применены | Любой шаг провалился или `Deleting` |

### Финализатор

`vault.in-cloud.io/vaultsecretclaim-finalizer`. При `Purge` сначала удаляет записанные ключи из Vault, затем снимает finalizer.

### Примеры

См. [examples/vaultsecretclaim](../examples/vaultsecretclaim/).

---

## VaultConfig

| Поле | Scope | Описание |
|---|---|---|
| Kind | Cluster-scoped | `vault.in-cloud.io/v1alpha1` |
| Short name | `vcfg` | `kubectl get vcfg` |
| Subresources | `status` | |
| Print columns | Address, Unsealed, Reachable, Refs, Age | |

### spec

| Поле | Тип | Обязательно | Описание |
|---|---|:---:|---|
| `address` | `string` | Да | URL Vault, `https://` в проде, `http://` допустим для dev/e2e. |
| `managerAuth.method` | `enum` | Нет (default `kubernetes`) | В v1alpha1 только `kubernetes`. |
| `managerAuth.mountPath` | `string` | Нет (default `kubernetes-mgmt`) | Auth-mount, через который оператор сам логинится. |
| `managerAuth.role` | `string` | Нет (default `vault-operator`) | Роль в Vault, привязанная к SA оператора. |
| `storage.kvMountPath` | `string` | Нет (default `secret`) | Общий KV-v2 mount. **Immutable.** |
| `tls.caBundleRef` | `LocalObjectRef` | Нет | Secret или ConfigMap с ключом `ca.crt`. |
| `tls.serverName` | `string` | Нет | SNI override. |

### status

| Поле | Тип | Описание |
|---|---|---|
| `observedGeneration` | `int64` | Последнее обработанное `metadata.generation`. |
| `conditions[]` | `[]Condition` | См. ниже. |
| `sealStatus.sealed` | `bool` | Зеркало `sys/seal-status`. |
| `sealStatus.initialized` | `bool` | Зеркало `sys/seal-status`. |
| `sealStatus.t`, `sealStatus.n` | `int32` | Shamir threshold / share count. |
| `sealStatus.progress` | `int32` | Сколько долей уже отдано на unseal. |
| `vaultVersion` | `string` | Версия Vault сервера. |
| `lastHealthCheckAt` | `time` | Время последнего seal-status пробинга. |
| `referencedBy` | `int32` | Число VaultClaim'ов, ссылающихся на этот VaultConfig. |

### Conditions VaultConfig

| Type | True значит | False значит |
|---|---|---|
| `Reachable` | `GET sys/seal-status` отвечает 200 | Сеть/TLS не работают |
| `VaultInitialized` | `seal-status.initialized=true` | Vault не инициализирован |
| `VaultUnsealed` | `seal-status.sealed=false` | Vault sealed |
| `ManagerLoggedIn` | `auth/{managerAuth.mountPath}/login` прошёл | Логин failed (роль не найдена, JWT отклонён) |
| `SharedMountFound` | `sys/mounts` содержит `{storage.kvMountPath}/` и это KV | Mount отсутствует или 403 (нет прав) |

### Финализатор

`vault.in-cloud.io/vaultconfig-finalizer` — снимается только когда `status.referencedBy == 0`. Иначе блокирует удаление, эмитит `DeletionBlocked`.

---

## Phases (VaultClaim)

| Phase | Когда |
|---|---|
| `Pending` | Только что создан, ещё не начался pipeline |
| `Configuring` | Pipeline в процессе |
| `Ready` | Все шаги прошли, `Ready=True` |
| `Failed` | Терминальная ошибка (зарезервировано) |
| `Deleting` | Идёт reverse pipeline |

## События

Оператор эмитит события на VaultClaim и VaultConfig.

### VaultClaim события

| Reason | Type | Когда |
|---|---|---|
| `VaultClaimReady` | Normal | Полный pipeline завершён успешно |
| `StepRetrying` | Warning | Шаг pipeline вернул транзиентную ошибку |
| `AuthMountReady` | Normal | Auth-mount enabled + config записан |
| `ReviewerJWTRotated` | Normal | Reviewer JWT обновлён |
| `RolesPurged` | Normal | Soft-purge удалил роли, которых нет в spec |
| `DriftDetected` | Warning | Drift найден на Ready claim'е |
| `DeletionStuck` | Warning | Reverse pipeline застрял на Vault |
| `TargetCleanupBestEffort` | Warning | Cleanup в infra-кластере не удался (finalizer всё равно снимется) |
| `VaultClaimDeleted` | Normal | Reverse pipeline завершён, finalizer снят |

### VaultConfig события

| Reason | Type | Когда |
|---|---|---|
| `DeletionBlocked` | Warning | Попытка удалить VaultConfig с `referencedBy > 0` |

### VaultSecretClaim события

| Reason | Type | Когда |
|---|---|---|
| `MissingSource` | Warning | Источник `copy` отсутствует в Vault (pre-validate) |
| `DuplicateDestination` | Warning | Два элемента пишут в один `path + key` |
| `ItemApplyFailed` | Warning | Элемент не записался |
| `DeletionStuck` | Warning | `Purge` не смог удалить ключи (Vault недоступен / нет прав) |

## Метрики

Все метрики Prometheus экспонируются через `/metrics` endpoint controller-runtime (защищён через `--metrics-secure`).

| Метрика | Labels | Что считает |
|---|---|---|
| `vaultclaim_drift_detected_total` | `drift_type=mount\|policy\|role` | Категории найденного drift, инкрементируется один раз на категорию на цикл |
| `vault_reviewer_jwt_renewal_total` | `result=rotated\|skipped\|failed` | Лайфцикл reviewer JWT |
| `vault_api_responses_total` | `verb`, `path`, `code` | HTTP-ответы Vault (path bucketed: `auth_login`, `auth_role`, `sys_mounts`, ...) |
| `vault_api_calls_total` | `verb`, `path`, `result=success\|client_error\|server_error\|transport_error` | Каждый вызов оператора в Vault |
| `vault_client_token_renewal_total` | `result=login_success\|login_failed\|renew_success\|renew_failed` | Лайфцикл собственного `client_token` оператора |

Подробнее — [user-guide/monitoring.md](../user-guide/monitoring.md).

> **vault-secret-operator** собственных controller-метрик (`vaultsecretclaim_*`) не экспонирует. Доступны общие `vault_api_*` и `vault_client_token_renewal_total` (через тот же `internal/vault` клиент), а также `phase`/`conditions` через kube-state-metrics.

## Связанные документы

- [VaultClaim](../concepts/vaultclaim.md), [VaultConfig](../concepts/vaultconfig.md) — концепции
- [Pipeline](../concepts/pipeline.md) — что происходит между spec и Vault
- [Troubleshooting](../troubleshooting.md) — диагностика по condition reason'ам
