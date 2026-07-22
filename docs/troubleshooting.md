# Troubleshooting

Runbook для типичных проблем — от обнаружения через `kubectl describe` до устранения. Метрики и события дают сигнал, conditions конкретизируют причину.

## Быстрая диагностика

```bash
kubectl describe vaultclaim -n <ns> <name>
kubectl describe vaultconfig <config-name>
kubectl get events -n <ns> --field-selector involvedObject.name=<name> --sort-by=.lastTimestamp
```

`status.phase` — первая остановка. `status.conditions[]` — кто `False` и почему. У каждого `False` есть `reason` и `message`.

```bash
# Все False-условия одним выводом
kubectl get vaultclaim <name> -n <ns> \
  -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}: {.reason} — {.message}{"\n"}{end}'
```

---

## Phase=Pending / Configuring — pipeline застрял

Pipeline остановился на каком-то шаге. Смотрите какой condition `False`.

### ConfigResolved=False

| reason | причина | действие |
|---|---|---|
| `ConfigRefMissing` | `spec.vaultConfigRef.name` пустой | заполнить spec |
| `NotFound` | VaultConfig с таким именем не существует | создать VaultConfig или поправить ref |
| `VaultUnreachable` | у VaultConfig `Reachable=False` | `kubectl describe vaultconfig` — смотрите его conditions; обычно проблемы с сетью, TLS или sealed Vault |
| `SharedMountMissing` | VaultConfig `SharedMountFound=False` | в Vault создать `secret/` KV-v2 mount |

### VaultReachable=False

| reason | причина | действие |
|---|---|---|
| `LoginFailed` | оператор не смог войти через `auth/{managerAuth.mountPath}/login` | проверить, что в Vault создана role с binding на SA оператора и admin-policy |
| `FactoryError` | проблема с TLS bundle или конфигом | проверить `VaultConfig.spec.tls.caBundleRef` — Secret/ConfigMap с ключом `ca.crt` существует и валиден |

### KubeconfigAvailable=False

| reason | причина | действие |
|---|---|---|
| `NotFound` | Secret `{clusterRef.name}-infra-kubeconfig` отсутствует | дождаться `cluster-claim-operator` (kubeconfig публикуется его pipeline'ом) |
| `InvalidSecret` | Secret есть, но без ключа `value` | проверить, что `certificate-set` правильно собрал секрет |

### TokenReviewerJWTFresh=False

| reason | причина | действие |
|---|---|---|
| `TargetClientError` | kubeconfig не парсится / target apiserver unreachable | проверить, что kubeconfig валиден и infra-кластер запущен |
| `TargetSAFailed` | SSA на namespace/SA/CRB провалилась | проверить RBAC kubeconfig'а в infra-кластере (нужны права на `serviceaccounts`, `clusterrolebindings`, `namespaces`) |
| `TokenRequestFailed` | TokenRequest API провалился | k8s ≥ 1.20 в infra-кластере; проверить, что SA существует |

### AuthMountReady=False

| reason | причина | действие |
|---|---|---|
| `EnableAuthFailed` | Vault отказал в `sys/auth/{path}` (не 400) | проверить `vault-operator-admin` policy: `sys/auth/kubernetes-*` нужны capabilities `create`, `sudo` |
| `WriteConfigFailed` | проблема записи `auth/{mount}/config` | та же policy + `auth/kubernetes-*/config` |

### PoliciesApplied=False

| reason | причина | действие |
|---|---|---|
| `AccessorLookupFailed` | не удалось получить accessor для `{{ .AuthMountAccessor }}` шаблона | сначала должен быть `AuthMountReady=True` — если auth method не создан, шаг 5 неуспешен |
| `RenderFailed` | template error в HCL | проверить `spec.policies[].rules` — синтаксис Go template, доступная переменная: `.AuthMountAccessor` |
| `PutPolicyFailed` | Vault отверг policy (часто 400 — invalid HCL) | смотреть message — обычно невалидный HCL |

### RolesApplied=False

| reason | причина | действие |
|---|---|---|
| `PutRoleFailed` | Vault отверг role | проверить, что `boundServiceAccounts` непустые и `policies[]` ссылается на существующие policy |
| `ListRolesFailed` | LIST `auth/{mount}/role` неуспешен | проверить policy оператора: `auth/kubernetes-*/role/*` нужны capabilities `list` |
| `PurgeFailed` | delete лишних ролей провалился | та же policy + capability `delete` |

---

## Phase=Failed

Невосстановимая ошибка (CEL-валидация, spec violation). Поправьте spec — оператор валидирует повторно.

---

## Phase=Deleting бесконечно

Reverse pipeline застрял — обычно Vault недоступен или сломан.

### Событие DeletionStuck

```
DeletionStuck: Vault cleanup failed (will retry): vault login: ...
```

- **Vault действительно down** → починить Vault, оператор сам подхватит.
- **VaultConfig.spec.address сломан** → `kubectl edit vaultconfig` (адрес mutable) или удалить VaultConfig (после того, как все claim'ы почистились).
- **`vault-operator-admin` policy отозвана** → восстановить policy в Vault.

### Аварийная разблокировка

Когда Vault мёртв навсегда (тестовый кластер удалён, нет смысла восстанавливать) и нужно силой удалить claim:

```bash
kubectl patch vaultclaim -n <ns> <name> --type=merge -p '{"metadata":{"finalizers":null}}'
```

> ⚠ Это оставит auth-method + policies + roles в Vault как «orphan». Если Vault снова поднимется — нужна ручная чистка:
>
> ```bash
> vault auth disable kubernetes-ec8a00
> vault policy delete ec8a00-vmauth-reader
> # и т.д.
> ```

### Событие TargetCleanupBestEffort

Это **не блокер** — cleanup в infra-кластере (SA + CRB) провалился, но finalizer всё равно снимается. Орфанный SA в покинутом infra-кластере неактивен, но если этот кластер ещё жив — почистите вручную:

```bash
kubectl --kubeconfig <infra-kubeconfig> delete serviceaccount -n beget-vault-system vault-token-reviewer
kubectl --kubeconfig <infra-kubeconfig> delete clusterrolebinding vault-token-reviewer-auth-delegator
```

---

## DriftDetected при Phase=Ready

Что-то в Vault разошлось со spec. По `summary` понимаем что именно:

```
DriftDetected: VaultClaim diverged from Vault state: auth mount missing; 2 policies missing
```

- Оператор сам исправит на следующем reconcile через идемпотентные шаги 5-7.
- Если событие повторяется циклически — кто-то снаружи откатывает изменения. Источники:
  - Ручные `vault delete` / `vault policy delete` от админа.
  - Конкурирующий процесс (другой оператор, скрипт).
  - Restore Vault из backup'а.
- Метрика `vaultclaim_drift_detected_total{drift_type}` — алерт `rate(...) > 0` over 30m–1h.

---

## VaultConfig conditions

### Reachable=False, sealStatus=null

Vault вообще не отвечает на `GET sys/seal-status` (т.е. нет ни TCP, ни TLS handshake).

- DNS: `kubectl exec -n vault-operator-system deploy/vault-operator-controller-manager -- nslookup vault.beget.com`
- TLS: проверить `tls.caBundleRef`, `tls.serverName`
- Сеть: NetworkPolicy между management-кластером и Vault

### VaultUnsealed=False

Vault жив, но запечатан. Нужно `vault operator unseal` со Shamir-долями (обычно автоматизировано через KMS-auto-unseal).

Пока sealed → все VaultClaim'ы каскадно получают `ConfigResolved=False`, шаги 2-7 не выполняются (защита от 503-шторма). После unseal всё восстановится за один цикл (1 min для VaultConfig + 10 min для каждого claim, или сразу через watch).

### VaultInitialized=False

Vault никогда не был инициализирован — операция первого запуска. `vault operator init` руками или через Vault Agent.

### ManagerLoggedIn=False

Сеть в порядке, Vault unsealed, но оператор не может залогиниться.

| Возможная причина | Проверка |
|---|---|
| `auth/kubernetes-mgmt` не существует | `vault auth list` |
| Role `vault-operator` не привязана к SA оператора | `vault read auth/kubernetes-mgmt/role/vault-operator` |
| SA-JWT оператора недействителен | проверить `/var/run/secrets/.../token` в pod'е оператора |
| `kubernetes_host` в `auth/kubernetes-mgmt/config` указывает на неверный apiserver | `vault read auth/kubernetes-mgmt/config` |

### SharedMountFound=False

Reason `Forbidden` → оператор не имеет прав на `sys/mounts`. Обновите `vault-operator-admin` policy:

```hcl
path "sys/mounts" { capabilities = ["read", "list"] }
```

Reason `NotFound` → KV-mount `{spec.storage.kvMountPath}` отсутствует. Создайте:

```bash
vault secrets enable -path=secret -version=2 kv
```

---

## Circuit breaker

После 5 подряд неудачных вызовов в Vault breaker открывается на 2 минуты. В логах:

```
ErrCircuitOpen: vault circuit breaker is open
```

Метрика `vault_api_calls_total{result="server_error"}` или `transport_error` показывает рост за минуту до этого.

Через 2 минуты breaker сам пробует один probe-запрос (half-open). Успех → breaker закрывается. Провал → ещё 2 минуты open.

Сбросить breaker руками можно только рестартом pod'а оператора (breaker state in-memory):

```bash
kubectl rollout restart deploy/vault-operator-controller-manager -n vault-operator-system
```

---

## Метрики и алёрты

Полный список — [user-guide/monitoring.md](user-guide/monitoring.md). Самые важные для алёртинга:

| Метрика | Когда алёртить |
|---|---|
| `vault_api_responses_total{code="5xx"}` | `rate(...) > 0` 5m → Vault unhealthy |
| `vault_api_responses_total{code="403"}` | `rate(...) > 0` 10m → admin-policy недостаточна |
| `vault_client_token_renewal_total{result="login_failed"}` | `rate(...) > 0` 5m → оператор не может войти |
| `vault_reviewer_jwt_renewal_total{result="failed"}` | `rate(...) > 0` 15m → consumer pods начнут получать 401 |
| `vault_reviewer_jwt_expiry_seconds` | `< 7200` warn, `< 0` crit → reviewer JWT протух/протухает; per-claim, ставится каждый reconcile независимо от drift short-circuit |
| `vaultclaim_drift_detected_total` | `rate(...) > 0` over 30m–1h → внешние мутации Vault |

---

## Часто задаваемые вопросы

### Можно ли изменить `spec.auth.mountPath`?

Нет — CEL-валидация отклонит. Если действительно нужно:

1. Удалить VaultClaim.
2. Дождаться reverse pipeline (auth-mount исчезнет в Vault).
3. Создать новый VaultClaim с другим `mountPath`.

### Pod'ы в infra-кластере получают 401 при login

- `auth/{mount}/config.token_reviewer_jwt` устарел → проверьте `status.vault.tokenReviewerJWT.expiresAt`. Если в прошлом:
  - `TokenReviewerJWTFresh=False` → ротация упала, смотрите reason (`TokenRequestFailed`/`TargetClientError`);
  - `TokenReviewerJWTFresh=True` при свежих `lastReconcileAt`/`lastDriftCheckAt` и `expiresAt` в прошлом → баг, при котором drift short-circuit пропускал ротацию (Step 4). Исправлено: short-circuit теперь гейтится по `ShouldRotateReviewerJWT`; кластер само-лечится на ближайшем reconcile. Ориентируйтесь на `vault_reviewer_jwt_expiry_seconds`, а не на condition.
- Audience JWT'а pod'а не совпадает с тем, что ожидает Vault → проверьте, что pod использует дефолтный SA-token (без override `audience`).
- SA pod'а не в `boundServiceAccounts` ни одной роли в этом auth-mount → добавьте role в VaultClaim.

### Один claim удалили — другой завис

Если у двух VaultClaim'ов одинаковый `spec.auth.mountPath` (чего **не должно случиться** при правильной конвенции `kubernetes-{name}`), reverse pipeline первого удалил mount, второй потом не может его перенастроить. Уникальность mountPath обеспечивайте конвенцией.

### Drift повторяется, хотя в Vault никто не лазит

Возможны три источника:

- **Vault auto-rotation policies** (не наш случай в OSS, но в Enterprise бывает).
- **VAULT_TOKEN с истекающим lease** заходит из CI и что-то меняет.
- **Кто-то применяет старый snapshot Vault'а** через `vault operator raft snapshot restore`.

Проверьте audit-log Vault'а (`vault audit list`) — он покажет источник мутаций.

---

## VaultSecretClaim

`vault-secret-operator` — отдельный контроллер (наполнение Vault значениями). Диагностика та же — через conditions и события, но условия другие.

```bash
kubectl describe vaultsecretclaim -n <ns> <name>

kubectl get vaultsecretclaim <name> -n <ns> \
  -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}: {.reason} — {.message}{"\n"}{end}'

# Статусы по элементам:
kubectl get vaultsecretclaim <name> -n <ns> \
  -o jsonpath='{range .status.items[*]}{.name}: {.state} {.message}{"\n"}{end}'
```

### Phase=Pending — не дошли до записи

| condition (False) | reason | причина | действие |
|---|---|---|---|
| `ConfigResolved` | `NotFound` | VaultConfig `vault-secret` не существует | создать VaultConfig (`examples/vaultsecretclaim/vaultconfig.yaml`) |
| `ConfigResolved` | `VaultUnavailable` | у VaultConfig `Reachable=False` / `SharedMountFound=False` | `kubectl describe vaultconfig vault-secret` — смотрите его conditions |
| `VaultReachable` | `LoginFailed` | секрет-оператор не вошёл в Vault | проверить role `vault-secret-operator` (binding на SA секрет-оператора) и policy `vault-secret-operator-admin` |
| `VaultReachable` | `CircuitOpen` | breaker открыт после 5 ошибок | см. [Circuit breaker](#circuit-breaker); подождать 2 мин |

> Если `VaultConfig vault-secret` вообще не реконсилится (нет conditions) — проверьте label `vault.in-cloud.io/owner: vault-secret`. Без него конфиг подхватывает `vault-operator`, а не секрет-процесс (owner-scoping).

### Phase=Failed — запись не прошла

| condition (False) | reason | причина | действие |
|---|---|---|---|
| `SourcesResolved` | `MissingSource` | для `copy` источник `source.path#source.key` отсутствует в Vault | завести источник (`vault kv put …`); до этого **ни один** элемент не пишется (all-or-nothing на pre-validate) |
| `ItemsApplied` | `DuplicateDestination` | два элемента пишут в один `destination.path + key` | поправить spec — пара path+key уникальна в пределах CR |
| `ItemsApplied` | `ApplyFailed` | хотя бы один элемент не записался | смотреть `status.items[].message` (часто 403 — недостаточно прав в `vault-secret-operator-admin`) |

Поправьте причину — оператор повторит запись по событию обновления CR (или через RequeueAfter 1m).

### Phase=Deleting (только при deletionPolicy: Purge)

`Retain` (дефолт) снимает finalizer сразу. `Purge` сначала удаляет записанные ключи из Vault.

#### Событие DeletionStuck

```
DeletionStuck: Purge requested but Vault is unavailable; retrying
DeletionStuck: purge failed: vault DELETE ...: 403 ...
```

- **Vault недоступен** → починить Vault, оператор подхватит.
- **Нет `delete`-права** → добавить в `vault-secret-operator-admin`:
  ```hcl
  path "secret/data/clusters/+/*"     { capabilities = ["delete"] }
  path "secret/metadata/clusters/+/*" { capabilities = ["delete"] }
  ```

#### Аварийная разблокировка

```bash
kubectl patch vaultsecretclaim -n <ns> <name> --type=merge -p '{"metadata":{"finalizers":null}}'
```

> Оставит записанные значения в Vault как «orphan». Ручная чистка: `vault kv metadata delete secret/clusters/ec8a00/argocd`.

### Часто задаваемые вопросы

#### Значение не обновляется, хотя я поменял источник для copy

`copy` перекопирует только при смене **значения** источника (детект по `hash(path+key+value)`). Сверьте `status.items[].sourceHash` — он должен поменяться. Изменение `destination` — это изменение spec, применяется по событию обновления CR.

#### Сгенерированный пароль не меняется после редактирования CR

`generate` работает **create-once**: значение перегенерируется только если ключа нет в Vault или сменились критерии (`length`/`charset`/`hash`). Намеренно — пароль уже прочитали consumer'ы. Чтобы форсировать новый — поменяйте критерий (например `length`) или удалите ключ в Vault.

#### Секрет удалили в Vault руками — оператор не восстанавливает

By design: reconcile событийный, без поллинга значений. Восстановление зависит от типа:

- **generate** — тригерните reconcile (`kubectl annotate vaultsecretclaim <name> -n <ns> reconcile=$(date +%s) --overwrite`): ключа нет → перегенерируется, но **новым** значением (старое было случайным и невосстановимо — consumer'ы должны перечитать).
- **copy** — обычный reconcile НЕ восстановит (источник не менялся → no-op по `sourceHash`). Восстановить: пересоздать CR (пустой статус → copy перекопирует) либо сменить значение источника.

#### Consumer получает 403 на чтение записанного секрета

Путь `destination` не покрыт consumer-policy. Эти policy пишет `VaultClaim` (`vault-operator`), а не секрет-оператор. Проверьте, что `secretsPrefix` у `VaultSecretClaim` совпадает с `VaultClaim.secretsPrefix`, и что в `VaultClaim` есть policy на `secret/data/clusters/{cluster}/{app}/*`.

---

## Связанные документы

- [Концепции / Pipeline](concepts/pipeline.md) — как шаги pipeline'а связаны с conditions
- [Концепции / VaultSecretClaim](concepts/vaultsecretclaim.md) — генерация/копирование значений
- [Развёртывание vault-secret-operator](user-guide/deploying-vault-secret-operator.md)
- [user-guide/monitoring.md](user-guide/monitoring.md) — мониторинг и алёрты
- [reference/api.md](reference/api.md) — все conditions и метрики
