# VaultSecretClaim — Техническое задание

> **Status:** Draft
> **Целевая среда:** Vault OSS (1.17+), Kubernetes ≥ 1.34
> **Базовый оператор:** vault-operator (`docs/OPERATOR-SPEC.md`) — настройка доступа к Vault.

---

## 0. Назначение

### 0.1. Что делает контроллер

`VaultSecretClaim` — control-plane оператор в management-кластере, который наполняет HashiCorp Vault значениями секретов для каждого кластера. По одному ресурсу `VaultSecretClaim` (1:1 с кластером) он:

1. **генерирует** новые секреты (пароли) по заданным критериям и пишет их в Vault;
2. **копирует** существующие секреты из общих путей Vault в per-cluster пути;
3. поддерживает их в актуальном состоянии при изменении входных данных.

Это единственный компонент платформы с правом записи в `secret/data/*`. Настройку доступа к Vault (auth method, ACL-policies, roles) выполняет `vault-operator` (CRD `VaultClaim`); `VaultSecretClaim` наполняет те пути, на которые `vault-operator` выдал consumer'ам read-доступ.

### 0.2. Что контроллер НЕ делает

- не настраивает доступ к Vault (auth method, policies, roles) — это `VaultClaim`;
- не разворачивает Vault и общий KV-mount;
- не заводит исходные секреты для копирования — их размещает платформа;
- не отслеживает и не восстанавливает секреты, удалённые в Vault извне;
- не доставляет секреты в pod'ы — это делает consumer (vault-injector / vault-csi / app-side);
- не пишет k8s-Secret в кластеры — только значения в Vault.

---

## 1. Ресурсы

### 1.1. CRD

| CRD | Scope | Назначение |
|-----|-------|------------|
| `VaultSecretClaim` | Namespaced | Per-cluster — список секретов кластера (generate/copy). Имя совпадает с именем кластера, 1:1. |

API Group: `vault.in-cloud.io/v1alpha1`. Подключение к Vault — через отдельный экземпляр CRD `VaultConfig` (§3.1); собственной CRD под конфигурацию не вводится.

### 1.2. Что контроллер создаёт / изменяет в Vault

| Операция | Endpoint |
|----------|----------|
| Запись секрета (generate/copy) | `POST {kvMount}/data/{secretsPrefix}/{destination.path}` |
| Чтение источника (copy) | `GET {kvMount}/data/{source.path}` |
| Проверка существования | `GET {kvMount}/metadata/{secretsPrefix}/{destination.path}` |

### 1.3. Что контроллер читает

| Ресурс | Зачем |
|--------|-------|
| `VaultConfig` (`vaultConfigRef.name`) | адрес Vault, TLS, путь KV-mount, manager-auth роль |
| `ServiceAccount` контроллера | JWT для логина в Vault |
| Секреты-источники в Vault (`source.path`) | значения для `copy` |

Доступ в target-кластеры (kubeconfig) контроллеру **не требуется** — он работает только с Vault.

---

## 2. CRD `VaultSecretClaim`

### 2.1. Пример

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultSecretClaim
metadata:
  name: ec8a00                            # = имя кластера
  namespace: dlputi1u
spec:
  vaultConfigRef: { name: vault-secret }  # отдельный VaultConfig с write-ролью (§3.1)
  clusterRef:     { name: ec8a00 }
  secretsPrefix: clusters/ec8a00          # immutable; == VaultClaim.secretsPrefix
  deletionPolicy: Retain                  # Retain (дефолт) | Purge

  secretList:
    # generate: пароль администратора Argo CD (raw + bcrypt)
    - name: argocd-admin
      type: generate
      destination: { path: argocd, key: admin.password, hashedKey: admin.passwordBcrypt }
      generate:    { length: 16, hash: bcrypt }

    # generate: пароль vmagent (без хеша)
    - name: vmagent
      type: generate
      destination: { path: monitoring/vmagent, key: password }
      generate:    { length: 24, hash: none }

    # copy: общий OIDC staticClient → grafana
    - name: grafana-oidc
      type: copy
      source:      { path: system/dex, key: staticClient }
      destination: { path: grafana, key: staticClient }

    # copy: s3-креды etcd → etcd-backup
    - name: etcd-backup-s3
      type: copy
      source:      { path: system/etcd, key: s3Creds }
      destination: { path: etcd-backup, key: s3Creds }
status:
  phase: Ready
  conditions:
    - { type: ConfigResolved,  status: "True" }
    - { type: VaultReachable,  status: "True" }
    - { type: SourcesResolved, status: "True" }
    - { type: ItemsApplied,    status: "True" }
    - { type: Ready,           status: "True" }
  items:
    - { name: argocd-admin,   state: Applied, sourceHash: "9f2c…", lastAppliedAt: "2026-06-16T10:00:00Z" }
    - { name: vmagent,        state: Applied, sourceHash: "1ab4…", lastAppliedAt: "2026-06-16T10:00:00Z" }
    - { name: grafana-oidc,   state: Applied, sourceHash: "77de…", lastAppliedAt: "2026-06-16T10:00:00Z" }
    - { name: etcd-backup-s3, state: Applied, sourceHash: "c310…", lastAppliedAt: "2026-06-16T10:00:00Z" }
  observedGeneration: 3
```

### 2.2. Поля `spec`

| Поле | Тип | Назначение |
|------|-----|------------|
| `vaultConfigRef.name` | string | Cluster-scoped `VaultConfig` с write-ролью (отдельный экземпляр, §3.1). Mutable. |
| `clusterRef.name` | string | Имя кластера в той же namespace. Immutable. |
| `secretsPrefix` | string | Базовый префикс per-cluster путей в KV-mount. Конвенция `clusters/{name}`. Должен совпадать с `VaultClaim.secretsPrefix`. Immutable. |
| `deletionPolicy` | enum `Retain`/`Purge` | Поведение при удалении CR (§7). Дефолт `Retain`. |
| `secretList[]` | list (map by `name`) | Список секретов, ≥ 1 элемент. |
| `secretList[].name` | string | Уникальный идентификатор элемента в пределах CR. |
| `secretList[].type` | enum `generate`/`copy` | Режим. |
| `secretList[].destination` | object | Куда писать: `{ mount?, path, key, hashedKey? }`. `path` относительный к `secretsPrefix`; `hashedKey` — куда класть хеш (используется только при `generate.hash != none`, иначе игнорируется). |
| `secretList[].generate` | object (при `type=generate`) | Параметры генерации: `{ length, charset, hash }` (§10.1). |
| `secretList[].source` | object (при `type=copy`) | Откуда читать: `{ mount?, path, key }`. `path` — произвольный в рамках настроенного engine. |

### 2.3. Валидации (CEL)

- `metadata.name` ≤ 40 символов, `[a-z0-9-]+`;
- `spec.secretsPrefix`, `spec.clusterRef.name` — immutable;
- `secretList[].name` — уникален в пределах CR;
- `type == generate` ⇒ задан `generate` и не задан `source`;
- `type == copy` ⇒ задан `source` и не задан `generate`;
- `generate.length >= 8`;
- уникальность пары `destination.path + destination.key` в пределах `secretList` — проверяется в reconcile (или webhook).

### 2.4. Naming conventions

| Сущность | Значение |
|----------|----------|
| `metadata.name` | = имя кластера |
| `secretsPrefix` | `clusters/{metadata.name}`, совпадает с `VaultClaim.secretsPrefix` |
| Путь записи | `{kvMount}/data/{secretsPrefix}/{destination.path}` |
| Путь источника | `{kvMount}/data/{source.path}` |

`secretsPrefix` immutable: он встраивается в consumer-policies, которые пишет `VaultClaim`; его изменение сделало бы записанные данные недостижимыми по этим policies.

---

## 3. Аутентификация, права, топология

### 3.1. Логин контроллера и VaultConfig

Контроллер логинится в Vault Kubernetes Auth Method своим ServiceAccount, используя **отдельный экземпляр** `VaultConfig` (тот же CRD, что у `vault-operator`, но другой объект):

- secret-`VaultConfig` (например, `vault-secret`) содержит те же connection-параметры (`address`, `tls`, `storage.kvMountPath`), но `managerAuth.role: vault-secret-operator` с write-policy (§3.2);
- `VaultSecretClaim.spec.vaultConfigRef.name` указывает на этот конфиг;
- secret-`VaultConfig` реконсилит **только** процесс secret-оператора (predicate по label `vault.in-cloud.io/owner`), чтобы write-роль использовалась исключительно в его процессе.

Connection-параметры secret-`VaultConfig` и основного `VaultConfig` указывают на один Vault и один KV-mount.

### 3.2. Policy `vault-secret-operator-admin`

```hcl
# Запись сгенерированных/скопированных секретов в per-cluster пути.
path "secret/data/clusters/+/*"          { capabilities = ["create", "update", "read"] }
path "secret/metadata/clusters/+/*"      { capabilities = ["read", "list"] }

# Чтение секретов-источников для copy (read-only). Путь источника задаётся в CR;
# грант покрывает выбранное место источников (рекомендуется ограниченный префикс).
path "secret/data/<source-prefix>/*"     { capabilities = ["read"] }
path "secret/metadata/<source-prefix>/*" { capabilities = ["read", "list"] }

# Опционально (при deletionPolicy: Purge):
# path "secret/data/clusters/+/*"        +"delete"
# path "secret/metadata/clusters/+/*"    +"delete"

# Ротация собственного токена.
path "auth/token/renew-self"             { capabilities = ["update"] }
path "auth/token/lookup-self"            { capabilities = ["read"] }
```

Не выдаются `sys/auth/*`, `sys/policies/*`, `auth/+/role/*` — настройка доступа остаётся за `vault-operator`. Разделение прав: один контроллер пишет конфигурацию доступа и не может писать данные, второй пишет данные и не может изменять конфигурацию доступа.

### 3.3. Bootstrap

Policy `vault-secret-operator-admin` и роль `vault-secret-operator` в Vault создаёт платформа разово (runbook / Terraform), вне скоупа контроллера.

### 3.4. Топология деплоя

Контроллер запускается **отдельным Deployment'ом с отдельным ServiceAccount'ом**, не как дополнительный reconciler в pod'е `vault-operator`. Репозиторий и Go-модуль общие; артефакт — тот же образ с отдельным entrypoint'ом.

| | `vault-operator` | `vault-secret-operator` |
|---|---|---|
| Deployment / SA | `vault-operator` / `vault-operator-controller` | `vault-secret-operator` / `vault-secret-operator-controller` |
| Reconcilers | `VaultConfig`, `VaultClaim` | `VaultConfig` (scoped), `VaultSecretClaim` |
| VaultConfig | `default` (role `vault-operator`) | `vault-secret` (role `vault-secret-operator`) |
| Vault role / policy | `vault-operator-admin` (без доступа к `secret/data`) | `vault-secret-operator-admin` (write `secret/data/clusters/*`) |
| kubeconfig target | требуется | не требуется |

Граница привилегий — пара (pod ServiceAccount ↔ Vault role через `bound_service_account_names`): раздельные SA делают изоляцию прав реальной, а не логической.

---

## 4. Логика работы

### 4.1. Pipeline reconcile

```
Step 1  Resolve VaultConfig + login (role vault-secret-operator)
Step 2  Pre-validate: все источники copy существуют в Vault
            нет → SourcesResolved=False, Phase=Failed (без частичного применения)
Step 3  Apply items — по каждому элементу secretList[] (§4.2)
Step 4  Ready → Phase=Ready
```

### 4.2. Применение и регенерация по типам

Значение перезаписывается только при реальном изменении входа, а не на каждом reconcile.

**copy** — перекопировать, когда изменился источник (путь, ключ или значение):

- контроллер вычисляет `hash(source.path + source.key + source.value)` и сравнивает с `status.items[].sourceHash`;
- совпало — действий нет; иначе — перекопировать значение в `destination` и обновить `sourceHash`;
- перекопирование идемпотентно: после пересоздания CR (статус пуст) копируется то же значение, без побочных эффектов.

**generate** — регенерировать, когда:

- ключа нет в Vault (`!exists(destination.key)`), **или**
- изменились критерии генерации (`length` / `charset` / `hash`);

иначе действует create-once (значение уже прочитано потребителями; перегенерация на каждом reconcile сломала бы логины). Защита от ложной регенерации при пересоздании CR: если ключ в Vault существует, а baseline критериев в статусе отсутствует (свежий статус) — текущие критерии принимаются за baseline, регенерация не выполняется.

**Хеш-вход.** При `hash != none` в один secret пишутся оба ключа: `destination.key` (исходное значение) и `destination.hashedKey` (хеш). `hashedKey` без `hash` (или для `type: copy`) игнорируется.

**Изменение `destination`** (путь/ключ) — изменение спеки CR; применяется на reconcile по событию обновления CR.

---

## 5. Триггеры и стратегия reconcile

Reconcile — событийный: watch на `VaultSecretClaim` и шаблоны + повторная синхронизация при старте контроллера. Периодического поллинга значений нет — он создавал бы значительную сетевую и CPU-нагрузку при большом числе кластеров и копий.

| Step | Условие | Если не готов |
|------|---------|---------------|
| 1 Login | получен client_token | RequeueAfter 30s → 5m (exp + jitter), `VaultReachable=False` |
| 2 Pre-validate | все источники copy существуют | `Phase=Failed`, `SourcesResolved=False`, event с именем item и путём; RequeueAfter 1m |
| 3 Apply | все элементы записаны | `Phase=Failed`, per-item `state=Failed`, RequeueAfter 1m |
| 4 Ready | — | `Phase=Ready` |

Секрет, удалённый в Vault извне, контроллер не отслеживает и не восстанавливает — создание/перезапись выполняются только по входным триггерам (изменение CR/шаблона, старт контроллера).

---

## 6. Watches

| Ресурс | Механизм |
|--------|----------|
| `VaultSecretClaim` | primary |
| `VaultConfig` | field indexer по `vaultConfigRef.name` + predicate по label `owner` (только свой конфиг) |
| Шаблон (cluster-claim) | re-render при изменении |

У Vault HTTP API нет watch; circuit breaker и backoff переиспользуются из `internal/vault`.

---

## 7. Удаление

Finalizer: `vault.in-cloud.io/vaultsecretclaim-finalizer`. Поведение задаётся полем `spec.deletionPolicy`:

| `deletionPolicy` | При удалении CR |
|---|---|
| `Retain` (дефолт) | секреты остаются в Vault; пересоздание CR восстановит состояние (generate — create-once, copy — перекопирует из источника) |
| `Purge` | контроллер удаляет записанные ключи из Vault (требует `delete` в policy, §3.2) |

kubeconfig для cleanup не требуется (контроллер ничего не создаёт в target-кластерах).

---

## 8. Топология в Vault

```
secret/                                         общий KV-v2 mount (платформа)
  data/<source-prefix>/                         источники (заводит платформа вручную)
    dex            { staticClient }
    etcd           { s3Creds }
  data/clusters/ec8a00/                         per-cluster (пишет VaultSecretClaim)
    argocd         { admin.password, admin.passwordBcrypt }    generate
    monitoring/vmagent { password }                            generate
    grafana        { staticClient }                            copy ← dex
    etcd-backup    { s3Creds }                                 copy ← etcd
```

Пути `data/clusters/{cluster}/{app}/*` — те, на которые `vault-operator` выдаёт consumer'ам read-доступ через ACL-policies. Поэтому `VaultSecretClaim.secretsPrefix` совпадает с `VaultClaim.secretsPrefix`, и для каждого `destination.path` у consumer'а должна существовать соответствующая policy в `VaultClaim`. Несоответствие путей назначения и consumer-policies приводит к отказу доступа (403).

---

## 9. Status и Conditions

### 9.1. Phase

| Phase | Когда |
|-------|-------|
| `Pending` | CR создан / ожидание готовности `VaultConfig` |
| `Ready` | все элементы применены |
| `Failed` | отсутствует источник copy, semantic error, невосстановимая ошибка Vault |
| `Deleting` | finalizer cleanup |

> Промежуточного `Syncing` нет: применение всех элементов происходит за один reconcile-проход, отдельное персистируемое состояние «в процессе» не возникает.

### 9.2. Conditions

| Type | True означает |
|------|---------------|
| `ConfigResolved` | `VaultConfig` существует и в состоянии `Reachable=True` |
| `VaultReachable` | login успешен, токен валиден |
| `SourcesResolved` | все источники copy существуют в Vault |
| `ItemsApplied` | все элементы `secretList[]` записаны |
| `Ready` | aggregate |

### 9.3. Per-item status

`status.items[]` (map by `name`): `{ name, state: Applied|Pending|Failed, sourceHash, lastAppliedAt, message }`.

`sourceHash` — хеш входа для детекта изменений (copy: `hash(source.path + source.key + source.value)`; generate: хеш критериев `length/charset/hash`), отдельное поле, не condition. Даёт точечную диагностику, какой элемент не применился и почему.

---

## 10. Режимы и преобразования

### 10.1. generate

```yaml
generate:
  length: 16          # ≥ 8, дефолт 24
  charset: "a-zA-Z0-9" # алфавит (не regex); дефолт [A-Za-z0-9]
  hash: bcrypt         # none | bcrypt; дефолт none
```

- генерация — `crypto/rand` + rejection sampling (без modulo-bias);
- при `hash != none` в secret пишутся оба ключа: `destination.key` (raw) и `destination.hashedKey` (hash);
- регенерация — только при изменении критериев (§4.2), иначе create-once.

### 10.2. Перечень хешей (`HashKind`)

| Значение | Преобразование | Потребитель |
|----------|----------------|-------------|
| `none` | без хеша, только raw | большинство паролей |
| `bcrypt` | bcrypt, cost 10 (Go default) → `$2a$` | `argocd-secret.admin.password` и общий случай |

`bcrypt` через `golang.org/x/crypto/bcrypt` выдаёт префикс `$2a$` — формат, ожидаемый Argo CD. Перечень расширяемый (`map[HashKind]func(string)(string,error)`); добавление нового хеша не меняет API.

### 10.3. copy

```yaml
source:      { path: system/dex, key: staticClient }   # путь в KV
destination: { path: grafana, key: staticClient }       # относительно secretsPrefix
```

Чтение источника → запись в destination (KV-v2). Один источник может питать несколько destination. Источник — только Vault-путь.

### 10.4. Валидация источников

Перед записью контроллер проверяет существование всех источников `copy`. Если хотя бы один отсутствует, частичное применение не выполняется: `Phase=Failed`, `SourcesResolved=False`, сообщение с именем элемента и путём.

---

## 11. Связь с другими компонентами

| Компонент | Связь |
|-----------|-------|
| `vault-operator` (`VaultClaim`) | `VaultClaim` настраивает доступ (policies на `clusters/{cluster}/{app}/*`), `VaultSecretClaim` пишет данные в те же пути. Запускаются параллельно, строгой очерёдности нет. Общий `secretsPrefix` (собственное поле в каждом CR). |
| `cluster-claim-operator` | Создаёт `VaultSecretClaim` в pipeline через поле `ClusterClaim.spec.vaultSecretClaimTemplateRef`; ждёт `Phase=Ready` перед собственным Ready; пропускает шаг при отсутствии поля. |
| `secret-copy-operator` | Копирует k8s-Secret между кластерами; `VaultSecretClaim` копирует Vault-путь → Vault-путь. Разные механизмы. |
| `addons-operator` | Потребители (Argo CD, Grafana, vmagent) читают записанные секреты из Vault собственным агентом. |

### 11.1. Интеграция в cluster-claim-operator

- новое optional поле `ClusterClaim.spec.vaultSecretClaimTemplateRef`; conditions `VaultSecretClaimCreated` + `VaultSecretClaimReady`; summary в `status`;
- шаг `EnsureVaultSecretClaim` (рядом с `EnsureVaultClaim`) и `WaitVaultSecretClaim` (перед READY); оба пропускаются при `vaultSecretClaimTemplateRef == nil`;
- при удалении — в reverse-pipeline вместе с `VaultClaim`;
- шаблон `default-vault-secret` (`ClusterClaimObserveResourceTemplate`), парный к `default-vault`, рендерит `VaultSecretClaim` из имени кластера.

---

## 12. Этапы реализации

| Этап | Размер | Содержание |
|------|--------|------------|
| S1 | M | CRD `VaultSecretClaim` (типы, CEL, deepcopy, manifests, sample) + отдельный Deployment/SA/RBAC-оверлей |
| S2 | S | Генератор строк (`internal/secretgen`): length + charset, `crypto/rand`, rejection sampling |
| S3 | M | Хеш-трансформы (`none`, `bcrypt`); проверка: хеш начинается с `$2a$` и проходит `bcrypt.CompareHashAndPassword` |
| S4 | M | Чтение/запись KV-v2 в `internal/vault` + policy `vault-secret-operator-admin` |
| S5 | M | Режим copy + pre-validate источников + детект изменений по `sourceHash` |
| S6 | M | Режим generate (create-once + регенерация при смене критериев; raw + hash) |
| S7 | L | Reconciler + событийный pipeline + per-item status (`sourceHash`) + conditions + finalizer |
| S8 | S | Watches (VaultConfig scoped by owner) + валидация (CEL/webhook) |
| S9 | M | Интеграция в `cluster-claim-operator` (`vaultSecretClaimTemplateRef`, ensure/wait, шаблон) |
| S10 | M | E2E (envtest + `vault server -dev`): generate / copy / missing-source / change-detect / delete |
| S11 | S | Документация и примеры |

Критический путь: S1 → S6 → S7 → S9.

---

## 13. Вне скоупа

- развёртывание Vault и общего KV-mount;
- bootstrap policy `vault-secret-operator-admin` и роли `vault-secret-operator`;
- заведение исходных секретов для копирования;
- доставка секретов в pod'ы (vault-injector / vault-csi / app-side);
- настройка consumer-доступа (policies/roles) — `vault-operator`;
- отслеживание и восстановление секретов, удалённых в Vault извне;
- ротация секретов по времени/токену (может быть добавлена позднее неблокирующим полем с дефолтами).
