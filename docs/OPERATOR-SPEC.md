# Vault Operator — Техническое задание (v1.1)

> **Status:** Approved — все архитектурные решения зафиксированы (см. §12).
> **Связанные задачи:** K8S-38 (написать контроллер), K8S-220 (этот документ), K8S-221 (родительская — централизованная система секретов), K8S-222 (роли для consumer'ов), K8S-225 (настройка аддонов на Vault), K8S-181 (vmauth — потребитель).
> **Целевая среда:** Vault OSS (без Enterprise namespaces), Kubernetes ≥ 1.34.

---

## 0. Контекст и цель

### 0.1. Зачем нужен оператор

В платформе уже есть `ClusterClaim`, который через 13-шаговый pipeline создаёт **infra-кластер** и опционально **client-кластер**. После того как кластер живой, в нём появляются потребители секретов: `vmauth`, мониторинг, ArgoCD-аддоны, пользовательские deployment'ы. Сейчас секреты раздаются ad-hoc — копируются из system-кластера через `secret-copy-operator`, либо собираются в ConfigMap'ы Helm-чартами.

У такого подхода три проблемы:

1. **Нет единого хранилища** — секрет может жить в system-кластере, в state Argo CD, или захардкоден в values; найти его и заротировать нельзя.
2. **Нет аудита** — кто читал секрет и когда, не известно.
3. **Раздача по pull-модели невозможна** — pod в infra-кластере не может пойти за секретом сам, потому что в кластере нечего настраивать (нет auth method'а, нет policy, нет роли).

Цель — централизовать хранение в **HashiCorp Vault** и автоматизировать настройку доступа для каждого нового кластера. Vault Operator решает строго **control-plane** часть: подготавливает Vault так, чтобы pod'ы в infra-кластере могли пойти в Vault со своим ServiceAccount-токеном и получить только свои секреты. **Сами секреты в KV кладёт тот, кто их владеет** (платформа, пользователь, CI) — Vault Operator не пишет данные секретов.

### 0.2. Концепция в одном абзаце

Vault Operator — это control-plane оператор в system-кластере. Под каждый infra-кластер пользователь создаёт **один** `VaultClaim` (1:1 c `ClusterClaim`); в нём перечисляются consumer'ы этого кластера (vmauth, argocd, …) и их права. Оператор настраивает в Vault per-cluster Kubernetes Auth Method, ACL-policies и роли с binding'ами `SA + namespace → policy`. Координаты Vault (`VAULT_ADDR`, путь auth method) consumer'ы собирают сами из имени кластера в Helm values своих чартов — оператор в infra-кластер ничего не публикует. Pod'ы дальше сами ходят в Vault со своим SA-JWT — оператор в этом потоке не участвует.

### 0.3. Что Vault Operator делает

Для одного `VaultClaim` (то есть для одного infra-кластера):

1. **Регистрирует кластер в Vault** — создаёт Kubernetes Auth Method для этого кластера (`auth/kubernetes-{cluster}/`).
2. **Раздаёт права consumer'ам** — создаёт ACL-policies и роли (binding `SA + namespace → policy`) под каждого потребителя из `spec.roles[]`; данные секретов лежат в общем `secret/` KV-v2 mount с префиксом `clusters/{cluster}/`.
3. **Поддерживает дрифт** — на каждом reconcile проверяет, что состояние Vault совпадает с `VaultClaim.spec`, и чинит расхождения.
4. **Чистит за собой** — при удалении `VaultClaim` снимает roles, policies, auth method этого кластера. Данные секретов в KV не трогает (см. §7).

Координаты входа для consumer'ов (`VAULT_ADDR`, путь auth method) — шаблонные и вычисляются самими consumer'ами из имени кластера, оператор их в infra-кластер не публикует.

### 0.4. Что Vault Operator НЕ делает

- Не разворачивает Vault и его HA — Vault считается уже работающим (внешний или managed).
- Не создаёт и не настраивает KV-v2 mount `secret/` — общий mount существует в Vault до запуска оператора, развёртывается платформой разово.
- Не пишет/читает данные секретов (`secret/data/clusters/{cluster}/...`) — это делает отдельный оператор/инструмент платформы (см. K8S-224).
- Не управляет доступом со стороны разработчиков (UI/CLI access, AD/OIDC) — только машинный доступ через k8s-auth.
- Не управляет PKI engine, transit, DB engine — только конфиг auth method и ACL для KV-v2.

---

## 1. Ресурсы, которыми оперирует оператор

### 1.1. CRD оператора

| CRD | Scope | Назначение |
|-----|-------|------------|
| `VaultClaim` | Namespaced | Per-cluster — описание Vault-настроек для одного кластера (per-cluster auth method, policies, roles). Имя совпадает с именем `ClusterClaim`. |
| `VaultConfig` | Cluster | Глобальная конфигурация подключения к Vault: адрес, путь auth method контроллера (manager-auth), путь общего KV-mount, TLS. На один VaultConfig ссылается N VaultClaim'ов. Multi-Vault — через несколько именованных `VaultConfig`'ов. |

API Group: `vault.in-cloud.io/v1alpha1`.

Роли потребителей описываются инлайном в `VaultClaim.spec.roles[]` — отдельной CRD под шаблоны ролей нет.

### 1.2. Что создаёт / изменяет оператор в Vault

| Объект Vault | API endpoint | Уникальность |
|--------------|--------------|--------------|
| Auth method `kubernetes-{cluster}` | `POST /v1/sys/auth/{path}` | по path |
| Конфиг auth method (`token_reviewer_jwt`, `kubernetes_host`, `issuer`, `kubernetes_ca_cert`) | `POST /v1/auth/{path}/config` | один на mount |
| ACL Policies `{cluster}-{role}` | `PUT /v1/sys/policies/acl/{name}` | по name (глобальные в OSS) |
| Auth roles `{role-name}` | `POST /v1/auth/{path}/role/{role}` | по path+role |

Общий KV-v2 mount `secret/` развёрнут платформой и считается частью окружения; оператор только пишет в него policies, ссылающиеся на префикс `secret/data/clusters/{cluster}/...`.

### 1.3. Что создаёт оператор в Kubernetes

| Ресурс | Где | GVK | Назначение |
|--------|-----|-----|------------|
| `ServiceAccount` `vault-token-reviewer` | **infra cluster**, namespace `beget-vault-system` | `v1/ServiceAccount` | SA, JWT которого Vault использует для TokenReview API. Создаётся опционально (`spec.auth.tokenReviewer.autoCreate: true`). |
| `ClusterRoleBinding` `vault-token-reviewer-auth-delegator` | infra cluster | `rbac.authorization.k8s.io/v1/ClusterRoleBinding` | Даёт SA право `system:auth-delegator` (вызывать TokenReview). |
| Events на `VaultClaim` | system cluster | `v1/Event` | Operational visibility. |

### 1.4. Что читает оператор (не создаёт)

| Ресурс | Зачем |
|--------|-------|
| `Secret` `{clusterClaim}-infra-kubeconfig` | Kubeconfig для infra-кластера: создание token-reviewer SA + CRB, выпуск reviewer JWT через TokenRequest API. |
| `ServiceAccount` оператора в system-кластере | Подписанный JWT для логина контроллера в Vault. |
| `ClusterClaim` (через `clusterRef`) | Валидация существования кластера, ссылка на kubeconfig Secret. |
| `VaultConfig` (через `vaultConfigRef.name`) | Адрес Vault, путь manager-auth, путь общего KV-mount, TLS. Один на платформу (`default`) или несколько для multi-Vault. |

---

## 2. CRDs оператора

### 2.1. VaultClaim — минимальный пример

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata:
  name: ec8a00                            # = ClusterClaim.metadata.name
  namespace: dlputi1u
spec:
  vaultConfigRef:
    name: default                         # cluster-scoped VaultConfig
                                          # (адрес Vault, manager-auth, KV mount path)

  clusterRef:
    name: ec8a00                          # ClusterClaim в той же namespace
    kubeconfigSecret: ec8a00-infra-kubeconfig
                                          # подготовлен certificate-set

  secretsPrefix: clusters/ec8a00          # префикс в общем secret/ mount,
                                          # используется в policies; immutable

  auth:
    mountPath: kubernetes-ec8a00          # auth method per-cluster
    autoCreate: true
    issuer: ""                            # пусто = автодискавер из infra-кластера
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer
        autoCreate: true                  # создать SA + CRB в infra-кластере
      ttl: 24h                            # TTL reviewer JWT; перевыпуск при <30% остатка

  roles:
    # ОДИН SA per role (CRD design); общая policy через `policies:` массив.
    - name: vmauth-reader
      boundServiceAccounts:
        name:      vmauth
        namespace: monitoring
      policies:     [ec8a00-vmauth-reader]
      tokenTTL:     1h
      tokenMaxTTL:  24h
    - name: argocd-application-controller-reader
      boundServiceAccounts:
        name:      argocd-application-controller
        namespace: argocd
      policies:     [ec8a00-argocd-reader]
      tokenTTL:     1h
    - name: argocd-server-reader
      boundServiceAccounts:
        name:      argocd-server
        namespace: argocd
      policies:     [ec8a00-argocd-reader]   # same policy, separate role for audit clarity
      tokenTTL:     1h

  policies:
    - name: ec8a00-vmauth-reader
      rules: |
        path "secret/data/clusters/ec8a00/monitoring/vmauth/*" {
          capabilities = ["read", "list"]
        }
    - name: ec8a00-argocd-reader
      rules: |
        path "secret/data/clusters/ec8a00/argocd/*" {
          capabilities = ["read", "list"]
        }
        path "secret/metadata/clusters/ec8a00/argocd/*" {
          capabilities = ["read", "list"]
        }
status:
  phase: Ready
  conditions:
    - { type: ConfigResolved,       status: "True" }
    - { type: VaultReachable,       status: "True" }
    - { type: KubeconfigAvailable,  status: "True" }
    - { type: AuthMountReady,       status: "True" }
    - { type: PoliciesApplied,      status: "True", observedGeneration: 7 }
    - { type: RolesApplied,         status: "True" }
    - { type: TokenReviewerJWTFresh,status: "True" }
    - { type: Ready,                status: "True" }
  vault:
    configName:       default
    authMountPath:    kubernetes-ec8a00
    secretsPrefix:    clusters/ec8a00
    appliedRoles:     [vmauth-reader, argocd-reader]
    appliedPolicies:  [ec8a00-vmauth-reader, ec8a00-argocd-reader]
    tokenReviewerJWT:
      issuedAt:    "2026-05-15T08:00:00Z"
      expiresAt:   "2026-05-16T08:00:00Z"
      lastRotated: "2026-05-15T08:00:00Z"
    lastReconcileAt:  "2026-05-07T14:00:00Z"
  observedGeneration: 7
```

### 2.2. VaultClaim — ключевые поля spec

| Поле | Тип | Назначение |
|------|-----|------------|
| `vaultConfigRef.name` | string | Имя cluster-scoped `VaultConfig` (адрес Vault, manager-auth, KV mount path). Mutable — изменение запускает миграцию VaultClaim на другой Vault (см. §11.1). |
| `clusterRef.name` | string | Имя `ClusterClaim` в той же namespace. Immutable. |
| `clusterRef.kubeconfigSecret` | string | Имя Secret'а с kubeconfig (по умолчанию `{clusterRef.name}-infra-kubeconfig`). |
| `secretsPrefix` | string | Префикс пути в общем `secret/` KV-v2 mount, используется в `policies[].rules`. Конвенция — `clusters/{metadata.name}`. Immutable. |
| `auth.mountPath` | string | Путь auth method. Конвенция — `kubernetes-{metadata.name}`. Immutable. |
| `auth.issuer` | string (опц) | OIDC issuer URL infra-кластера. Если пусто — автодискавер (см. §3.4). |
| `auth.tokenReviewer.serviceAccount` | object | SA в infra-кластере, JWT которого Vault использует для TokenReview. |
| `auth.tokenReviewer.serviceAccount.autoCreate` | bool | Создавать ли SA + CRB `system:auth-delegator` в infra-кластере. Дефолт `true`. |
| `auth.tokenReviewer.ttl` | duration | TTL JWT, запрашиваемого через TokenRequest API. Дефолт `24h`. Оператор перевыпускает токен при остатке < 30% TTL (см. §3.2). |
| `roles[]` | list | Связки SA+namespace → policies. Каждая роль = одна запись `auth/{path}/role/{name}`. |
| `policies[]` | list | HCL-policies. Имена должны быть unique в Vault (OSS-global namespace) — конвенция prefix `{metadata.name}-`. |

### 2.3. CEL-валидации (webhook)

- `metadata.name` ≤ 40 символов и `[a-z0-9-]+`.
- `spec.secretsPrefix` immutable после создания (изменение делает существующие данные недостижимыми по новым policies).
- `spec.auth.mountPath` immutable.
- `spec.clusterRef.name` immutable.
- `spec.roles[].name` unique within CR.
- `spec.policies[].name` unique within CR.
- Каждый `roles[].policies[]` должен ссылаться либо на `spec.policies[].name`, либо на existing policy в Vault (валидируется на reconcile, не webhook'ом).

### 2.4. Naming conventions

| Сущность | Default | Override |
|----------|---------|----------|
| `metadata.name` | задаёт пользователь, конвенция — равно `ClusterClaim.metadata.name` | — |
| `auth.mountPath` | `kubernetes-{metadata.name}` | явно через `spec.auth.mountPath` |
| `secretsPrefix` | `clusters/{metadata.name}` | явно через `spec.secretsPrefix` |
| `policies[].name` | задаётся пользователем; рекомендация — `{metadata.name}-{role-suffix}` для глобального namespace | — |
| `roles[].name` | задаётся пользователем; уникальность — внутри `auth/{mountPath}/role/`, не глобально | — |
| Token reviewer SA | `beget-vault-system/vault-token-reviewer` в infra-кластере | через `spec.auth.tokenReviewer.serviceAccount` |

**Обоснование выбора naming:**

- `secretsPrefix` immutable — он встраивается в `policies[].rules`, и его изменение делает существующие данные в `secret/data/clusters/{old-prefix}/...` недостижимыми. В редких сценариях миграции пользователь пересоздаёт VaultClaim вручную.
- Policy naming с prefix'ом `{metadata.name}-` — в Vault OSS policies глобальные (нет namespace), без префикса разные кластеры могли бы перезаписывать чужие policies (та же проблема, что с global namespace у `ClusterRole` в Kubernetes).
- Roles НЕ требуют global prefix — они scoped по `auth/{mountPath}/role/`, и `mountPath` уже содержит `{metadata.name}`. Изоляция автоматическая, prefix избыточен.

### 2.5. VaultConfig — минимальный пример

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata:
  name: default                          # Cluster-scoped; обычно один на платформу
spec:
  address: https://vault.beget.com:8200  # URL Vault'а

  managerAuth:                           # как Vault Operator логинится в Vault
    method:    kubernetes
    mountPath: kubernetes-mgmt           # auth method в Vault для manager-логина
    role:      vault-operator            # role внутри этого auth method

  storage:
    kvMountPath: secret                  # общий KV-v2 mount, в котором живут данные
                                         # (оператор только пишет policies на него,
                                         # сам mount разворачивает платформа разово)

  tls:                                   # опционально, если Vault с custom CA
    caBundleRef:
      name: vault-ca-bundle
      namespace: beget-vault-system
    serverName: vault.beget.com
status:
  conditions:
    - { type: Reachable,        status: "True" }
    - { type: ManagerLoggedIn,  status: "True" }
    - { type: SharedMountFound, status: "True" }
  vaultVersion:      "1.17.6"
  lastHealthCheckAt: "2026-05-18T11:00:00Z"
  referencedBy:      7                   # количество VaultClaim'ов, ссылающихся
```

### 2.6. VaultConfig — ключевые поля spec

| Поле | Тип | Назначение |
|------|-----|------------|
| `address` | string (URL) | Адрес Vault сервера. Изменение разрешено — триггерит reconcile всех зависимых VaultClaim'ов. |
| `managerAuth.method` | enum `kubernetes` | Сейчас только Kubernetes Auth Method. Зарезервировано для будущих методов. |
| `managerAuth.mountPath` | string | Путь auth method в Vault, через который логинится сам оператор. Дефолт `kubernetes-mgmt`. |
| `managerAuth.role` | string | Имя role внутри `managerAuth.mountPath`, привязанной к SA контроллера. Дефолт `vault-operator`. |
| `storage.kvMountPath` | string | Имя KV-v2 mount, в котором живут данные секретов всех кластеров. Дефолт `secret`. Immutable. |
| `tls.caBundleRef` | LocalObjectRef (опц.) | Secret/ConfigMap с CA-бандлом, если Vault не подписан публичным CA. |
| `tls.serverName` | string (опц.) | SNI override для TLS-handshake. |

### 2.7. VaultConfig — CEL-валидации и lifecycle

**Валидации (webhook):**

- `metadata.name` — `[a-z0-9-]+`, ≤ 50 символов.
- `spec.address` — обязательный URL `https://`.
- `spec.storage.kvMountPath` immutable (его изменение делает все ранее записанные policies невалидными).
- `spec.managerAuth.mountPath` mutable, но изменение требует, чтобы новый auth method уже существовал в Vault (валидируется на reconcile).

**Finalizer на удаление:** `vault.in-cloud.io/vaultconfig-finalizer`. Блокирует удаление VaultConfig, пока существует хотя бы один VaultClaim с `spec.vaultConfigRef.name = {name}`. При попытке удалить — оператор пишет event с перечислением ссылающихся VaultClaim'ов и оставляет CR в состоянии `Deleting` до тех пор, пока ссылки не уйдут.

**Reconcile-on-change:** изменение VaultConfig (любое поле) триггерит reconcile всех VaultClaim'ов, у которых `spec.vaultConfigRef.name = {name}`, через field indexer. Это обеспечивает, что смена адреса Vault или пути manager-auth немедленно применяется ко всем зависимым VaultClaim'ам.

---

## 3. Аутентификация контроллера и per-cluster auth

### 3.1. Mount paths — чтобы не путаться

| Mount | Назначение | Кто настраивает |
|-------|-----------|-----------------|
| `auth/{VaultConfig.spec.managerAuth.mountPath}/` (дефолт `auth/kubernetes-mgmt/`) | Логин **самого Vault Operator'а** в Vault. SA `vault-operator` в system-кластере → policy `vault-operator-admin`. | **Платформа, разово** (Terraform / runbook). Имя пути и role читаются из `VaultConfig.spec.managerAuth`. |
| `auth/kubernetes-{cluster}/` | Логин **потребителей** infra-кластера. | **Vault Operator** на каждый VaultClaim (Step 5). |

### 3.2. Token reviewer SA в infra-кластере

Vault при логине pod'а проверяет JWT через TokenReview API кластера. Для этого Vault'у нужен **reviewer JWT** — токен SA с правом `tokenreviews.authentication.k8s.io/create`.

Поток:

1. Оператор подключается к infra-кластеру по kubeconfig.
2. (Опц., если `autoCreate: true`) Создаёт `ServiceAccount` `vault-token-reviewer` в `beget-vault-system`.
3. (Опц., если `autoCreate: true`) Создаёт `ClusterRoleBinding` с `ClusterRole: system:auth-delegator`.
4. Через **TokenRequest API** запрашивает JWT этого SA с TTL = 24h и **без явного audience override** (TokenRequestSpec.Audiences = nil). TTL настраивается через `spec.auth.tokenReviewer.ttl` (дефолт 24h). **Почему без audience:** reviewer JWT используется Vault'ом как Bearer-токен для аутентификации в target apiserver при вызове TokenReview API. apiserver валидирует `aud` claim против собственного `--api-audiences` (обычно `service-account-issuer`, по умолчанию `https://kubernetes.default.svc.cluster.local`). Минтинг JWT с `--audience=vault` ломает эту аутентификацию — apiserver отвергнет токен с 401, Vault замаскирует это как 403 "permission denied" для consumer pod'ов. Без override TokenRequest API выдаёт токен с дефолтным audience apiserver'а, который сам apiserver и принимает.
5. Передаёт JWT в Vault как `auth/{mountPath}/config.token_reviewer_jwt`.
6. **Ротация JWT** — оператор отслеживает время выпуска и проактивно перевыпускает токен через TokenRequest API, когда до expiration осталось менее **30%** оставшегося времени. Состояние ротации отражается в `status.vault.tokenReviewerJWT.expiresAt` и в condition `TokenReviewerJWTFresh`. Если ротация не удалась несколько раз подряд — condition становится `False`, и оператор поднимает event.

### 3.3. Permissions контроллера в Vault (policy `vault-operator-admin`)

```hcl
# Управление auth methods.
# Внимание: в Vault ACL `+` matches WHOLE path segment (до следующего `/`),
# НЕ partial-match внутри сегмента. То есть `sys/auth/kubernetes-+` НЕ
# матчится с `sys/auth/kubernetes-ec8a00`. Используем whole-segment `+`
# и полагаемся на naming convention (`kubernetes-{cluster}`) для изоляции
# между claim'ами.
path "sys/auth/+"                     { capabilities = ["create", "read", "update", "delete", "sudo"] }
path "sys/auth/+/*"                   { capabilities = ["create", "read", "update", "delete", "sudo"] }
path "auth/+/config"                  { capabilities = ["create", "read", "update"] }
path "auth/+/role/*"                  { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/+/role"                    { capabilities = ["list"] }

# Проверка существования общего KV mount (read-only, на startup)
path "sys/mounts"                     { capabilities = ["read", "list"] }

# ACL policies
path "sys/policies/acl/*"             { capabilities = ["create", "read", "update", "delete", "list"] }

# Token-self для ротации собственного токена
path "auth/token/renew-self"          { capabilities = ["update"] }
path "auth/token/lookup-self"         { capabilities = ["read"] }
```

**Намеренно НЕ выдаём:** `sys/mounts/secret*` (mount уже настроен платформой, оператор не должен иметь возможность его пересоздать), `secret/data/*`, `secret/metadata/*` — оператор не должен иметь возможности читать/писать сами секреты.

### 3.4. Issuer URL: автодискавер из infra-кластера

`auth/{mountPath}/config.issuer` нужен Vault для валидации `iss` claim в JWT. Источник:

1. Если `spec.auth.issuer` задан явно — используем его.
2. Иначе оператор делает запрос к `/.well-known/openid-configuration` на kube-apiserver infra-кластера (через kubeconfig).
3. Извлекает поле `issuer` из ответа и записывает в Vault config.

Это покрывает случаи, когда apiserver настроен с `--service-account-issuer` ≠ дефолтному `https://kubernetes.default.svc.cluster.local`.

---

## 4. Pipeline выполнения

### 4.1. Граф

```
                     ┌─────────────────────┐
                     │      VaultClaim     │
                     │   создан / изменён  │
                     └──────────┬──────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 1│ Resolve VaultConfig +     │  client с auto-renew;
                  │ login в Vault (mgmt SA)   │  адрес и mountPath
                  │ {managerAuth.mountPath}/  │  из VaultConfig
                  │   login                   │
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 2│ WAIT clusterRef.kubeconfig│  Secret существует
                  │  ready                    │  и валиден
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 3│ Подготовить target:       │  Create SA + CRB
                  │  SA, CRB, issuer-discovery│  (autoCreate=true)
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 4│ TokenRequest в target     │  audience=vault, TTL=24h
                  │   → reviewer JWT          │
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 5│ Auth method per-cluster   │  POST sys/auth/{path},
                  │ (create + config с JWT    │  затем POST auth/{path}/config
                  │  из Step 4)               │  с token_reviewer_jwt
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 6│ Policies (apply ACL)      │  PUT sys/policies/acl/*
                  │ idempotent                │  один вызов на policy
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 7│ Roles (apply + soft-purge)│  POST auth/{mount}/role/*
                  │ idempotent                │  delete лишних
                  └─────────────┬─────────────┘
                                │
                  ┌─────────────▼─────────────┐
            Step 8│      READY                │  Phase = Ready
                  └───────────────────────────┘
```

**Связка Steps 3 → 4 → 5 — это единая процедура подготовки token-reviewer.** В infra-кластере оператор создаёт `ServiceAccount vault-token-reviewer` + `ClusterRoleBinding system:auth-delegator` (Step 3), затем через **TokenRequest API** infra-кластера выпускает JWT этого SA (Step 4), и наконец передаёт этот JWT в Vault как `auth/{mountPath}/config.token_reviewer_jwt` (часть Step 5). С этого момента Vault при логине consumer-pod'ов из infra-кластера использует JWT token-reviewer'а для вызова TokenReview API и валидации pod-токенов.

**Startup-check shared mount.** Существование общего `secret/` KV-v2 mount оператор проверяет один раз на startup (`GET sys/mounts/secret`) — если mount отсутствует, контроллер не стартует и пишет clear error, потому что без него policies бессмысленны. На per-VaultClaim reconcile эта проверка не повторяется.

### 4.2. Идемпотентность всех шагов

| Step | Операция | Идемпотентность |
|------|----------|-----------------|
| 3 | Create SA / CRB через SSA с fieldOwner `vault-operator` | Native idempotent (server-side apply) |
| 4 | TokenRequest — всегда выпускает новый JWT, но **только когда нужно** (до expiration > 30% — пропускаем) | Conditional |
| 5 | `POST sys/auth/{path}` — если 400 (already exists), переходим к `POST auth/{path}/config` | Vault возвращает 204 на повторное config |
| 6 | (опц.) `GET sys/auth/{mountPath}/tune` — только если хоть одна `spec.policies[].rules` содержит `{{ .AuthMountAccessor }}`. Затем `PUT sys/policies/acl/{name}` — overwrites. | Native idempotent; accessor-fetch lazy |
| 7 | `POST auth/{path}/role/{role}` — overwrites; удаляем roles, которых нет в spec (soft-purge через enumeration `LIST auth/{path}/role`) | Soft-purge старых |

**Защитные решения в pipeline:**

- Step 7 soft-purge удаляет роли, отсутствующие в spec, но только в пределах `auth/{mountPath}/role/`, никогда не трогая другие auth mounts. Чужие mounts защищены тем, что `mountPath` включает `{metadata.name}`, и оператор работает только с тем, что matches его spec.
- TokenRequest API (k8s ≥ 1.34) — audience-scoped, short-lived JWT, выпускаемый kube-apiserver на лету. Даёт ротацию по умолчанию и избавляет от долгоживущего credential'а в etcd, который пришлось бы охранять отдельно.

---

## 5. Триггеры и условия перехода

### 5.1. Таблица триггеров

| Step | Действие | Условие перехода | Источник | Если не готов |
|------|----------|------------------|----------|---------------|
| 1 | Login в Vault | Получен `client_token` | Vault API response | RequeueAfter 30s, condition `VaultLoginFailed` |
| **2** | **WAIT kubeconfig** | **Secret `kubeconfigSecret` существует и валиден** | **Watch на Secret** | RequeueAfter 5m |
| 3 | Подготовить target | SA + CRB applied | k8s API через remote client | RequeueAfter 30s |
| 4 | TokenRequest | JWT получен | k8s API | RequeueAfter 1m |
| 5 | Auth method | 200/204 от Vault | API response | RequeueAfter 30s |
| 6 | Policies | 200/204 на каждую | API response | RequeueAfter 1m |
| 7 | Roles | 200/204 + soft-purge done | API response | RequeueAfter 1m |
| 8 | READY | — | — | Phase=Ready, RequeueAfter 10m (drift) |

### 5.2. Reconcile стратегия (events + periodic)

```
RequeueAfter:
  WAIT kubeconfig                  → 5m (страховка, главное — Watch)
  Phase = Ready (drift-detect)     → 10m
  Vault API error / login failed   → 30s, exponential up to 5m
  Render / spec validation error   → 1m, Phase=Failed
  JWT renewal needed (Step 4)      → reconcile-on-event при approaching expiration
```

### 5.3. Drift detection

На каждом reconcile при `Phase=Ready` оператор:

1. `LIST sys/auth` → проверяет существование `auth/{mountPath}/`.
2. `LIST sys/policies/acl` → diff по `spec.policies[].name`.
3. `LIST auth/{mountPath}/role` → diff по `spec.roles[].name`.
4. Для каждого расхождения — `Configuring` фаза + соответствующий step.

Покрывает кейс «кто-то руками удалил policy в Vault UI» — оператор её восстановит. Общий `secret/` mount считается частью базового окружения и в drift-check не входит — его восстановлением занимается платформа.

---

## 6. Watches и reconcile стратегия

| Ресурс | Механизм | Что триггерит |
|--------|----------|---------------|
| `VaultClaim` | Primary | Полный reconcile |
| `Secret` (kubeconfig) | predicate: name match | Step 2 |
| `ClusterClaim` | name ref через field indexer | Reconcile при появлении clusterRef.name |
| `VaultConfig` | field indexer по `VaultClaim.spec.vaultConfigRef.name` | Изменение VaultConfig → enqueue всех зависимых VaultClaim'ов (cascade re-login + drift-check) |

**Vault HTTP API не имеет watch** — drift detection делается через периодический reconcile (§5.3), не push-механизм. Это принципиальное отличие от других beget-операторов: `cluster-claim-operator` живёт на watch-событиях k8s, а Vault Operator вынужден polling'ом проверять Vault. Из этого следуют два требования к реализации: circuit breaker для Vault и оценка стоимости reconcile при росте количества VaultClaim'ов. Drift detection в такой архитектуре — не nice-to-have, а единственный способ заметить ручные изменения в Vault UI; без неё они накопятся как «теневой config», и при первом обновлении spec оператор перезапишет их без предупреждения.

---

## 7. Удаление и finalizer

Finalizer: `vault.in-cloud.io/finalizer`.

### 7.1. Обратный pipeline

```
Phase = Deleting
  1. (Опц.) Snapshot истории — дамп ролей/полиси для аудита
  2. Delete roles                     — DELETE auth/{mountPath}/role/*
  3. Delete policies                  — DELETE sys/policies/acl/*
  4. Delete auth method               — DELETE sys/auth/{mountPath}
  5. Delete token-reviewer SA + CRB в target (best-effort, если autoCreate=true)
  6. Remove finalizer
```

### 7.2. Данные в KV не трогаем

`secret/data/clusters/{cluster}/...` остаются в Vault после удаления VaultClaim. Это сознательное решение: данные — зона ответственности отдельного оператора (см. K8S-224), а Vault Operator не имеет прав на их чтение/запись (§3.3). Случайное удаление VaultClaim не приводит к потере секретов; администратор может пересоздать VaultClaim с тем же `secretsPrefix` и получить тот же набор путей с прежними значениями.

---

## 8. Топология в Vault

Vault OSS, один общий KV-v2 mount `secret/`, per-cluster auth methods и policies. Изоляция кластеров — через path-prefix `secret/data/clusters/{cluster}/` и naming policies `{cluster}-{role}`.

```
auth/
  kubernetes-mgmt/                       ← оператор логинится сюда
  kubernetes-ec8a00/                     ← per-cluster auth (Step 5)
  kubernetes-rktqvfd/

secret/                                  ← общий KV-v2 mount, развёрнут платформой
  data/clusters/ec8a00/monitoring/vmauth/credentials
  data/clusters/ec8a00/argocd/...
  data/clusters/rktqvfd/monitoring/vmauth/credentials
  ...

sys/policies/acl/
  ec8a00-vmauth-reader                   ← Step 6
  ec8a00-argocd-reader
  rktqvfd-vmauth-reader
```

Что гарантирует изоляцию между кластерами:

- `auth/kubernetes-{cluster}/` — JWT pod'а из кластера A не пройдёт валидацию в auth method кластера B (разные `token_reviewer_jwt` и `kubernetes_host`).
- `policies[].rules` — каждая policy жёстко привязана к префиксу `secret/data/clusters/{cluster}/...`; policy кластера A не даст pod'у читать данные кластера B даже теоретически.
- Naming convention `{cluster}-{role}` — defense-in-depth против случайной перезаписи policies при ручных операциях.

---

## 9. Status и Conditions

### 9.1. Phase

| Phase | Когда |
|-------|-------|
| `Pending` | CR создан, ещё не reconciled / kubeconfig не готов |
| `Configuring` | Pipeline в процессе (Steps 1–9) или drift fix |
| `Ready` | Все Steps OK, drift detection passing |
| `Failed` | Невосстановимая ошибка (type mismatch у KV mount, semantic spec error) |
| `Deleting` | Idle finalizer cleanup |

### 9.2. Conditions

| Type | True означает |
|------|---------------|
| `ConfigResolved` | `spec.vaultConfigRef.name` указывает на существующий VaultConfig, который сам в состоянии `Reachable=True` и `SharedMountFound=True` |
| `VaultReachable` | Login успешен (через `managerAuth` из VaultConfig), токен валиден |
| `KubeconfigAvailable` | Step 2 OK |
| `AuthMountReady` | Step 5 OK, config validate |
| `PoliciesApplied` | Step 6 OK, все из `spec.policies[]` записаны |
| `RolesApplied` | Step 7 OK, soft-purge не оставил лишних |
| `TokenReviewerJWTFresh` | Reviewer JWT, записанный в `auth/{mountPath}/config.token_reviewer_jwt`, выпущен или продлён в текущее окно ротации; до expiration осталось > 30% TTL |
| `Ready` | Aggregate, все выше = True |

### 9.3. Зеркалирование в `status.vault`

```yaml
status:
  vault:
    configName:       default                # resolved VaultConfig
    authMountPath:    kubernetes-ec8a00
    secretsPrefix:    clusters/ec8a00
    appliedRoles:     [vmauth-reader, argocd-reader]
    appliedPolicies:  [ec8a00-vmauth-reader, ec8a00-argocd-reader]
    tokenReviewerJWT:
      issuedAt:    "2026-05-15T08:00:00Z"
      expiresAt:   "2026-05-16T08:00:00Z"
      lastRotated: "2026-05-15T08:00:00Z"
    lastReconcileAt:  "2026-05-07T14:00:00Z"
```

Адрес Vault и manager-auth не дублируем в `VaultClaim.status` — их видно в `VaultConfig.status` (один источник истины). Быстрая проверка «что настроено в Vault для этого кластера» делается через `kubectl get vaultclaim {name} -o yaml` + `kubectl get vaultconfig {configName}`.

---

## 10. Опциональная схема: одна policy с identity templating

Vault поддерживает [identity templating в ACL-policies](https://developer.hashicorp.com/vault/tutorials/policies/policy-templating): атрибут залогиненной entity подставляется в path. Можно описать **одну** policy для всего кластера, где доступ ограничен namespace'ом pod'а:

```hcl
path "secret/data/clusters/ec8a00/{{identity.entity.aliases.<auth-mount-accessor>.metadata.service_account_namespace}}/*" {
  capabilities = ["read", "list"]
}
```

Vault при логине pod'а из namespace `monitoring` сам подставит `monitoring` в path — pod увидит только `secret/data/clusters/ec8a00/monitoring/*`. Это та самая «разбивка ролевки по namespace в рамках кластера», ради которой используется accessor.

**Когда использовать:**

- Много namespace'ов с однотипной моделью доступа (каждый namespace → свой prefix).
- Хочется одну роль на весь кластер вместо N ролей.

**Когда НЕ использовать:**

- Сложные модели прав (разные TTL, разные capabilities, cross-namespace доступ).
- Аудит проще читать, если есть `{cluster}-{role}` именованные policies — у каждого consumer'а своя.

В v1 оператор **обе схемы поддерживает одинаково**: пользователь сам пишет HCL в `spec.policies[].rules`. Если в шаблоне используется `{{ .AuthMountAccessor }}`, оператор автоматически подгрузит accessor свежесозданного auth method и подставит в render. Если переменная не используется — accessor вообще не запрашивается, дополнительных вызовов Vault API не происходит.

**Особенности реализации templating:**

- `auth-mount-accessor` опционален. Перед Step 6 оператор просматривает `spec.policies[].rules` и определяет, ссылается ли хоть одна policy на `{{ .AuthMountAccessor }}`. Если ссылается — делает дополнительный `GET sys/auth/{mountPath}/tune` (или `LIST sys/auth`), достаёт accessor и кладёт в TemplateContext. Если нет — Step 6 рендерит сразу, без обращения к Vault за accessor'ом.
- Identity templating снимает «N policies на N namespace'ов», но не работает для случаев, когда хочется разные права на разные пути в одном namespace (например, `monitoring/vmauth-read` + `monitoring/grafana-write`). Для таких сценариев — несколько именованных policies с конкретными path'ами.

---

## 11. Связь с другими операторами Beget

| Оператор | Связь |
|----------|-------|
| `cluster-claim-operator` | Источник `kubeconfig` Secret через `clusterRef`. **VaultClaim создаётся ПОСЛЕ** того, как ClusterClaim достиг Phase=Ready (или хотя бы certset[infra]+kubeconfig готовы). Триггер — пользователь / GitOps, не cluster-claim. |
| `certificate-set` | Опосредовано — kubeconfig Secret приходит из его pipeline. |
| `addons-operator` | Аддоны в infra-кластере (vmauth, ArgoCD, ...) являются consumer'ами Vault. Их Helm values содержат `VAULT_ADDR` (глобальная константа платформы) и `VAULT_AUTH_PATH = auth/kubernetes-{cluster}` — шаблонные значения, собираются самим чартом из имени кластера. См. K8S-225. |
| `secret-copy-operator` | Пересекается на задаче раздачи секретов. После запуска Vault Operator — `secret-copy` остаётся для bootstrap-секретов и кейсов, где Vault недоступен. Постепенный мигрейшн. |
| `worker-group-claim-operator` | Не связан напрямую. |

### 11.1. Поток на примере vmauth

```
1. cluster-claim-operator → Cluster[infra] Ready, kubeconfig Secret готов
2. Платформа создаёт VaultClaim для этого кластера (вручную или через Helm)
3. Vault Operator:
     - login → auth/kubernetes-mgmt
     - в target создаёт SA `vault-token-reviewer` + CRB system:auth-delegator
     - TokenRequest → reviewer JWT
     - в Vault: auth/kubernetes-ec8a00 + config,
       policy ec8a00-vmauth-reader (path "secret/data/clusters/ec8a00/monitoring/vmauth/*"),
       role vmauth-reader (SA monitoring/vmauth)
4. Отдельный оператор данных (K8S-224) кладёт секрет в Vault:
     vault kv put secret/clusters/ec8a00/monitoring/vmauth/credentials \
       user=... password=...
5. addons-operator → деплоит vmauth с агентом (vault-injector / vault-csi / app-side).
   Helm values чарта vmauth содержат VAULT_ADDR (глобальная константа платформы)
   и VAULT_AUTH_PATH = auth/kubernetes-{ClusterClaim.name} — оба значения
   шаблонные, чарт собирает их сам из имени кластера.
6. Pod startup → auth/kubernetes-ec8a00/login с SA JWT + role=vmauth-reader
                → возвращается client token → секрет монтируется
```

---

## 12. Принятые решения

| # | Решение | Обоснование |
|---|---------|-------------|
| D1 | **Vault OSS** — без Enterprise namespaces | Используется бесплатная редакция Vault; multi-tenancy за счёт naming convention и path-isolation в policies (§8). |
| D2 | **Один общий `secret/` KV-v2 mount**, развёрнут платформой разово | Оператор не создаёт и не обновляет mount; работает только с policies/roles/auth, ссылающимися на префикс `secret/data/clusters/{cluster}/...`. |
| D3 | **TokenReview JWT** для валидации pod-токенов | Vault использует `token_reviewer_jwt` SA `vault-token-reviewer` в infra-кластере (см. §3.2); вариант с JWKS отклонён. |
| D4 | **TokenRequest API** для получения reviewer JWT, **Kubernetes ≥ 1.34** в infra-кластерах | Audience-scoped, short-lived, автоматическая ротация; в платформе нет кластеров старше 1.34, поэтому fallback на Secret-type SA token не требуется. |
| D5 | **Один VaultClaim на кластер** (1:1 с ClusterClaim) | `VaultClaim.metadata.name` = `ClusterClaim.metadata.name`. |
| D6 | **Policies называются `{cluster}-{role}`**, roles — без global prefix (scoped по auth mount) | Защита от перезаписи в OSS глобальном namespace policies. |
| D7 | **Данные в KV пишет отдельный оператор** (см. K8S-224) | Vault Operator не имеет прав на `secret/data/*` и `secret/metadata/*`. |
| D8 | **Auto-renew client-token оператора** через `auth/token/renew-self` при достижении 60% TTL | Без долгих re-login circle на каждый reconcile. |
| D9 | **Reviewer JWT для SA `vault-token-reviewer`** выпускается через TokenRequest API infra-кластера с TTL=`spec.auth.tokenReviewer.ttl` (дефолт `24h`); оператор **проактивно перевыпускает** токен и обновляет `auth/{mountPath}/config.token_reviewer_jwt` при остатке < 30% TTL. Состояние видно в `status.vault.tokenReviewerJWT.{issuedAt,expiresAt,lastRotated}` и в condition `TokenReviewerJWTFresh`. | Без проактивной ротации Vault перестанет валидировать pod-токены, когда reviewer JWT истечёт, и весь кластер потеряет доступ к секретам. |
| D10 | **Метрики**: controller-runtime defaults + кастомные `vault_api_responses_total{verb,path,code}`, `vault_api_calls_total{verb,path,result}`, `vaultclaim_drift_detected_total`, `vault_client_token_renewal_total`, `vault_reviewer_jwt_renewal_total{result}` | Коды ответов Vault выделены в отдельную метрику для алертов на 5xx/403. Ротация client-token и reviewer JWT — разные метрики, потому что фейлы у них разные по последствиям. |
| D11 | **При удалении VaultClaim данные в KV не трогаем** | Они не принадлежат этому оператору; policy `vault-operator-admin` это даже технически не позволяет (см. §3.3). |
| D12 | **При удалении VaultClaim token-reviewer SA + CRB в target — best-effort cleanup**, чужие SA не трогаем | Удаляются только ресурсы, которые оператор сам создал в namespace `beget-vault-system`. |
| D13 | **VaultConfig CRD** (Cluster-scoped) — глобальная конфигурация подключения к Vault: `address`, `managerAuth.{mountPath,role}`, `storage.kvMountPath`, `tls`. VaultClaim ссылается через `spec.vaultConfigRef.name`. Multi-Vault поддерживается через несколько именованных VaultConfig'ов. Finalizer блокирует удаление VaultConfig, пока на него ссылаются VaultClaim'ы. | Снимает дублирование Vault-параметров в каждом VaultClaim, даёт типизированный API (vs ConfigMap), готовит почву для multi-Vault и миграции кластеров между system-кубами. |

---

## 13. План реализации (предложение для K8S-38)

| Story | Размер | Что |
|-------|--------|-----|
| 001 | M | Scaffold (kubebuilder v4), CRDs VaultClaim + VaultConfig, типы |
| 002 | M | Vault client wrapper + login flow (с параметрами из VaultConfig) + token auto-renew |
| 003 | M | VaultConfig reconciler — health-check Vault, status conditions, field indexer + cascade reconcile зависимых VaultClaim'ов, finalizer-блокировка удаления |
| 004 | L | Pipeline framework + Steps 1–4 (resolve VaultConfig + login, kubeconfig, target SA/CRB, TokenRequest), включая проактивную ротацию reviewer JWT и update `auth/{mount}/config.token_reviewer_jwt` |
| 005 | L | Steps 5–7 (auth method, policies с опц. accessor templating, roles + soft-purge) |
| 006 | M | Drift detection, Conditions, Status mirroring; проверка shared mount теперь идёт через VaultConfig.status |
| 007 | M | Deletion + finalizer (reverse pipeline, без KV-операций); finalizer на VaultConfig блокирует его удаление при существующих ссылках |
| 008 | S | Watches + indexers + webhook validation (CEL) для обоих CRD |
| 009 | S | Observability — events, metrics (включая `vault_api_responses_total{code}`), troubleshooting docs |
| 010 | M | E2E tests (envtest + Vault dev-mode container в test fixture) |

---

## 14. Что осталось вне этого документа

- **Развёртывание самого Vault** (HA, storage backend, unseal) — отдельная epic, не контроллер.
- **Bootstrap policy `vault-operator-admin`** в Vault и auth method, указанный в `VaultConfig.spec.managerAuth.mountPath` (дефолт `auth/kubernetes-mgmt/`) — runbook платформы.
- **Создание самого `VaultConfig default`** — выполняется платформой при первой раскатке оператора (Helm chart / GitOps).
- **UI/CLI access для пользователей** в Vault (OIDC, AD, userpass) — не задача этого оператора.
- **Pull-секретов в pod'ы**: vault-injector vs vault-csi vs собственная логика consumer'а — выбор делает каждый аддон.
- **Координаты Vault для consumer'ов** (`VAULT_ADDR`, путь auth method) — Helm values каждого чарта собирают их сами из имени кластера; оператор в infra-кластер ничего не публикует.
- **Кто и как пишет данные в KV** (K8S-224) — отдельная задача.
- **Развёртывание общего `secret/` KV-v2 mount** в Vault — runbook платформы; контроллер только проверяет его наличие.

