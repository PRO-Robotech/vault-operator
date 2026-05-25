# Auth & Policies

Как оператор связывает в Vault три уровня — auth method, ACL-policies и role bindings — так, чтобы pod в infra-кластере под конкретным SA получил доступ только к нужным секретам.

## Три уровня

```
                         pod (SA: monitoring/vmauth)
                                │
                                │ POST auth/kubernetes-ec8a00/login
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Auth Method: kubernetes-ec8a00                              │
   │   config.kubernetes_host:       https://kube-apiserver/    │
   │   config.token_reviewer_jwt:    <SA vault-token-reviewer>  │
   │   config.issuer:                <OIDC issuer кластера>     │
   │                                                             │
   │   Role: vmauth-reader                                       │
   │     bound_service_account_names:      [vmauth]              │
   │     bound_service_account_namespaces: [monitoring]          │
   │     token_policies:                   [ec8a00-vmauth-reader]│
   └────────────────────────────────────────────────────────────┘
                                │
                                │ выдаёт client_token
                                ▼
   ┌────────────────────────────────────────────────────────────┐
   │ ACL Policy: ec8a00-vmauth-reader                            │
   │   path "secret/data/clusters/ec8a00/monitoring/vmauth/*" { │
   │     capabilities = ["read", "list"]                         │
   │   }                                                         │
   └────────────────────────────────────────────────────────────┘
```

## Уровень 1: Auth Method

**Что:** `POST sys/auth/{spec.auth.mountPath}` (тип `kubernetes`).

**Конфигурация (`auth/{mount}/config`):**

| Поле | Источник |
|---|---|
| `kubernetes_host` | URL apiserver'а из kubeconfig-секрета |
| `kubernetes_ca_cert` | CA-bundle из kubeconfig-секрета |
| `token_reviewer_jwt` | JWT, выпущенный TokenRequest'ом для SA `vault-token-reviewer` |
| `issuer` | `spec.auth.issuer` или `iss` claim из OIDC discovery |
| `disable_iss_validation` | `true`, если `issuer` пуст и discovery провалился |
| `disable_local_ca_jwt` | Всегда `true` — Vault работает вне infra-кластера |

**Идемпотентность:** при `POST sys/auth` Vault отвечает 400, если mount уже существует — оператор игнорирует и идёт к `auth/{mount}/config`.

## Уровень 2: ACL Policies

**Что:** `PUT sys/policies/acl/{name}` с HCL-телом.

**Имена политик в Vault OSS — плоское глобальное пространство имён.** Префиксуйте именем кластера или claim'а:

```hcl
# ec8a00-vmauth-reader
path "secret/data/clusters/ec8a00/monitoring/vmauth/*" {
  capabilities = ["read", "list"]
}
```

**Soft-purge оператор НЕ делает для политик** — если убрать запись из `spec.policies[]`, политика остаётся в Vault. (Причина: политика может быть переиспользована другим claim'ом, а различить «моя» от «чужой» без явного префикса нельзя.) Удаление вручную или через reverse-pipeline при удалении claim'а.

## Уровень 3: Roles

**Что:** `POST auth/{mount}/role/{name}` — связывает SA + namespace с policy.

**Один SA на роль** — CRD ограничивает `boundServiceAccounts` единичной парой `{name, namespace}`. Хотя Vault принимает массивы и делает декартово произведение, мы намеренно избегаем этого:

| Причина | Объяснение |
|---|---|
| Аудит | Лог-запись Vault `login` называет роль; роль 1:1 с SA → ясно, кто залогинился |
| Per-SA tuning | TTL, max-TTL, bound CIDR можно настроить только если каждая роль — про один SA |
| Identity mapping | Vault entity ↔ SA однозначен |

Если одну политику нужно раздать N SA — создаются N ролей с одинаковыми `policies: [...]`.

**Soft-purge для ролей** — да: при reconcile оператор `LIST auth/{mount}/role` и удаляет имена, которых нет в `spec.roles[]`. Срабатывает только в пределах конкретного auth-mount этого claim'а, так что чужие роли (других claim'ов) не задеваются.

## TTL и Max-TTL

| Поле в `RoleSpec` | Эффект |
|---|---|
| `tokenTTL` | Время жизни выпущенного client_token. По умолчанию — system default. |
| `tokenMaxTTL` | Максимум при renew. Без него client_token можно бесконечно продлевать в пределах TTL. |

## Token Reviewer JWT

Этот JWT — не для pod'ов в infra-кластере. Он принадлежит **самому Vault'у**: Vault использует его, чтобы вызывать **TokenReview API** infra-кластера и проверять предъявленные pod'ами JWT.

- SA `vault-token-reviewer` в namespace `beget-vault-system` (или указанном в `spec.auth.tokenReviewer.serviceAccount.namespace`)
- ClusterRoleBinding `system:auth-delegator` даёт permission на `TokenReview`
- JWT выпускается через TokenRequest API (`POST /api/v1/namespaces/{ns}/serviceaccounts/{name}/token`)
- TTL — `spec.auth.tokenReviewer.ttl` (по умолчанию 24h)
- **Ротация — проактивная**: оператор обновляет JWT когда остаётся <30% TTL

**Безопасность:** байты JWT никогда не сохраняются в `VaultClaim.status` — только timestamps `issuedAt`/`expiresAt`/`lastRotated`. JWT попадает только в Vault (`auth/{mount}/config.token_reviewer_jwt`) и в памяти контроллера на одну итерацию reconcile.

## Жизненный цикл с точки зрения pod'а в infra-кластере

```
1. Pod стартует под SA monitoring/vmauth
2. Пакет/sidecar читает JWT из /var/run/secrets/.../token
3. POST https://vault.beget.com/v1/auth/kubernetes-ec8a00/login
   { "role": "vmauth-reader", "jwt": "<SA-JWT>" }

4. Vault:
   - Берёт reviewer JWT из auth/kubernetes-ec8a00/config
   - Вызывает TokenReview infra-кластера, передаёт SA-JWT и reviewer-JWT для auth
   - apiserver проверяет SA-JWT и возвращает { sub: "system:serviceaccount:monitoring:vmauth" }
   - Vault сверяет с role: bound_service_account_names=[vmauth], namespaces=[monitoring] ✓
   - Vault выпускает client_token с token_policies=[ec8a00-vmauth-reader]

5. Pod использует client_token:
   GET https://vault.beget.com/v1/secret/data/clusters/ec8a00/monitoring/vmauth/credentials
   → политика разрешает → 200 OK
```

Оператор в этом потоке не участвует — он лишь подготовил уровни 1-3.

## Связанные документы

- [VaultClaim](vaultclaim.md) — где описываются policies и roles
- [Identity templating](identity-templating.md) — `{{ .AuthMountAccessor }}` в HCL
- [Управление policies и roles](../user-guide/managing-policies-and-roles.md) — практическое руководство
