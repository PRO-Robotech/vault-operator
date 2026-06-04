# Identity Templating

Vault ACL-policies могут содержать ссылки на **identity** — атрибуты залогиненного entity (псевдо-пользователя). Самый частый сценарий в vault-operator — ограничить доступ namespace'ом pod'а через `{{ identity.entity.aliases.{accessor}.metadata.service_account_namespace }}`.

## Когда это нужно

Без identity templating — для каждой пары `(SA, namespace) → policy` приходится писать **отдельную политику** с явным namespace в path:

```hcl
# 100 namespace'ов = 100 политик
path "secret/data/clusters/ec8a00/monitoring/vmauth/*" { ... }
path "secret/data/clusters/ec8a00/billing/svc/*" { ... }
path "secret/data/clusters/ec8a00/observability/loki/*" { ... }
...
```

С identity templating — **одна политика на N namespace'ов**:

```hcl
path "secret/data/clusters/ec8a00/{{ identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace }}/*" {
  capabilities = ["read", "list"]
}
```

Vault на login'е автоматически проставляет `metadata.service_account_namespace`; ACL подставляет его в path.

## Как это работает в операторе

1. Оператор замечает в `spec.policies[].rules` подстроку `.AuthMountAccessor`.
2. Лениво (один раз за reconcile) вызывает `GET sys/auth`, достаёт accessor для `spec.auth.mountPath`.
3. Прогоняет HCL через `text/template` с `data = { AuthMountAccessor: "auth_kubernetes_a1b2c3" }`.
4. Записывает отрендеренный HCL через `PUT sys/policies/acl/{name}`.

Accessor кэшируется в `status.vault.authMountAccessor` для отладки (`kubectl describe`).

## Пример

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata:
  name: ec8a00
  namespace: dlputi1u
spec:
  vaultConfigRef: { name: default }
  clusterRef:     { name: ec8a00 }
  secretsPrefix: clusters/ec8a00
  auth:
    mountPath: kubernetes-ec8a00
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer

  policies:
    - name: ec8a00-namespace-scoped
      rules: |
        # Любой pod из любого namespace в этом кластере читает секреты
        # только из своего namespace.
        path "secret/data/clusters/ec8a00/{{`{{`}} identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace {{`}}`}}/*" {
          capabilities = ["read", "list"]
        }

  roles:
    - name: namespace-reader-monitoring
      boundServiceAccounts: { name: vmauth, namespace: monitoring }
      policies: [ec8a00-namespace-scoped]
    - name: namespace-reader-billing
      boundServiceAccounts: { name: svc, namespace: billing }
      policies: [ec8a00-namespace-scoped]
```

Pod `monitoring/vmauth` залогинится в роль `namespace-reader-monitoring`, получит client_token с политикой `ec8a00-namespace-scoped`, и сможет прочитать только `secret/data/clusters/ec8a00/monitoring/*`. Pod `billing/svc` — только `secret/data/clusters/ec8a00/billing/*`. Политика одна.

## Двойное экранирование

Внутри YAML-строки `rules` имеется два уровня шаблонизации:

1. **Внешний** — Go `text/template` оператора подставляет `.AuthMountAccessor`.
2. **Внутренний** — Vault на login'е подставляет identity-атрибуты.

Чтобы Vault'овские `{{ ... }}` дошли до Vault как есть и не были съедены первым уровнем, экранируйте их `{{`{{`}} ... {{`}}`}}`:

```hcl
# Что пишем в spec.policies[].rules
path "secret/data/{{`{{`}} identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace {{`}}`}}/*" {
```

После рендера оператором уходит в Vault:

```hcl
path "secret/data/{{ identity.entity.aliases.auth_kubernetes_a1b2c3.metadata.service_account_namespace }}/*" {
```

## Доступные identity-атрибуты

| Атрибут | Описание |
|---|---|
| `service_account_namespace` | Namespace pod'а |
| `service_account_name` | Имя SA |
| `service_account_uid` | UID SA |
| `service_account_secret_name` | Имя legacy SA-секрета (если есть) |

Полный список — [Vault docs: Kubernetes Auth Method](https://developer.hashicorp.com/vault/docs/auth/kubernetes#metadata).

## Когда НЕ использовать

- **Маленькое число пар (SA, namespace)** — проще одну явную политику на пару, чем шаблон.
- **Разные capabilities по namespace** — templating даёт один path-шаблон с одинаковыми `capabilities`. Если monitoring читает, а billing пишет, разделяйте.
- **Если шаблонизация раздражает** — Vault считает identity templating «advanced»; явные политики проще читать в audit log'е.

## Связанные документы

- [Auth & Policies](auth-and-policies.md) — общий стек
- [Пример](../examples/identity-templating/README.md) — рабочий YAML
- [Vault docs: Templated Policies](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies)
