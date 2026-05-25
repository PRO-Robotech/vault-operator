# VaultClaim

## Обзор

- Namespaced-ресурс, описывающий Vault-конфигурацию для одного infra-кластера
- 1:1 с `ClusterClaim`: один VaultClaim — один кластер
- Содержит: ссылку на VaultConfig, ссылку на kubeconfig-секрет, спецификацию auth-mount, ACL-policies и роли
- Оператор создаёт в Vault auth-method, политики и роли, а в infra-кластере — SA + CRB для TokenReview

## Структура spec

```yaml
spec:
  vaultConfigRef:       # подключение к Vault (мутируемо)
    name: default
  clusterRef:           # источник kubeconfig (immutable)
    name: ec8a00
    kubeconfigSecret: ec8a00-infra-kubeconfig    # опционально
  secretsPrefix: clusters/ec8a00                  # immutable
  auth:                                           # настройки auth-mount (mountPath immutable)
    mountPath: kubernetes-ec8a00
    autoCreate: true
    issuer: ""                                    # пусто → автоопределение по OIDC discovery
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer
        autoCreate: true
      ttl: 24h
  policies: [...]
  roles: [...]
```

## Immutable поля

| Поле | Почему immutable |
|---|---|
| `spec.clusterRef.name` | Привязка к конкретному кластеру; смена = другой кластер |
| `spec.secretsPrefix` | Все политики ссылаются на префикс; смена их инвалидирует |
| `spec.auth.mountPath` | Auth-mount привязан к имени; смена оставит старый mount «висеть» |

Изменение валидируется через CEL — `kubectl apply` отклонит изменение этих полей.

## Что попадает в status

| Поле | Описание |
|---|---|
| `phase` | `Pending`, `Configuring`, `Ready`, `Failed`, `Deleting` |
| `observedGeneration` | Последнее обработанное `metadata.generation` |
| `conditions[]` | 8 типов: `ConfigResolved`, `VaultReachable`, `KubeconfigAvailable`, `TokenReviewerJWTFresh`, `AuthMountReady`, `PoliciesApplied`, `RolesApplied`, `Ready` |
| `vault.configName` | Имя резолвнутого VaultConfig |
| `vault.authMountPath` | Путь auth-mount в Vault |
| `vault.authMountAccessor` | Accessor (кэшируется лениво при первом использовании в templating) |
| `vault.appliedPolicies[]` | Имена политик, фактически записанных в Vault |
| `vault.appliedRoles[]` | Имена ролей, фактически созданных в Vault |
| `vault.tokenReviewerJWT.*` | Timestamps жизненного цикла reviewer JWT (без самого JWT) |
| `vault.lastReconcileAt` | Время последнего успешного reconcile |
| `vault.lastDriftCheckAt` | Время последней проверки drift |

## Жизненный цикл фаз

```
                    ┌────────────┐
        создание ──►│Configuring │──► Ready
                    └────────────┘     │
                                       │ при изменении spec / drift
                                       ▼
                    ┌────────────┐  ┌────────────┐
                    │ Failed     │  │Configuring │
                    │ (терминаль-│  │ (повтор)   │
                    │  ная ошиб.)│  └─────┬──────┘
                    └────────────┘        │
                                          ▼
                                        Ready

        удаление ──► Deleting ──► finalizer снят ──► удалён
```

## Связь с другими ресурсами

```
                     references
   VaultClaim ─────────────────────────► VaultConfig (cluster-scoped)
       │                                       │
       │ clusterRef.kubeconfigSecret           │ describes connection
       ▼                                       ▼
   Secret ({name}-infra-kubeconfig)       HashiCorp Vault
       │
       │ kubeconfig
       ▼
   Infra-кластер (TokenRequest, SA create/delete)
```

## Безопасность

- **JWT reviewer'а никогда не хранится в `status`** — только timestamps. Сами байты живут в `auth/{mount}/config.token_reviewer_jwt` в Vault и в памяти контроллера на время reconcile.
- **Finalizer `vault.in-cloud.io/finalizer`** удерживает claim до полного reverse-pipeline (роли → политики → auth-mount → SA в infra-кластере).
- **Cleanup в infra-кластере best-effort** — если kubeconfig-секрет удалён или apiserver недоступен, оператор всё равно снимет finalizer, чтобы claim не висел в `Deleting` вечно.

## Лучшие практики

1. **Имя claim = имя ClusterClaim** — упрощает поиск, eventing и привязку имён auth-mount.
2. **Префиксуйте имена policies** — например, `{cluster}-{role}` (`ec8a00-vmauth-reader`). Policies в Vault OSS живут в плоском пространстве имён, без префикса будут конфликты.
3. **Используйте `tokenReviewer.serviceAccount.autoCreate: true`** — без этого надо вручную поддерживать SA + ClusterRoleBinding в каждом infra-кластере.
4. **TTL token-reviewer'а 24h по умолчанию** — оператор ротирует за 30% TTL; для критичных кластеров можно поднять до 48h, чтобы пережить простой оператора.
5. **`policies` в claim — только те, что *этот claim* владеет** — другие политики оператор не трогает, но и не отслеживает.

## Связанные документы

- [VaultConfig](vaultconfig.md) — подключение к Vault
- [Pipeline](pipeline.md) — 7 шагов reconcile
- [Auth & Policies](auth-and-policies.md) — как auth-method, policies и roles работают вместе
- [API Reference](../reference/api.md) — все поля CRD
