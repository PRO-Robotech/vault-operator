# VaultConfig

## Обзор

- Cluster-scoped ресурс — описывает подключение к HashiCorp Vault
- Один VaultConfig обычно достаточно (`default`); несколько именованных — для multi-Vault
- Содержит адрес, способ аутентификации оператора, путь общего KV-mount и опциональные TLS-настройки
- VaultConfigReconciler непрерывно проверяет здоровье Vault и публикует условия

## Структура spec

```yaml
spec:
  address: https://vault.beget.com:8200    # https:// в проде, http:// для dev/e2e
  managerAuth:
    method: kubernetes                     # единственный поддерживаемый в v1alpha1
    mountPath: kubernetes-mgmt             # auth-mount, через который логинится оператор
    role: vault-operator                   # роль, привязанная к SA оператора
  storage:
    kvMountPath: secret                    # immutable, общий KV-v2 mount
  tls:                                     # опционально
    caBundleRef:
      namespace: vault-operator-system
      name: vault-ca
    serverName: vault.beget.com
```

## Что попадает в status

| Поле | Описание |
|---|---|
| `observedGeneration` | Последнее обработанное `metadata.generation` |
| `conditions[]` | 5 типов: `Reachable`, `VaultInitialized`, `VaultUnsealed`, `ManagerLoggedIn`, `SharedMountFound` |
| `sealStatus` | Сырой ответ `GET /v1/sys/seal-status` — `sealed`, `initialized`, `t`/`n` (Shamir), `progress` |
| `vaultVersion` | Версия Vault, сообщённая seal-status |
| `lastHealthCheckAt` | Время последнего health-probe |
| `referencedBy` | Число VaultClaim'ов, ссылающихся на этот VaultConfig |

## Цикл проверки здоровья

```
        ┌────────────────────┐
        │ GET sys/seal-status│ ← без авторизации
        └─────────┬──────────┘
                  │
        ┌─────────┴──────────┐
        │ initialized?       │── нет → VaultInitialized=False, requeue 1 min
        ├─────────┬──────────┤
        │ sealed?           │── да  → VaultUnsealed=False, requeue 1 min, очистить кэш токена
        ├─────────┴──────────┤
        │ POST auth/.../login│
        └─────────┬──────────┘
                  │
                  ▼
        ┌────────────────────┐
        │ GET sys/mounts     │ ← проверка наличия KV-mount
        └─────────┬──────────┘
                  │
                  ▼
              Reachable=True, ManagerLoggedIn=True, SharedMountFound=True
              requeue 5 min
```

| Состояние | RequeueAfter |
|---|---|
| Здоров (все 5 условий True) | 5 min |
| Sealed/uninitialized | 1 min |
| Сеть/login сломан | 30 sec |

## Immutable поля

| Поле | Почему |
|---|---|
| `spec.storage.kvMountPath` | Каждый VaultClaim ссылается через `secretsPrefix` на путь под этим mount — смена сломает все политики во всех claim'ах |

## Финализатор и удаление

VaultConfig имеет `vault.in-cloud.io/vaultconfig-finalizer`. Пока `status.referencedBy > 0`, оператор отказывается снимать finalizer и эмитит событие `DeletionBlocked` с числом ссылающихся claim'ов.

Удалите сначала все ссылающиеся VaultClaim, потом VaultConfig — иначе VaultConfig зависнет в `Terminating`.

## Multi-Vault

Несколько VaultConfig разводят claim'ы по разным Vault-инстансам:

```yaml
---
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata: { name: primary }
spec: { address: "https://vault-primary.example:8200", ... }
---
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata: { name: dr }
spec: { address: "https://vault-dr.example:8200", ... }
---
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata: { name: ec8a00, namespace: dlputi1u }
spec:
  vaultConfigRef:
    name: primary                      # выбор инстанса
  ...
```

См. [user-guide/migration.md](../user-guide/migration.md) для переноса claim'а с одного VaultConfig на другой.

## Лучшие практики

1. **Один canonical VaultConfig `default`** — пока нет требований multi-Vault, не плодите имена.
2. **`address` пишите с `https://`** — `http://` допустим, но только для dev/e2e (CRD это разрешает специально).
3. **TLS: используйте CA-bundle через Secret** — приходит из `certificate-set`/Let's Encrypt; кладите в `tls.caBundleRef`, не в `--insecure-skip-tls-verify`.
4. **Мониторьте `Reachable=False`** — это единственное условие, которое говорит «оператор вообще не может говорить с Vault», в отличие от `Unsealed=False` (Vault жив, просто запечатан).

## Связанные документы

- [VaultClaim](vaultclaim.md) — ресурс, ссылающийся на VaultConfig
- [Pipeline](pipeline.md) — где VaultConfig используется в reconcile VaultClaim
- [Troubleshooting](../troubleshooting.md) — диагностика недоступности Vault
