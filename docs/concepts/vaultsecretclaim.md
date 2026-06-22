# VaultSecretClaim

## Обзор

- Namespaced-ресурс: список секретов одного кластера, которые нужно наполнить **значениями** в Vault.
- 1:1 с кластером (`metadata.name` = имя кластера).
- Два режима на элемент: `generate` (сгенерировать пароль) и `copy` (скопировать общий секрет в per-cluster путь).
- Обслуживается **отдельным** контроллером `vault-secret-operator` (свой Deployment + ServiceAccount + Vault-роль с write-правом), а не `vault-operator`.

## Зачем отдельный контроллер

`vault-operator` (`VaultClaim`) настраивает **доступ** (auth method, policies, roles) и намеренно НЕ имеет права писать в `secret/data/*`. `vault-secret-operator` (`VaultSecretClaim`) наполняет те же пути **значениями** и имеет write-право. Граница привилегий физическая: разные pod SA ↔ разные Vault-роли.

| | vault-operator | vault-secret-operator |
|---|---|---|
| CRD | VaultClaim, VaultConfig | VaultSecretClaim, VaultConfig (scoped) |
| VaultConfig | `default` (role `vault-operator`) | `vault-secret` (role `vault-secret-operator`) |
| Право в Vault | НЕТ write в `secret/data` | write `secret/data/clusters/*` |
| kubeconfig target | нужен | не нужен (работает только с Vault) |

## Owner-scoping VaultConfig

Оба процесса реконсилят CRD `VaultConfig`, но **каждый — только свои объекты** (по label `vault.in-cloud.io/owner`): `vault-secret-operator` берёт только `owner=vault-secret`, `vault-operator` — label-less + `owner=vault-operator`. Поэтому VaultConfig `vault-secret` с write-ролью реконсилит исключительно секрет-процесс.

## Структура spec

```yaml
spec:
  vaultConfigRef: { name: vault-secret }    # VaultConfig с write-ролью
  clusterRef:     { name: ec8a00 }           # immutable
  secretsPrefix: clusters/ec8a00             # immutable; == VaultClaim.secretsPrefix
  deletionPolicy: Retain                     # Retain (дефолт) | Purge
  secretList:
    - name: argocd-admin
      type: generate
      destination: { path: argocd, key: admin.password, hashedKey: admin.passwordBcrypt }
      generate:    { length: 16, charset: "a-zA-Z0-9", hash: bcrypt }
    - name: grafana-oidc
      type: copy
      source:      { path: system/dex, key: staticClient }
      destination: { path: grafana, key: staticClient }
```

## Режимы

### generate — create-once

- Генерирует строку через `crypto/rand` по `length`/`charset`, опц. хеширует (`none`/`bcrypt`).
- **Перегенерирует только** если ключа нет в Vault ИЛИ сменились критерии (`length`/`charset`/`hash`). Иначе значение неизменно — его уже прочитали consumer'ы, и перегенерация на каждом reconcile сломала бы логины.
- При `hash != none` пишет два ключа: `key` (raw) + `hashedKey` (хеш). `bcrypt` даёт префикс `$2a$…` — формат, который ждёт Argo CD.
- `charset` — алфавит с range-сокращением `X-Y` (например, `a-zA-Z0-9`); дефолт `[A-Za-z0-9]`.

### copy

- Читает `source.path#source.key` в Vault → пишет в `destination`.
- **Перекопирует только** при смене значения источника (детект по `hash(path+key+value)` в `status.items[].sourceHash`).
- KV-v2 запись — full-replace, поэтому соседние ключи в `destination` сохраняются (read-modify-write merge).

## Immutable поля

| Поле | Почему immutable |
|---|---|
| `spec.clusterRef.name` | Привязка к кластеру; смена = другой кластер |
| `spec.secretsPrefix` | Встроен в consumer-policies, которые пишет `VaultClaim`; смена сделает данные недостижимыми по этим policies |

Изменение валидируется через CEL — `kubectl apply` отклонит.

## Что попадает в status

| Поле | Описание |
|---|---|
| `phase` | `Pending`, `Ready`, `Failed`, `Deleting` |
| `observedGeneration` | Последнее обработанное `metadata.generation` |
| `conditions[]` | `ConfigResolved`, `VaultReachable`, `SourcesResolved`, `ItemsApplied`, `Ready` |
| `items[].name` | Идентификатор элемента из `secretList` |
| `items[].state` | `Applied`, `Pending`, `Failed` |
| `items[].sourceHash` | Хеш входа (copy: `path+key+value`; generate: критерии) — детект изменений |
| `items[].lastAppliedAt` | Время последней записи в Vault |
| `items[].message` | Текст ошибки при `Failed` |

> Сами **значения** секретов в `status` не попадают — только `sourceHash`. Сгенерированные пароли существуют только в Vault.

## Поведение и границы

- Reconcile **событийный** (watch на `VaultSecretClaim` + свой `VaultConfig`), без периодического поллинга — на больших масштабах это экономит сеть/CPU.
- Секрет, удалённый в Vault **извне**, контроллер не отслеживает и не восстанавливает — by design.
- Удаление item из `secretList` **не** удаляет его значение из Vault (cleanup только при удалении CR + `Purge`).

## Удаление

- Finalizer `vault.in-cloud.io/vaultsecretclaim-finalizer`.
- `Retain` (дефолт) — значения остаются в Vault; пересоздание CR восстановит состояние.
- `Purge` — удаляет записанные ключи (нужен `delete` в policy). Если Vault недоступен — событие `DeletionStuck`, requeue.

## Связь с `VaultClaim`

`VaultClaim` (через `vault-operator`) выдаёт consumer'ам read-доступ на `secret/data/clusters/{cluster}/{app}/*`, `VaultSecretClaim` пишет значения в те же пути. Поэтому `secretsPrefix` у обоих CR совпадает. Запускаются параллельно, строгой очерёдности нет.

## Связанные документы

- [VaultConfig](vaultconfig.md) — подключение к Vault
- [Развёртывание vault-secret-operator](../user-guide/deploying-vault-secret-operator.md)
- [API Reference](../reference/api.md) — все поля CRD
- [Troubleshooting](../troubleshooting.md) — диагностика по conditions
