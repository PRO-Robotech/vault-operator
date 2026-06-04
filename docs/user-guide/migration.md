# Миграция между Vault

Когда нужно перенести VaultClaim с одного Vault-инстанса на другой (multi-Vault setup) или переехать с тестового Vault на production.

## Сценарии

1. **Multi-Vault failover** — есть `primary` и `dr` VaultConfig; нужно переключить часть claim'ов с одного на другой.
2. **Тест → прод** — VaultClaim сначала жил на `staging` VaultConfig, теперь переводим на `production`.
3. **Замена адреса** — Vault переехал на новый эндпоинт; меняем `VaultConfig.spec.address` (не миграция в строгом смысле, но похожий процесс).

## Что меняется и что нет

| Изменение | Эффект |
|---|---|
| Сменить `VaultClaim.spec.vaultConfigRef.name` | Полная миграция: новый Vault получит конфигурацию, старый — нет автоматического cleanup |
| Сменить `VaultConfig.spec.address` | Cascade reconcile всех ссылающихся claim'ов — они начнут пользоваться новым адресом |

## Миграция claim'а на другой VaultConfig

### Подготовка нового Vault

В целевом Vault'е должно быть:

- Manager auth-mount (`kubernetes-mgmt` обычно), доступный для SA оператора
- Policy `vault-operator-admin` с правами на `sys/auth`, `sys/policies/acl`, `sys/mounts`, и т.д.
- Общий KV-mount по тому же пути (`secret` по умолчанию) — `spec.storage.kvMountPath` immutable

Подробнее — [installation.md](installation.md) §«Подготовка Vault».

### Шаги

1. **Создайте новый VaultConfig** (если ещё нет):

   ```yaml
   apiVersion: vault.in-cloud.io/v1alpha1
   kind: VaultConfig
   metadata: { name: production }
   spec:
     address: https://vault-prod.beget.com:8200
     managerAuth: { method: kubernetes, mountPath: kubernetes-mgmt, role: vault-operator }
     storage: { kvMountPath: secret }
   ```

   Дождитесь `Reachable=True`, `SharedMountFound=True`:

   ```bash
   kubectl wait vaultconfig/production --for=condition=Reachable=True --timeout=2m
   ```

2. **Скопируйте секреты в новый Vault** (вручную или через миграционный скрипт). Оператор управляет auth/policies/roles, но **не самими секретами под `secret/data/...`**.

3. **Измените `spec.vaultConfigRef.name` в VaultClaim'е**:

   ```bash
   kubectl patch vaultclaim ec8a00 -n dlputi1u --type=merge \
     -p '{"spec":{"vaultConfigRef":{"name":"production"}}}'
   ```

4. **Дождитесь reconcile на новом Vault**:

   ```bash
   kubectl get vaultclaim ec8a00 -n dlputi1u -w
   # NAME     PHASE         CONFIG       CLUSTER   AGE
   # ec8a00   Configuring   production   ec8a00    5m
   # ec8a00   Ready         production   ec8a00    5m1s
   ```

5. **Удалите auth-mount и policies в старом Vault** — оператор этого не делает автоматически:

   ```bash
   # На старом Vault
   vault auth disable kubernetes-ec8a00
   vault policy delete ec8a00-vmauth-reader
   vault policy delete ec8a00-billing-writer
   # ... и т.д. для всех policies этого claim'а
   ```

### Что произойдёт под капотом

После смены `spec.vaultConfigRef.name`:

- Шаг 1 pipeline'а резолвнет **новый** VaultConfig, проверит его `Reachable=True`/`SharedMountFound=True`, залогинится через `VaultFactory.For(new VaultConfig)` (новый кэшированный клиент).
- Шаг 5 идемпотентно создаст auth-mount `kubernetes-ec8a00` в новом Vault.
- Шаги 6-7 запишут все policies и roles из spec.
- В status `appliedPolicies` / `appliedRoles` обновятся; `configName` станет `production`.

**Старый Vault при этом**: его mount/policies/roles остаются — оператор о них больше не знает. Удалять надо руками.

### Pod'ы в infra-кластере

Pod'ы продолжат логиниться по тому же endpoint (`https://vault.beget.com` или какой у них настроен), но теперь это новый Vault — убедитесь, что **DNS/Service** в infra-кластере указывает на правильный Vault.

Если адрес меняется — обновите ConfigMap/Secret с `VAULT_ADDR` в pod'ах через `addons-operator` или ручной rolling restart.

## Миграция всех claim'ов одной командой

Если переезжает весь VaultConfig:

```bash
# 1. Поменять адрес у самого VaultConfig
kubectl patch vaultconfig default --type=merge \
  -p '{"spec":{"address":"https://vault-new.beget.com:8200"}}'

# 2. Cascade reconcile сработает автоматически — оператор сам пройдёт все claim'ы
kubectl get vaultclaim -A -w
```

В этом случае создавать новый VaultConfig не нужно — старый просто меняет адрес. Drift detection заметит, что новый Vault пуст, и оператор пересоздаст auth/policies/roles.

> ⚠ Это **разрушительная операция, если новый Vault не был подготовлен** — оператор не «копирует» состояние, он восстанавливает из spec. Если в старом Vault были вручную добавленные политики, не описанные в VaultClaim'е — они пропадут.

## Откат

Если миграция пошла не так — верните `spec.vaultConfigRef.name` или `VaultConfig.spec.address` назад. Оператор идемпотентно восстановит конфигурацию на старом Vault (если auth/policies/roles ещё не удалены).

## Связанные документы

- [VaultConfig](../concepts/vaultconfig.md) — multi-Vault setup
- [creating-vaultclaim.md](creating-vaultclaim.md) — что immutable, что нет
- [monitoring.md](monitoring.md) — как отследить миграцию
