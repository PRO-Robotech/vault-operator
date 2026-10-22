# Управление policies и roles

Практическое руководство по добавлению, изменению и удалению ACL-policy и role в существующем VaultClaim.

## Добавление policy

```yaml
spec:
  policies:
    - name: ec8a00-vmauth-reader
      rules: |
        path "secret/data/clusters/ec8a00/monitoring/vmauth/*" {
          capabilities = ["read", "list"]
        }
    - name: ec8a00-billing-writer            # ← новая
      rules: |
        path "secret/data/clusters/ec8a00/billing/*" {
          capabilities = ["create", "update", "read", "delete", "list"]
        }
```

```bash
kubectl apply -f vaultclaim.yaml
```

Оператор увидит изменение `generation`, пройдёт полный pipeline (drift detection отключён при смене spec), запишет новую политику через `PUT sys/policies/acl/ec8a00-billing-writer`.

Проверка:

```bash
kubectl get vaultclaim ec8a00 -n dlputi1u -o jsonpath='{.status.vault.appliedPolicies}'
# ["ec8a00-billing-writer","ec8a00-vmauth-reader"]
```

## Изменение policy

Просто измените `rules` и `kubectl apply`. Vault'овский `PUT sys/policies/acl/{name}` перезаписывает политику.

> Изменения вступают в силу для **новых** client_token'ов — уже выданные продолжают действовать в пределах своего TTL.

## Удаление policy

Уберите запись из `spec.policies[]` и `kubectl apply`.

Оператор удалит политику на следующем полном проходе — после того, как роли перестанут на неё ссылаться: удаляются только имена из журнала `status.vault.appliedPolicies`. Зарезервированные имена и имена другой заявки не удаляются никогда. Событие — `PoliciesPurged`.

## Добавление role

```yaml
spec:
  roles:
    - name: vmauth-reader
      boundServiceAccounts: { name: vmauth, namespace: monitoring }
      policies: [ec8a00-vmauth-reader]
      tokenTTL: 1h
    - name: billing-writer                    # ← новая
      boundServiceAccounts: { name: svc, namespace: billing }
      policies: [ec8a00-billing-writer]
      tokenTTL: 30m
      tokenMaxTTL: 4h
```

`kubectl apply` → роль появляется в `auth/kubernetes-ec8a00/role/billing-writer`.

## Изменение role

Любое поле — `boundServiceAccounts`, `policies`, `tokenTTL`, `tokenMaxTTL` — обновляется через `kubectl apply`. Vault `POST auth/{mount}/role/{name}` идемпотентен.

## Удаление role

Уберите запись из `spec.roles[]` и `kubectl apply`. Что удалится, задаёт `spec.auth.rolePruning`:

1. `Exclusive` (по умолчанию у владельца mount) — все роли из `LIST auth/{mount}/role/`, которых нет в spec, пока mount доказанно принадлежит заявке.
2. `Owned` (обязателен у гостя) — только роли из журнала `status.vault.appliedRoles`.
3. Зарезервированные роли и роли другой заявки не удаляются никогда.
4. Эмитится событие `RolesPurged` с числом удалённых.

Проверка:

```bash
kubectl get events -n dlputi1u --field-selector reason=RolesPurged
# LAST SEEN   TYPE     REASON         OBJECT                MESSAGE
# 10s         Normal   RolesPurged    vaultclaim/ec8a00     removed 1 roles in auth/kubernetes-ec8a00 no longer present in spec.roles[]
```

> `Exclusive` действует только на mount, который `sys/auth` показывает с описанием этой заявки. На чужом mount заявка ведёт себя как `Owned`. См. [concepts/ownership.md](../concepts/ownership.md).

## Identity templating

Если нужен один шаблон политики, работающий для N namespace'ов — см. [concepts/identity-templating.md](../concepts/identity-templating.md).

## Дрейф

Каждые 10 минут оператор сверяет состояние Vault со spec и эмитит `DriftDetected`, если что-то расходится. Это сигнал для алёрта, не для немедленного действия — на следующем reconcile оператор сам восстановит состояние (политика будет перезаписана, роль создана, лишняя удалена).

Если drift повторяется постоянно — значит, **кто-то снаружи меняет состояние Vault**. Возможные источники:

- Ручные `vault policy write` / `vault delete` от админа
- Конкурирующий процесс (другой оператор, скрипт)
- Restore Vault из backup'а

См. [monitoring.md](monitoring.md) §«Алёрты на drift».

## Best practices

1. **Один claim — много политик и ролей; не размножайте VaultClaim'ы по purpose.** Один VaultClaim на кластер.
2. **Префиксуйте политики**: `{cluster}-{role}` — `ec8a00-vmauth-reader`. Vault OSS политики глобальные.
3. **Не префиксуйте роли** — они scoped к auth-mount.
4. **Не давайте `*` в path** без необходимости — придерживайтесь `secret/data/clusters/{cluster}/{component}/*` (data-path для KV-v2 — это `data/`, не корень mount'а).
5. **`tokenMaxTTL` для долгоживущих сервисов** — без него renew может продлевать токен бесконечно.
6. **Не используйте root-policy** (`root`) — это есть только для emergency. Создавайте свои с минимальными capabilities.
