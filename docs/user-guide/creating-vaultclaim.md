# Создание VaultClaim

Пошаговое руководство по созданию VaultClaim для нового infra-кластера.

## Предусловия

- VaultConfig (обычно `default`) уже существует и `Reachable=True`. См. [installation.md](installation.md).
- ClusterClaim для этого кластера уже дошёл до `Phase=Ready` — это значит, что есть kubeconfig-секрет в namespace ClusterClaim'а.
- В Vault есть общий KV-v2 mount (по умолчанию `secret/`) — оператор это проверит через `SharedMountFound`.

## Минимальный пример

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata:
  name: ec8a00                                # обычно = ClusterClaim.metadata.name
  namespace: dlputi1u                         # namespace ClusterClaim
spec:
  vaultConfigRef:
    name: default

  clusterRef:
    name: ec8a00
    # kubeconfigSecret опущен → подставится "ec8a00-infra-kubeconfig"

  secretsPrefix: clusters/ec8a00              # immutable

  auth:
    mountPath: kubernetes-ec8a00              # immutable
    autoCreate: true
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer
        autoCreate: true
      ttl: 24h

  # policies и roles можно добавить сразу или позже — VaultClaim
  # станет Ready и без них.
```

## Конвенции именования

| Объект | Конвенция | Пример |
|---|---|---|
| `metadata.name` | Совпадает с `ClusterClaim.metadata.name` | `ec8a00` |
| `metadata.namespace` | Совпадает с namespace ClusterClaim'а | `dlputi1u` |
| `spec.secretsPrefix` | `clusters/{metadata.name}` | `clusters/ec8a00` |
| `spec.auth.mountPath` | `kubernetes-{metadata.name}` | `kubernetes-ec8a00` |
| `spec.policies[].name` | `{metadata.name}-{purpose}` | `ec8a00-vmauth-reader` |
| `spec.roles[].name` | `{purpose}` (без префикса — scoped к auth-mount) | `vmauth-reader` |

Имена policy **обязательно** префиксуйте — Vault OSS политики в плоском глобальном пространстве имён, без префикса будут конфликты между разными VaultClaim'ами.

Имена ролей префиксовать **не нужно** — они находятся под `auth/{mountPath}/role/`, который уже namespace'нут.

## Добавление policies и roles

См. отдельное руководство — [managing-policies-and-roles.md](managing-policies-and-roles.md).

## Проверка

```bash
kubectl get vaultclaim ec8a00 -n dlputi1u
# NAME     PHASE   CONFIG    CLUSTER   AGE
# ec8a00   Ready   default   ec8a00    1m

kubectl describe vaultclaim ec8a00 -n dlputi1u
```

В `describe` ищите блок `Conditions:` — все 8 должны быть `True`:

```
Conditions:
  Type:                   Status   Reason
  ConfigResolved          True     Resolved
  VaultReachable          True     LoggedIn
  KubeconfigAvailable     True     Available
  TokenReviewerJWTFresh   True     Rotated
  AuthMountReady          True     Configured
  PoliciesApplied         True     Applied
  RolesApplied            True     Applied
  Ready                   True     Ready
```

## Что делать, если claim не `Ready`

Каждое `False`-условие имеет `Reason` и `Message`, объясняющий причину. Краткий путь:

```bash
# Получить все False-условия с reason+message
kubectl get vaultclaim ec8a00 -n dlputi1u \
  -o jsonpath='{range .status.conditions[?(@.status=="False")]}{.type}: {.reason} — {.message}{"\n"}{end}'
```

Типовые причины и решения — [troubleshooting.md](../troubleshooting.md).

## Изменение spec

VaultClaim допускает большинство изменений «в живую». Каскад reconcile срабатывает на смене `metadata.generation`.

**Запрещено (CEL-валидация):**

- `spec.clusterRef.name` — смена = другой кластер.
- `spec.secretsPrefix` — инвалидирует все политики.
- `spec.auth.mountPath` — старый mount остался бы висеть в Vault.

**Разрешено и идемпотентно:**

- Добавлять, удалять, изменять `policies` и `roles` (см. [managing-policies-and-roles.md](managing-policies-and-roles.md))
- Менять `spec.vaultConfigRef.name` (миграция — см. [migration.md](migration.md))
- Менять `spec.auth.tokenReviewer.ttl`, `spec.auth.issuer`
- Менять `spec.auth.tokenReviewer.serviceAccount.autoCreate` (на `false` оператор перестанет создавать/удалять SA в infra-кластере)

## Удаление

```bash
kubectl delete vaultclaim ec8a00 -n dlputi1u
```

Что произойдёт:

1. Установится `deletionTimestamp`, `Phase=Deleting`.
2. Reverse pipeline удалит роли → политики → auth-mount в Vault.
3. Best-effort удалит SA + ClusterRoleBinding в infra-кластере.
4. Finalizer снимется, ресурс исчезнет из etcd.

Если Vault недоступен → ресурс зависнет в `Terminating` с событием `DeletionStuck` каждые ~1 min. Когда Vault вернётся — оператор завершит cleanup автоматически.

**Никогда не снимайте finalizer руками** (`kubectl edit ...`/`kubectl patch ...`), пока не убедились, что Vault-объекты действительно удалены — иначе они останутся висеть в Vault и могут конфликтовать со следующим claim'ом с тем же `mountPath`.
