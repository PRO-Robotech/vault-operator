# Identity Templating

Одна ACL-policy, работающая для всех namespace'ов кластера: pod в namespace X читает только секреты под `secret/data/clusters/{cluster}/X/*`. Подробное объяснение — [concepts/identity-templating.md](../../concepts/identity-templating.md).

## Состав

| Файл | Что |
|---|---|
| [vaultclaim.yaml](vaultclaim.yaml) | Один VaultClaim с шаблонизированной policy и N роли |

## Идея

```hcl
path "secret/data/clusters/ec8a00/{{ identity.entity.aliases.AUTH_MOUNT_ACCESSOR.metadata.service_account_namespace }}/*" {
  capabilities = ["read", "list"]
}
```

- `AUTH_MOUNT_ACCESSOR` — подставляется **оператором** из `GET sys/auth` (Go templating)
- `service_account_namespace` — подставляется **Vault'ом** на login'е (Vault templating)

В spec.policies[].rules оба уровня экранированы:

```yaml
rules: |
  path "secret/data/clusters/ec8a00/{{`{{`}} identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace {{`}}`}}/*" {
    capabilities = ["read", "list"]
  }
```

После рендера в Vault уходит:

```hcl
path "secret/data/clusters/ec8a00/{{ identity.entity.aliases.auth_kubernetes_xyz.metadata.service_account_namespace }}/*" {
  capabilities = ["read", "list"]
}
```

## Применение

```bash
kubectl apply -f docs/examples/identity-templating/vaultclaim.yaml
kubectl wait vaultclaim/ec8a00-shared -n dlputi1u --for=condition=Ready=True --timeout=2m

# Проверка что accessor лениво сохранён в status
kubectl get vaultclaim ec8a00-shared -n dlputi1u \
  -o jsonpath='{.status.vault.authMountAccessor}{"\n"}'
# auth_kubernetes_xyz12345
```

## Проверка из двух разных namespace'ов

```bash
# Pod в monitoring/vmauth — читает только secret/data/clusters/ec8a00/monitoring/*
kubectl run test-mon -n monitoring --restart=Never --rm -i --image=alpine/curl \
  --overrides='{"spec":{"serviceAccountName":"vmauth"}}' -- sh -c '
  JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  TOKEN=$(curl -sS -X POST -d "{\"role\":\"namespace-reader-monitoring\",\"jwt\":\"$JWT\"}" \
    https://vault.beget.com:8200/v1/auth/kubernetes-ec8a00/login | jq -r .auth.client_token)

  echo "--- own namespace (should work) ---"
  curl -sS -H "X-Vault-Token: $TOKEN" \
    https://vault.beget.com:8200/v1/secret/data/clusters/ec8a00/monitoring/foo

  echo "--- other namespace (should 403) ---"
  curl -sS -H "X-Vault-Token: $TOKEN" \
    https://vault.beget.com:8200/v1/secret/data/clusters/ec8a00/billing/foo
'
```

## Когда так делать стоит, а когда нет

**Стоит:**
- Много pod'ов в разных namespace'ах с одинаковым capabilities (например, read-only).
- Одинаковая структура путей под `secrets/clusters/{cluster}/{namespace}/...`.

**Не стоит:**
- Разные namespace'ы должны иметь разные capabilities (read у одних, write у других) — пишите явные политики на пару.
- Pod'ам нужен доступ к секретам в *других* namespace'ах — identity templating жёстко привязывает к namespace pod'а.

См. [concepts/identity-templating.md](../../concepts/identity-templating.md) §«Когда НЕ использовать».
