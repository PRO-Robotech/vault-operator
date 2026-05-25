# Базовый VaultClaim

Минимальная рабочая конфигурация: один VaultConfig и один VaultClaim, который выдаёт SA `monitoring/vmauth` в infra-кластере `ec8a00` доступ на чтение секретов под `secret/data/clusters/ec8a00/monitoring/vmauth/*`.

## Состав

| Файл | Что |
|---|---|
| [vaultconfig.yaml](vaultconfig.yaml) | Подключение к Vault (cluster-scoped, один на платформу) |
| [vaultclaim.yaml](vaultclaim.yaml) | Per-cluster конфигурация: auth-mount + policy + role |

## Предусловия

- Vault Operator установлен (см. [user-guide/installation.md](../../user-guide/installation.md)).
- В Vault есть auth-mount `kubernetes-mgmt` с ролью `vault-operator`, привязанной к SA оператора.
- В Vault есть общий KV-v2 mount `secret/`.
- В namespace `dlputi1u` есть Secret `ec8a00-infra-kubeconfig` с ключом `value` (обычно публикуется `cluster-claim-operator`).

## Применение

```bash
kubectl apply -f docs/examples/basic-vaultclaim/vaultconfig.yaml
kubectl wait vaultconfig/default --for=condition=Reachable=True --timeout=2m

kubectl apply -f docs/examples/basic-vaultclaim/vaultclaim.yaml
kubectl wait vaultclaim/ec8a00 -n dlputi1u --for=condition=Ready=True --timeout=2m
```

## Проверка

```bash
kubectl get vaultclaim -n dlputi1u ec8a00 -o wide
# NAME     PHASE   CONFIG    CLUSTER   AGE
# ec8a00   Ready   default   ec8a00    30s

kubectl get vaultclaim -n dlputi1u ec8a00 \
  -o jsonpath='Applied policies: {.status.vault.appliedPolicies}{"\n"}Applied roles: {.status.vault.appliedRoles}{"\n"}'
# Applied policies: ["ec8a00-vmauth-reader"]
# Applied roles: ["vmauth-reader"]
```

## Тест из infra-кластера

```bash
# Перейдите в infra-кластер (контекст ec8a00)
kubectl run -i --rm test-vault \
  --image=alpine/curl --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"vmauth"}}' \
  -n monitoring -- sh -c '
    JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    curl -sS -X POST \
      -d "{\"role\":\"vmauth-reader\",\"jwt\":\"$JWT\"}" \
      https://vault.beget.com:8200/v1/auth/kubernetes-ec8a00/login
  '
# Ожидаем JSON с auth.client_token
```

## Чистка

```bash
kubectl delete vaultclaim ec8a00 -n dlputi1u
# Reverse pipeline:
#   1. Удалит role vmauth-reader
#   2. Удалит policy ec8a00-vmauth-reader
#   3. Disable auth/kubernetes-ec8a00
#   4. Удалит SA + CRB в infra-кластере
#   5. Снимет finalizer

kubectl delete vaultconfig default     # только если referencedBy=0
```
