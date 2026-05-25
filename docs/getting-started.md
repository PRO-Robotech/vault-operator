# Быстрый старт

Установка оператора и создание первого VaultClaim для infra-кластера.

## Предварительные требования

- Kubernetes-кластер 1.34+ (management-кластер платформы)
- HashiCorp Vault 1.17+, доступный по сети из management-кластера
- В Vault уже настроен **manager auth method** для логина самого оператора (см. [user-guide/installation.md](user-guide/installation.md) §«Подготовка Vault»)
- `kubectl` настроен на management-кластер
- Готовый `kubeconfig`-секрет на каждый infra-кластер (обычно публикуется `cluster-claim-operator`)

## 1. Установка оператора

```bash
make install                                            # CRD: VaultClaim + VaultConfig
make deploy IMG=registry.beget.com/vault-operator:v0.1.0
```

Проверка:

```bash
kubectl get pods -n vault-operator-system
# vault-operator-controller-manager-xxx   1/1   Running
```

## 2. VaultConfig — подключение к Vault

VaultConfig — cluster-scoped, один на платформу (или несколько для multi-Vault).

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata:
  name: default
spec:
  address: https://vault.beget.com:8200
  managerAuth:
    method: kubernetes
    mountPath: kubernetes-mgmt          # как Vault Operator сам логинится
    role: vault-operator                # роль, привязанная к SA оператора
  storage:
    kvMountPath: secret                 # общий KV-v2 mount
```

```bash
kubectl apply -f vaultconfig.yaml

kubectl get vaultconfig default -o wide
# NAME      ADDRESS                          UNSEALED   REACHABLE   REFS   AGE
# default   https://vault.beget.com:8200     True       True        0      10s
```

Если `REACHABLE=False` — см. [troubleshooting.md](troubleshooting.md) §«VaultConfig не Reachable».

## 3. VaultClaim — заявка на конфигурацию для кластера

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultClaim
metadata:
  name: ec8a00                          # обычно = ClusterClaim.metadata.name
  namespace: dlputi1u                   # namespace ClusterClaim
spec:
  vaultConfigRef:
    name: default
  clusterRef:
    name: ec8a00                        # ClusterClaim в этом же namespace
    # kubeconfigSecret подставится автоматически — "{name}-infra-kubeconfig"

  secretsPrefix: clusters/ec8a00        # immutable, путь под общим KV-mount

  auth:
    mountPath: kubernetes-ec8a00        # immutable
    autoCreate: true
    tokenReviewer:
      serviceAccount:
        namespace: beget-vault-system
        name: vault-token-reviewer
        autoCreate: true
      ttl: 24h

  policies:
    - name: ec8a00-vmauth-reader
      rules: |
        path "secret/data/clusters/ec8a00/monitoring/vmauth/*" {
          capabilities = ["read", "list"]
        }

  roles:
    - name: vmauth-reader
      boundServiceAccounts:
        name: vmauth
        namespace: monitoring
      policies: [ec8a00-vmauth-reader]
      tokenTTL: 1h
```

```bash
kubectl apply -f vaultclaim.yaml
```

## 4. Проверка

```bash
kubectl get vaultclaim -n dlputi1u
# NAME     PHASE   CONFIG    CLUSTER   AGE
# ec8a00   Ready   default   ec8a00    30s

kubectl describe vaultclaim ec8a00 -n dlputi1u
```

Что должно быть в статусе:

- `phase: Ready`
- Все 8 conditions со `status: True`:
  `ConfigResolved`, `VaultReachable`, `KubeconfigAvailable`, `TokenReviewerJWTFresh`,
  `AuthMountReady`, `PoliciesApplied`, `RolesApplied`, `Ready`
- `status.vault.appliedPolicies` и `status.vault.appliedRoles` содержат ваши имена
- `status.vault.tokenReviewerJWT.expiresAt` в будущем

Проверка со стороны Vault (для отладки):

```bash
vault read sys/auth | grep kubernetes-ec8a00
vault policy read ec8a00-vmauth-reader
vault read auth/kubernetes-ec8a00/role/vmauth-reader
```

## 5. Использование из pod'а

Pod в infra-кластере под SA `monitoring/vmauth` теперь может логиниться:

```bash
# Внутри pod'а
JWT=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sS -X POST \
  -d "{\"role\":\"vmauth-reader\",\"jwt\":\"$JWT\"}" \
  https://vault.beget.com:8200/v1/auth/kubernetes-ec8a00/login
# → { "auth": { "client_token": "hvs.XXXXX", ... } }
```

## Дальнейшее чтение

- [Концепции](concepts/vaultclaim.md) — VaultClaim, VaultConfig, pipeline
- [Управление policies и roles](user-guide/managing-policies-and-roles.md)
- [Наблюдаемость](user-guide/monitoring.md) — что мониторить и алертить
- [API Reference](reference/api.md) — все поля CRD
