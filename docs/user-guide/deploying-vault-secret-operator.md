# Развёртывание vault-secret-operator

`vault-secret-operator` — **отдельный** процесс из того же образа, что и `vault-operator`, но со своим Deployment, ServiceAccount и Vault-ролью с **write-правом** в `secret/data/clusters/*`. Реконсилит `VaultSecretClaim` (наполнение Vault значениями) и свой `VaultConfig` (`vault-secret`).

> Предполагается, что `vault-operator` и общий KV-mount `secret/` уже развёрнуты — см. [installation.md](installation.md).

## 1. Bootstrap в Vault (платформа, разово)

Контроллер сам себе policy/role в Vault **не создаёт** — это делает платформа.

### 1.1. Policy с write-правом

```bash
vault policy write vault-secret-operator-admin - <<EOF
# health-probe: проверка существования общего KV-mount
path "sys/mounts"                   { capabilities = ["read", "list"] }

# запись сгенерированных/скопированных значений
path "secret/data/clusters/+/*"     { capabilities = ["create", "update", "read"] }
path "secret/metadata/clusters/+/*" { capabilities = ["read", "list"] }

# чтение источников для copy (ограничьте своим префиксом)
path "secret/data/system/*"         { capabilities = ["read"] }
path "secret/metadata/system/*"     { capabilities = ["read", "list"] }

# при deletionPolicy: Purge — раскомментируйте:
# path "secret/data/clusters/+/*"     { capabilities = ["delete"] }
# path "secret/metadata/clusters/+/*" { capabilities = ["delete"] }

path "auth/token/renew-self"        { capabilities = ["update"] }
path "auth/token/lookup-self"       { capabilities = ["read"] }
EOF
```

> У `vault-operator-admin` такого права (`write secret/data`) нет by design — это и есть граница привилегий между двумя операторами.

### 1.2. Role, привязанная к SA секрет-оператора

Auth-mount `kubernetes-mgmt` переиспользуется (тот же, что у `vault-operator`):

```bash
vault write auth/kubernetes-mgmt/role/vault-secret-operator \
  bound_service_account_names=vault-secret-operator-controller-manager \
  bound_service_account_namespaces=vault-secret-operator-system \
  token_policies=vault-secret-operator-admin \
  token_ttl=1h token_max_ttl=24h
```

### 1.3. Источники для copy

`copy`-элементы читают готовые секреты — их заводит платформа заранее, например:

```bash
vault kv put secret/system/dex  staticClient=@dex-client.json
vault kv put secret/system/etcd s3Creds=@etcd-s3.json
```

## 2. Развёртывание контроллера

CRD общие с `vault-operator` (`vaultsecretclaims.vault.in-cloud.io` входит в `config/default`/`make install`). Отдельно ставится только overlay контроллера:

```bash
kubectl apply -k config/secret-manager/
```

Overlay `config/secret-manager/` содержит:

- `Namespace vault-secret-operator-system`
- `ServiceAccount vault-secret-operator-controller-manager`
- **узкий** `ClusterRole` (только `vaultsecretclaims` + `vaultconfigs` + `secrets/configmaps` read + events; **без** доступа к VaultClaim и kubeconfig)
- `Deployment` с `command: [/vault-secret-manager]` (тот же образ, другой entrypoint)

> Образ задаётся через `images:` в `config/secret-manager/kustomization.yaml` (по умолчанию `controller:latest`) — переопределите на свой registry/tag.

Проверка:

```bash
kubectl get pods -n vault-secret-operator-system
# NAME                                                       READY   STATUS    AGE
# vault-secret-operator-controller-manager-XXXXXXXX-XXXXX    1/1     Running   30s

kubectl logs -n vault-secret-operator-system -l control-plane=vault-secret-operator --tail=50
```

### Флаги

| Флаг | Дефолт | Назначение |
|---|---|---|
| `--leader-elect` | (вкл. в overlay) | Один активный процесс |
| `--health-probe-bind-address` | `:8081` | `/healthz`, `/readyz` |
| `--metrics-bind-address` | `0` (выкл.) | Метрики (только общие `vault_api_*`; controller-метрик у секрет-оператора нет) |
| `--pprof-bind-address` | `127.0.0.1:8082` | pprof/диагностика, только через `kubectl port-forward` |

## 3. VaultConfig для секрет-оператора

Отдельный экземпляр `VaultConfig` с label владельца и write-ролью:

```bash
kubectl apply -f docs/examples/vaultsecretclaim/vaultconfig.yaml

kubectl get vaultconfig vault-secret
# NAME           ADDRESS                        UNSEALED   REACHABLE   REFS   AGE
# vault-secret   https://vault.beget.com:8200   True       True        0      10s
```

Ключевое — label `vault.in-cloud.io/owner: vault-secret`: без него VaultConfig подхватит `vault-operator`, а не секрет-процесс.

## 4. Проверка работоспособности

```bash
kubectl apply -f docs/examples/vaultsecretclaim/vaultsecretclaim.yaml
kubectl wait vaultsecretclaim/ec8a00 -n dlputi1u --for=condition=Ready=True --timeout=2m

kubectl get vaultsecretclaim -n dlputi1u ec8a00 \
  -o jsonpath='{range .status.items[*]}{.name}={.state}{"\n"}{end}'
# argocd-admin=Applied
# vmagent=Applied
# grafana-oidc=Applied
```

## Удаление

```bash
kubectl delete -k config/secret-manager/
```

> Перед удалением overlay'я учтите, что `VaultSecretClaim` с `deletionPolicy: Purge` и непочищенным finalizer'ом застрянет в `Deleting`, если контроллер уже снят — см. [troubleshooting.md → VaultSecretClaim](../troubleshooting.md#vaultsecretclaim).
