# Установка

Развёртывание Vault Operator в management-кластере + предварительная подготовка Vault.

## 1. Подготовка Vault

Оператор сам логинится в Vault через Kubernetes Auth Method — этот auth-mount должен существовать **до** запуска оператора.

### 1.1. Создать manager auth-mount

В Vault (под root token или эквивалентом):

```bash
vault auth enable -path=kubernetes-mgmt kubernetes

vault write auth/kubernetes-mgmt/config \
  kubernetes_host="https://<MANAGEMENT_APISERVER>:6443" \
  kubernetes_ca_cert="$(cat /path/to/management-cluster-ca.crt)"
```

### 1.2. Создать admin-policy для оператора

```bash
vault policy write vault-operator-admin - <<EOF
# Управление per-cluster auth-mount'ами
path "sys/auth"                  { capabilities = ["read", "list"] }
path "sys/auth/kubernetes-*"     { capabilities = ["create", "read", "update", "delete", "sudo"] }
path "auth/kubernetes-*/*"       { capabilities = ["create", "read", "update", "delete", "list"] }

# Управление ACL policies
path "sys/policies/acl"          { capabilities = ["list"] }
path "sys/policies/acl/*"        { capabilities = ["create", "read", "update", "delete"] }

# Чтение sys/mounts (для проверки наличия KV-mount + drift detection)
path "sys/mounts"                { capabilities = ["read", "list"] }

# Token-management (для renew-self)
path "auth/token/renew-self"     { capabilities = ["update"] }
path "auth/token/lookup-self"    { capabilities = ["read"] }
EOF
```

### 1.3. Создать role для SA оператора

```bash
vault write auth/kubernetes-mgmt/role/vault-operator \
  bound_service_account_names=vault-operator-controller-manager \
  bound_service_account_namespaces=vault-operator-system \
  token_policies=vault-operator-admin \
  token_ttl=1h \
  token_max_ttl=24h
```

## 2. Развёртывание оператора

### 2.1. Установка CRD

```bash
make install
# Создаёт:
#   - CustomResourceDefinition vaultclaims.vault.in-cloud.io
#   - CustomResourceDefinition vaultconfigs.vault.in-cloud.io
```

### 2.2. Деплой контроллера

```bash
make deploy IMG=registry.beget.com/vault-operator:v0.1.0
```

Это применит `config/default/kustomization.yaml`, который содержит:

- `Namespace vault-operator-system`
- `ServiceAccount vault-operator-controller-manager`
- `ClusterRole` / `ClusterRoleBinding` для VaultClaim/VaultConfig/Secret/Event
- `Deployment` контроллера (1 реплика по умолчанию)
- `Service` для метрик

Проверка:

```bash
kubectl get pods -n vault-operator-system
# NAME                                                READY   STATUS    AGE
# vault-operator-controller-manager-XXXXXXXX-XXXXX    1/1     Running   30s
```

Логи:

```bash
kubectl logs -n vault-operator-system -l control-plane=controller-manager --tail=50
```

## 3. VaultConfig

```bash
kubectl apply -f - <<EOF
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata:
  name: default
spec:
  address: https://vault.beget.com:8200
  managerAuth:
    method: kubernetes
    mountPath: kubernetes-mgmt
    role: vault-operator
  storage:
    kvMountPath: secret
EOF

kubectl get vaultconfig
# NAME      ADDRESS                          UNSEALED   REACHABLE   REFS   AGE
# default   https://vault.beget.com:8200     True       True        0      10s
```

Ожидаемые conditions:

```bash
kubectl get vaultconfig default -o jsonpath='{.status.conditions[*].type}{"\n"}'
# Reachable VaultInitialized VaultUnsealed ManagerLoggedIn SharedMountFound

kubectl get vaultconfig default -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}'
# Reachable=True
# VaultInitialized=True
# VaultUnsealed=True
# ManagerLoggedIn=True
# SharedMountFound=True
```

## 4. Проверка работоспособности

Создайте тестовый VaultClaim и убедитесь, что он переходит в `Phase=Ready`:

```bash
kubectl apply -f docs/examples/basic-vaultclaim/
kubectl get vaultclaim -A -w
```

## TLS к Vault через Secret

Если Vault использует не-публичный CA:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vault-ca
  namespace: vault-operator-system
type: Opaque
data:
  ca.crt: <base64 of PEM>
---
apiVersion: vault.in-cloud.io/v1alpha1
kind: VaultConfig
metadata: { name: default }
spec:
  address: https://vault.beget.com:8200
  tls:
    caBundleRef:
      namespace: vault-operator-system
      name: vault-ca
    serverName: vault.beget.com
  ...
```

## Аплифт версии

```bash
make deploy IMG=registry.beget.com/vault-operator:v0.2.0
```

CRD обновлять отдельно, если в новой версии есть schema-изменения:

```bash
make install
```

## Удаление

```bash
make undeploy        # снимает Deployment, SA, RBAC, namespace
make uninstall       # снимает CRD (предварительно удалите все VaultClaim/VaultConfig)
```

> ⚠ **Перед `make uninstall` удалите все VaultClaim'ы** — иначе finalizer-блокировка оставит их в `Terminating`. Аналогично для VaultConfig — он не удалится пока `referencedBy > 0`.
