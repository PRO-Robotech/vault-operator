# Vault Operator

Kubernetes-оператор для декларативной настройки HashiCorp Vault под каждый infra-кластер платформы Beget. По одному ресурсу `VaultClaim` оператор создаёт в Vault: per-cluster Kubernetes Auth Method, ACL-policies, роли и token-reviewer ServiceAccount в целевом кластере.

## Что это?

Vault Operator превращает заявку «нужен Vault-доступ для кластера X» в готовую к использованию конфигурацию: auth-mount `auth/kubernetes-X/`, набор политик с правильными path-ограничениями, роли с binding'ом `SA + namespace → policy`, и SA в infra-кластере для TokenReview. Pod'ы в infra-кластере дальше сами логинятся в Vault по SA-JWT — оператор в этом потоке не участвует.

## Ключевые возможности

- **Один ресурс на кластер** — `VaultClaim` 1:1 с `ClusterClaim`. Кластер появился — добавили claim, кластер удалили — удалили claim, оператор сам всё подчищает в Vault.
- **Multi-Vault** — несколько именованных `VaultConfig` позволяют развести VaultClaim'ы по разным Vault-инстансам.
- **Drift detection** — раз в 10 минут оператор сверяет состояние Vault со spec; расхождения попадают в условия, события и метрики.
- **Безопасная ротация JWT** — token-reviewer JWT обновляется проактивно при остатке <30% TTL; байты JWT никогда не попадают в `status`.
- **Sealed Vault aware** — оператор различает sealed/uninitialized Vault и сетевую недоступность, не уходит в шторм 503-ошибок.
- **Circuit breaker** — 5 подряд неудач → 2 минуты open + half-open probe, защищает Vault от лавины retry.

## Архитектура

```
┌──────────────┐       ┌──────────────────┐       ┌─────────────────────┐
│ VaultClaim   │──────▶│ VaultClaim       │──────▶│ HashiCorp Vault     │
│ (CRD)        │       │ Reconciler       │       │  /auth/kubernetes-X/│
└──────────────┘       │ (7-step pipeline)│       │  /sys/policies/acl/ │
       │               └──────────────────┘       └─────────────────────┘
       │ ссылается              │
       ▼                        ▼
┌──────────────┐       ┌──────────────────┐       ┌─────────────────────┐
│ VaultConfig  │       │ ClusterManager   │──────▶│ Infra cluster       │
│ (CRD,        │       │ (kubeconfig      │       │  SA vault-token-    │
│  cluster-    │       │  cache)          │       │   reviewer + CRB    │
│  scoped)     │       └──────────────────┘       └─────────────────────┘
└──────────────┘
       │
       ▼
┌──────────────┐
│ VaultConfig  │ ── seal-status / login probe / shared mount check
│ Reconciler   │
└──────────────┘
```

## Быстрый старт

```bash
# 1. Установить CRD и оператор
make install
make deploy IMG=registry.beget.com/vault-operator:v0.1.0

# 2. Описать подключение к Vault
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

# 3. Создать VaultClaim для конкретного infra-кластера
kubectl apply -f docs/examples/basic-vaultclaim/vaultclaim.yaml
```

Подробнее — [docs/getting-started.md](docs/getting-started.md).

## Документация

- [docs/README.md](docs/README.md) — индекс
- [docs/getting-started.md](docs/getting-started.md) — установка и первый VaultClaim
- [docs/concepts/](docs/concepts/) — VaultClaim, VaultConfig, pipeline, auth & policies
- [docs/reference/api.md](docs/reference/api.md) — полный справочник полей CRD
- [docs/user-guide/](docs/user-guide/) — установка, наблюдаемость, миграция, управление policies/roles
- [docs/examples/](docs/examples/) — рабочие YAML-примеры
- [docs/troubleshooting.md](docs/troubleshooting.md) — типовые проблемы и решения

## Совместимость

| Компонент | Версия |
|---|---|
| Kubernetes | 1.34+ |
| HashiCorp Vault | OSS 1.17+ |
| ClusterClaim Operator | любая (используется только kubeconfig-секрет) |
| Go | 1.24+ |

## Связь с другими операторами Beget

| Оператор | Связь |
|---|---|
| `cluster-claim-operator` | Источник `kubeconfig`-секрета через `VaultClaim.spec.clusterRef`. VaultClaim создаётся ПОСЛЕ `ClusterClaim` Phase=Ready. |
| `certificate-set` | Опосредовано — kubeconfig-секрет приходит из его pipeline. |
| `addons-operator` | Аддоны в infra-кластере (vmauth, ArgoCD) — потребители Vault через выпущенный auth-mount. |

## Лицензия

Apache License 2.0. Заголовки в `*.go` файлах содержат полный текст копирайта.
