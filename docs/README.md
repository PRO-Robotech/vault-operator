# Документация Vault Operator

## Содержание

### Начало работы

| Документ | Описание |
|----------|----------|
| [Быстрый старт](getting-started.md) | Установка оператора и создание первого VaultClaim |

### Концепции

| Документ | Описание |
|----------|----------|
| [VaultClaim](concepts/vaultclaim.md) | Per-cluster ресурс — auth-mount + policies + roles |
| [VaultConfig](concepts/vaultconfig.md) | Cluster-scoped подключение к Vault, health-проба |
| [Pipeline](concepts/pipeline.md) | 7-шаговый цикл reconcile + drift detection |
| [Auth & Policies](concepts/auth-and-policies.md) | Kubernetes Auth Method, ACL-policies, role bindings |
| [Identity templating](concepts/identity-templating.md) | `{{ .AuthMountAccessor }}` для namespace-scoped доступа |

### Руководство пользователя

| Документ | Описание |
|----------|----------|
| [Установка](user-guide/installation.md) | Развёртывание оператора в management-кластере |
| [Создание VaultClaim](user-guide/creating-vaultclaim.md) | Как описать клиент-кластер и его доступ |
| [Управление policies и roles](user-guide/managing-policies-and-roles.md) | Добавление, изменение, удаление |
| [Наблюдаемость](user-guide/monitoring.md) | Conditions, события, Prometheus-метрики |
| [Миграция между Vault](user-guide/migration.md) | Перенос VaultClaim на другой VaultConfig |

### Справочник

| Документ | Описание |
|----------|----------|
| [API Reference](reference/api.md) | Полное описание полей VaultClaim и VaultConfig |

### Примеры

| Документ | Описание |
|----------|----------|
| [Обзор примеров](examples/README.md) | Список доступных примеров |
| [Базовый VaultClaim](examples/basic-vaultclaim/README.md) | Минимальная рабочая конфигурация |
| [Identity templating](examples/identity-templating/README.md) | Namespace-ограниченный доступ через accessor |

### Диагностика

| Документ | Описание |
|----------|----------|
| [Troubleshooting](troubleshooting.md) | Типовые проблемы и решения |
