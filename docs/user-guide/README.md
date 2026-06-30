# Руководство пользователя

| Документ | Описание |
|----------|----------|
| [Установка](installation.md) | Развёртывание оператора в management-кластере + подготовка Vault |
| [Развёртывание vault-secret-operator](deploying-vault-secret-operator.md) | Отдельный контроллер VaultSecretClaim: bootstrap Vault + overlay |
| [Создание VaultClaim](creating-vaultclaim.md) | Описание клиент-кластера и его доступа к Vault |
| [Управление policies и roles](managing-policies-and-roles.md) | Добавление, изменение, удаление, soft-purge |
| [Наблюдаемость](monitoring.md) | Conditions, события, Prometheus-метрики, рекомендуемые алёрты |
| [Миграция между Vault](migration.md) | Перенос VaultClaim на другой VaultConfig (multi-Vault) |
