# Примеры

Рабочие конфигурации, которые можно применить через `kubectl apply -k examples/{name}/`.

| Пример | Описание |
|--------|----------|
| [basic-vaultclaim](basic-vaultclaim/) | Минимальная рабочая конфигурация: VaultConfig + один VaultClaim с одной policy и одной role |
| [identity-templating](identity-templating/) | Одна policy, одна role-шаблон → доступ N namespace'ов через `{{ .AuthMountAccessor }}` |

## Как использовать примеры

1. Установите оператор и подготовьте Vault — см. [user-guide/installation.md](../user-guide/installation.md).
2. Скопируйте YAML из примера и адаптируйте под свой кластер (имя claim'а, namespace, secretsPrefix).
3. Примените:

   ```bash
   kubectl apply -f docs/examples/basic-vaultclaim/vaultclaim.yaml
   ```

4. Проверьте, что claim перешёл в `Phase=Ready`:

   ```bash
   kubectl get vaultclaim -A
   ```

## См. также

- [Быстрый старт](../getting-started.md)
- [Создание VaultClaim](../user-guide/creating-vaultclaim.md)
- [Управление policies и roles](../user-guide/managing-policies-and-roles.md)
