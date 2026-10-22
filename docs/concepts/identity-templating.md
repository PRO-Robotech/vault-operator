# Identity Templating

Vault ACL-политика может ссылаться на атрибуты сущности, которая вошла в Vault. Kubernetes auth method на каждом входе пишет в метаданные alias имя и namespace ServiceAccount. Политика с путём по ним даёт каждому SA свой путь — одна политика вместо политики на каждую пару `(SA, namespace)`.

Vault подставляет атрибут по шаблону `{{identity.entity.aliases.<accessor>.metadata.<ключ>}}`, где `<accessor>` — accessor auth-mount, через который был вход. Accessor знает только Vault, поэтому его подставляет оператор.

## Три формы записи

### 1. `identityPaths` — основная

```yaml
policies:
  - name: ec8a00-apps
    identityPaths:
      - path: secret/data/clusters/ec8a00/{serviceAccountNamespace}/{serviceAccountName}
        capabilities: [read]
```

Плейсхолдеры в одинарных фигурных скобках: `{serviceAccountName}`, `{serviceAccountNamespace}`. Их не трогают ни Go-шаблон оператора, ни шаблоны, которыми рендерят заявки. Оператор дописывает к `rules` (если они есть) по строфе на каждый путь:

```hcl
path "secret/data/clusters/ec8a00/{{identity.entity.aliases.auth_kubernetes_1a2b3c4d.metadata.service_account_namespace}}/{{identity.entity.aliases.auth_kubernetes_1a2b3c4d.metadata.service_account_name}}" {
  capabilities = ["read"]
}
```

Что принимает схема:
- путь — сегменты из `[a-z0-9._-]` и плейсхолдеров, хотя бы один плейсхолдер;
- нет ведущего `/`, нет `*` и `+`, нет сегментов из одних точек (`.`, `..`);
- `{meta.<ключ>}` зарезервирован и сейчас отвергается;
- `capabilities` — `create`, `read`, `update`, `patch`, `delete`, `list`; `sudo` и `deny` недоступны.

Оператор при рендере проверяет путь тем же выражением, что и схема (`IdentityPathPattern`).

### 2. Функции шаблона в `rules`

```yaml
rules: |
  path "secret/data/clusters/ec8a00/shared/{{ vaultSANamespace }}" {
    capabilities = ["read"]
  }
```

`{{ vaultSAName }}` и `{{ vaultSANamespace }}` выводят тот же шаблон Vault, что и плейсхолдеры.

### 3. Экранированный шаблон Vault (прежняя форма)

```yaml
rules: |
  path "secret/data/clusters/ec8a00/{{`{{`}}identity.entity.aliases.{{ .AuthMountAccessor }}.metadata.service_account_namespace{{`}}`}}/*" {
    capabilities = ["read", "list"]
  }
```

`rules` проходят через Go `text/template` оператора: `{{ .AuthMountAccessor }}` — accessor, а `{{`{{`}}` и `{{`}}`}}` выводят фигурные скобки Vault. Заявки в этой форме рендерятся байт в байт как раньше.

Шаблон Vault без экранирования (`{{identity...}}` прямо в `rules`) отвергается: `PoliciesApplied=False reason=RenderFailed`, в сообщении названы формы, которыми его заменить.

## Как это работает в операторе

1. Accessor нужен, если у политики есть `identityPaths` или если дерево разбора `rules` ссылается на данные шаблона (`.AuthMountAccessor`) либо на функции `vaultSA*`. Решение принимается по дереву разбора, а не по поиску подстроки: слово в комментарии HCL accessor не требует.
2. Accessor читается из `GET sys/auth` один раз за полный проход и записывается в `status.vault.authMountAccessor`.
3. Accessor в `sys/auth`, отличный от записанного, означает, что mount пересоздан: тела в Vault ссылаются на старый accessor и ничего не дают. Проверка дрейфа сообщает `auth mount accessor changed`, полный проход перерендеривает политики и пишет событие `AuthMountAccessorChanged`. Пустой `status.vault.authMountAccessor` сменой не считается — его заполнит следующий полный проход.
4. Дрейф шаблонной политики сравнивает тело в Vault с телом, отрендеренным с записанным accessor. Ручная правка такой политики видна так же, как правка обычной.
5. Конфиг auth-mount оператор пишет с `use_annotations_as_alias_metadata=false`: метаданные alias, которые читают шаблоны, нельзя дописать аннотацией ServiceAccount.

## Роль на несколько SA

Шаблонной политике нужна роль, через которую входят все SA, — `boundServiceAccounts.names[]`:

```yaml
roles:
  - name: apps
    boundServiceAccounts:
      names: [loki, vmauth]
      namespace: monitoring
    aliasNameSource: serviceaccount_name
    policies: [ec8a00-apps]
```

- `names` и `name` взаимоисключающие. До 32 имён, DNS-1123, без глобов. Порядок не важен: оператор пишет имена отсортированными, а дрейф сравнивает множества.
- Namespace у роли один. Несколько namespace — несколько ролей.
- Кто именно вошёл, видно в метаданных токена (`service_account_name`, `service_account_namespace`) и в audit log.
- `aliasNameSource: serviceaccount_name` называет alias `<namespace>/<name>`. SA, пересозданный с тем же именем в том же namespace, получает ту же сущность Vault: принципал тот же. Пусто — поле в Vault не отправляется.
- `*`, `?`, `[` в `name` и `namespace` новой заявки отвергаются схемой. Сохранённое значение не перепроверяется, пока его не меняют (CRD validation ratcheting): старые заявки с `*` обновляются по другим полям.

## Доступные атрибуты alias

| Атрибут | Описание |
|---|---|
| `service_account_namespace` | Namespace pod'а |
| `service_account_name` | Имя SA |
| `service_account_uid` | UID SA |
| `service_account_secret_name` | Имя legacy SA-секрета (если есть) |

## Когда НЕ использовать

- Разные capabilities для разных SA: шаблон даёт всем одни и те же capabilities.
- Доступ к путям другого SA или namespace: шаблон привязывает путь к тому, кто вошёл.

## Связанные документы

- [Auth & Policies](auth-and-policies.md)
- [Пример](../examples/identity-templating/README.md)
- [Vault docs: Templated Policies](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies)
