# cmfake — двойник cloud-manager для стенда

`cmfake` — самостоятельная служба стенда kind, у которой s3-bucket-operator
заказывает бакеты вместо настоящего cloud-manager. Продовой посадки у неё
нет: это компонент стенда.

Код — `internal/cloudmanager/cmfake` (`Store`, `Service`, `Run`), бинарь —
`cmd/cmfake`, образ — `Dockerfile.cmfake`, собирается заданием
`docker-build.yml` как `<namespace>/cmfake:<ветка>-<sha8>`.

## Контракт

Тот же gRPC, что у клиента оператора (`internal/cloudmanager/proto`):
`CloudService.create` с `s3_params`, `CloudS3Service.findAll`,
`CloudS3Service.removeBucket`. Плюс `grpc.health.v1.Health` — по нему стенд
судит готовность. Слушатель без TLS, как и клиент оператора; порт наружу
кластера стенда не публикуется.

Семантика повторяет настоящую службу:

| вызов | поведение |
|---|---|
| `create` | имя — `lower(<префикс логина>-<запрошенное>)`; занятое (в любом статусе) — суффикс `-N`; бакет заводится в S3-хранилище стенда ключами арендатора, ответ — `service_info.slug` |
| `create`, неизвестный логин | ошибка gRPC `INTERNAL` «customer not found» — клиент ищется до перехвата ошибок S3, `s3_error` не приходит |
| `create`, не S3 | ошибка gRPC `UNIMPLEMENTED` «Unknown params for create» |
| `create`, отказы | `s3_error`: `CONFIGURATION_NOT_FOUND` (нет пары id+регион), `INVALID_BUCKET_NAME` (латиница, цифры, `-` не в начале, не в конце и не дважды подряд; полное имя ≤ 63), `BUCKET_LIMIT_REACHED` (живых, не `REMOVED`, бакетов логина ≥ `maxBuckets`), `CODE_RESERVED` (сбой хранилища; строка не остаётся) |
| `findAll` | области через И, значения внутри области через ИЛИ; без области — всё; `REMOVED` возвращается |
| `removeBucket` | `Not found` — не было; `Already removed` — `REMOVED`; иначе `REMOVING`, снятие объектов и бакета в хранилище асинхронно, затем `REMOVED`; исчерпав `removal.attempts` — `ERROR` |

`INSUFFICIENT_FUNDS` двойник не производит: биллинга у него нет.

Состояние — в памяти процесса: перезапуск его теряет, бакеты в хранилище
остаются (в режиме `bucketKeys: login` повторный `create` того же имени тем же
арендатором хранилище принимает; в режиме `bucketKeys: bucket` имя в хранилище
занято бакетом прежнего пользователя, и повторный `create` этого имени новыми
ключами получает `CODE_RESERVED`).

### Ключи бакета: `bucketKeys`

| режим | ключи бакета в `findAll` | что заводится в хранилище |
|---|---|---|
| `login` (умолчание) | ключи логина из `clients` — одни на все бакеты логина | бакет, ключами логина |
| `bucket` | своя случайная пара на каждый бакет (`crypto/rand`), как у настоящей службы | пользователь хранилища с ключами бакета и ролью `userplus` (вопрос администратора `PATCH /create-user`), затем бакет его ключами |

В режиме `bucket` ключи одного бакета не открывают другой бакет того же логина:
владелец бакета — его пользователь, листинг чужого — `AccessDenied` у
хранилища (versitygw, ACL private). Снятие бакета снимает затем его
пользователя (`PATCH /delete-user`); бакет, не заведённый в хранилище, снимает
пользователя тем же заходом. Вопросы администратора подписаны ключами
`s3.adminAccessKeyFile`/`s3.adminSecretKeyFile` вместе с хешем тела. Граница:
пользователь бакета с ролью `userplus` вправе завести и другой бакет — ключи
наружу двойник отдаёт только в `findAll` своего бакета.

## Конфиг

`cmfake --config /etc/cmfake/config.yaml`. Неизвестное поле — отказ старта.
Ключи S3 в конфиге не лежат: он называет файлы, которые монтирует Secret
стенда; файл читается без хвостового перевода строки.

```yaml
listenAddress: ":9090"            # умолчание
defaultRegion: ru1                # для create без региона
configurations:
  - id: s3_v1
    region: ru1
s3:
  endpoint: https://s3.stand.svc:9000   # только https
  signingRegion: us-east-1              # умолчание
  caFile: /etc/cmfake/s3-ca/ca.crt      # УЦ хранилища; пусто — системные
  bucketFqdnSuffix: s3.stand.svc        # fqdn бакета: <имя>.<хвост>
  requestTimeout: 30s                   # умолчание
  # только при bucketKeys: bucket — ключи администратора хранилища
  adminAccessKeyFile: /etc/cmfake/admin/accessKey
  adminSecretKeyFile: /etc/cmfake/admin/secretKey
bucketKeys: bucket                      # login (умолчание) | bucket
removal:
  attempts: 5                           # умолчание
  retryDelay: 2s                        # умолчание
clients:
  - login: tenant-a
    maxBuckets: 5
    accessKeyFile: /etc/cmfake/clients/tenant-a/accessKey
    secretKeyFile: /etc/cmfake/clients/tenant-a/secretKey
  - login: tenant-b
    maxBuckets: 5
    accessKeyFile: /etc/cmfake/clients/tenant-b/accessKey
    secretKeyFile: /etc/cmfake/clients/tenant-b/secretKey
```

Старт отказывает, если: клиентов нет; логин пуст или повторяется; у двух
арендаторов один ключ доступа; `maxBuckets` < 1; файл ключа отсутствует или
пуст; адрес хранилища не https либо с путём; длительность не разбирается или
не положительна; `bucketKeys` не `login` и не `bucket`; `bucketKeys: bucket` без
обоих файлов ключей администратора; файлы ключей администратора при
`bucketKeys: login`. Тексты отказов называют поле и путь, но не значения ключей.

Ключи каждого арендатора должны быть заведены пользователями в S3-хранилище
стенда с правом заводить и снимать бакеты: двойник делает это ключами
арендатора. Закрыт ли бакет одного арендатора ключам другого, решает политика
пользователей хранилища, а не двойник: её задаёт посадка стенда.
