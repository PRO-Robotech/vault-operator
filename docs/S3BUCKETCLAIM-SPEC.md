# S3BucketClaim (bucket-operator) — Техническое задание

> **Status:** Draft
> **Целевая среда:** Vault OSS (1.17+), Kubernetes ≥ 1.34, cloud-manager gRPC
> **Базовые документы:** `docs/OPERATOR-SPEC.md` (vault-operator — доступ к Vault), `docs/VAULTSECRETCLAIM-SPEC.md` (vault-secret-operator — значения секретов)
> **Эпик:** `realization/stories/platform/004-backup-bucket/`
> **Блокер:** контракт с командой cloud-manager (§10 П1)

---

## 0. Назначение

### 0.1. Что делает контроллер

`bucket-operator` — третий контроллер в репозитории vault-operator (отдельный Deployment + ServiceAccount + Vault-роль, по образцу vault-secret-operator). По ресурсу `S3BucketClaim` (1:1 с кластером) он:

1. **создаёт S3-бакет** под кастомером в облаке Beget через gRPC cloud-manager (`ManagedBy=SYSTEM`);
2. **дожидается** статуса `RUNNING` и забирает `AccessKey`/`SecretKey` через `CloudS3Service.FindAll`;
3. **пишет ключи в Vault** по пути кластера — `{kvMount}/data/{secretsPrefix}/backup/s3`;
4. **поддерживает актуальность**: при внешней ротации ключей в cloud-manager перезаписывает Vault (drift-recheck);
5. **удаляет** бакет и Vault-путь при удалении CR (`deletionPolicy: Purge`, дефолт).

Это единственный компонент платформы, который одновременно ходит в cloud-manager (создание бакетов) и в Vault (write одного листа `clusters/+/backup/s3`). Секретный материал не попадает ни в manager/MySQL, ни в k8s-Secret'ы management-кластера — только Vault.

### 0.2. Что контроллер НЕ делает

- не настраивает доступ к Vault (auth method, policies, roles) — это `VaultClaim` (vault-operator);
- не пишет другие секреты кластера — это `VaultSecretClaim` (vault-secret-operator);
- не настраивает потребителей ключей (etcd-backup, velero) и consumer-policies — отдельный эпик;
- не тарифицирует бакет — стоимость заложена в услугу кластера, биллинг-код не участвует (решение продукта, эпик §2);
- не ротирует ключи по расписанию — только след за внешней ротацией;
- не управляет объёмом/квотой бакета — сторона cloud-manager;
- не делает отложенное удаление / восстановление бекапов — при удалении кластера бакет удаляется сразу (решение продукта).

---

## 1. Ресурсы

### 1.1. CRD

| CRD | Scope | Назначение |
|-----|-------|------------|
| `S3BucketClaim` | Namespaced | Per-cluster: параметры бакета + куда положить ключи. Имя = имя кластера, 1:1, ownerRef на ClusterClaim. |

API Group: `vault.in-cloud.io/v1alpha1`. Подключение к Vault — через отдельный экземпляр `VaultConfig` (`vault-bucket`, §3.1); собственной CRD под конфигурацию не вводится.

### 1.2. Что контроллер создаёт / изменяет

| Где | Операция |
|-----|----------|
| cloud-manager | `CloudService.Create` (S3Params) — создание бакета; `CloudS3Service.RemoveBucket` — удаление |
| Vault | `POST {kvMount}/data/{secretsPrefix}/backup/s3` — запись ключей (merge); `DELETE {kvMount}/metadata/...` — purge |

### 1.3. Что контроллер читает

| Ресурс | Зачем |
|--------|-------|
| `VaultConfig` `vault-bucket` (owner-label `vault.in-cloud.io/owner=vault-bucket`) | адрес Vault, TLS, KV-mount, auth-роль |
| `ServiceAccount` контроллера | JWT для логина в Vault |
| `CloudS3Service.FindAll` (ByBucket) | статус бакета + `AccessKey`/`SecretKey` |

Kubeconfig'и target-кластеров **не требуются** — контроллер работает только с cloud-manager и Vault.

---

## 2. CRD-спецификация

### 2.1. S3BucketClaim

```yaml
apiVersion: vault.in-cloud.io/v1alpha1
kind: S3BucketClaim
metadata:
  name: ec8a00                       # = имя кластера (naming.S3BucketClaimName)
  namespace: dlputi1u                # customer namespace (== custLogin)
  ownerReferences: [...]             # ClusterClaim, controller=true (ставит cluster-claim-operator)
spec:
  vaultConfigRef:
    name: vault-bucket               # отдельный VaultConfig с write-ролью bucket-operator
  clusterRef:
    name: ec8a00                     # immutable
  customerLogin: dlputi1u            # immutable; рендер из .ClusterClaim.spec.extraEnvs.begetClusterCustomerLogin
  region: ru-1                       # из extraEnvs.begetClusterRegion
  bucket:
    # имя НЕ задаётся в spec — конвенция + adopt-семантика; итог фиксируется в status.bucketName (§6)
    public: false
    managedBy: SYSTEM                # enum SYSTEM|CUSTOMER, дефолт SYSTEM, immutable
    configurationId: s3_v1           # имя записи S3-конфигурации в каталоге cloud-manager
                                     # (статичный `s3_v1` — существует, подтв. cloud-manager 2026-07-09);
                                     # рендерится mgmt-шаблоном; при пустом — дефолт оператора
                                     # --default-s3-configuration-id. Мульти-регион: производное от region
  vault:
    secretsPrefix: clusters/ec8a00   # immutable, == secretsPrefix VaultClaim/VaultSecretClaim
    destinationPath: backup/s3       # относительный; итог: secret/data/clusters/ec8a00/backup/s3
  deletionPolicy: Purge              # Purge (дефолт) | Retain
status:
  phase: Ready                       # Pending | Provisioning | Ready | Failed | Deleting
  bucketName: k8s-dlputi1u-ec8a00
  bucketStatus: RUNNING              # зеркало s3.Status (CREATING/RUNNING/ERROR/...)
  endpoint: k8s-dlputi1u-ec8a00.s3.beget.cloud   # из Bucket.Fqdn
  keysWrittenHash: "9f2c…"           # hash(accessKey+secretKey+bucketName+endpoint) — детект ротации/дрифта
  observedGeneration: 2
  conditions:
    - { type: ConfigResolved,    status: "True" }   # VaultConfig разрешён
    - { type: VaultReachable,    status: "True" }   # login в Vault успешен
    - { type: BucketProvisioned, status: "True" }   # Create принят / бакет adopted
    - { type: BucketRunning,     status: "True" }   # Status==RUNNING, ключи непустые
    - { type: KeysWritten,       status: "True" }   # ключи в Vault
    - { type: Ready,             status: "True" }   # aggregate
```

### 2.2. Валидации (CEL)

| Поле | Правило |
|------|---------|
| `clusterRef.name`, `customerLogin`, `vault.secretsPrefix`, `bucket.managedBy` | immutable (`self == oldSelf`) |
| `metadata.name` | `[a-z0-9-]+`, ≤ 40 символов (запас под префикс имени бакета, лимит S3 = 63) |
| `deletionPolicy` | enum `Purge`/`Retain`, дефолт `Purge` |
| `vault.destinationPath` | непустой, без ведущего `/`, дефолт `backup/s3` |

`vaultConfigRef` — mutable (переключение write-роли без пересоздания CR, как у VaultSecretClaim).

---

## 3. Vault: топология, формат, привилегии

### 3.1. VaultConfig и роль

Третий экземпляр `VaultConfig` — `vault-bucket`, label `vault.in-cloud.io/owner=vault-bucket`: реконсилится только процессом bucket-operator (owner-scoped predicate — механизм vault-secret-operator переиспользуется). Vault-роль `bucket-operator` bound к SA `bucket-operator-controller`.

### 3.2. Путь и формат ключей

Путь: `{kvMount}/data/{secretsPrefix}/{destinationPath}` → `secret/data/clusters/<cluster>/backup/s3`. Лежит под `secretsPrefix` кластера — будущие consumer-policies (`read` на `clusters/<cluster>/backup/*` в шаблоне VaultClaim) добавляются вместе с первым потребителем, без изменений bucket-operator.

Формат — **отдельные ключи** (не JSON-blob), в стиле `destination.key` VaultSecretClaim, удобно для vault-injector-темплейтов. Набор полей выведен из того, что потребителю (etcd-backup/velero) нужно, чтобы собрать S3-клиент к ceph (референс `svc-vps-image-manager/S3Client.php`: `endpoint + region + use_path_style + access/secret`):

```
accessKey:       AKIA...
secretKey:       ...
bucketName:      k8s-dlputi1u-ec8a00        # = Bucket.name
endpoint:        https://s3.ru1.storage.beget.cloud   # per-region ceph S3, path-style
region:          ru1
s3ForcePathStyle: "true"                    # ceph требует path-style, не virtual-host
```

> **Endpoint — фиксированный per-region ceph-хост** (`s3.<region>.storage.beget.cloud`), а не домен бакета: в референсе `Repository::getS3URL()` захардкожен `https://s3.ru1.storage.beget.cloud`, регион кластера у cloud-manager для s3 пока тоже фиксирован `ru1` (TODO на их стороне — см. §10 П3). `Bucket.Fqdn`/`Cname` (домен самого бакета) для backup-потребителя не нужны — они для публичного доступа.

Запись — read-modify-write merge (переиспользовать `internal/vault/kv.go`): соседние ключи листа не клобберятся; запись только при `hash(входа) != status.keysWrittenHash` — не жечь KV-версии.

### 3.3. Policy `bucket-operator-admin` (bootstrap платформой, разово)

```hcl
path "secret/data/clusters/+/backup/s3"     { capabilities = ["create", "update", "read", "delete"] }
path "secret/metadata/clusters/+/backup/s3" { capabilities = ["read", "delete"] }
path "auth/token/renew-self"                { capabilities = ["update"] }
path "auth/token/lookup-self"               { capabilities = ["read"] }
```

Что НЕ выдаётся: `sys/*`, `auth/+/role/*` (только vault-operator), запись вне листа `backup/s3` (только vault-secret-operator).

> **Оговорка к VAULTSECRETCLAIM-SPEC §0.1**: формулировку «единственный компонент с правом записи в `secret/data/*`» уточнить: «…кроме листа `clusters/+/backup/s3`, которым владеет bucket-operator». Разделение остаётся enforced на уровне Vault-политик (pod SA ↔ role); писатели не пересекаются по путям. Опциональное deny-правило в policy vault-secret-operator — открытый вопрос D-open-1 (§10).

---

## 4. Reconcile-pipeline

Событийный (watch CR + startup); при `Ready` — drift-recheck RequeueAfter 10m (паттерн VaultClaim). Три gRPC-вызова к `svc-cloud-manager`, дословно как в прод-референсе `svc-vps-image-manager`: **Create → FindAll(creds) → RemoveBucket**. Креды берутся **не из create-ответа, а из `FindAll`** (канонический путь референса; работает и на текущем вендоренном proto).

| # | Шаг | Действие | Ошибка / WAIT |
|---|-----|----------|---------------|
| 1 | ResolveConfig | resolve `VaultConfig` `vault-bucket` + login (роль `bucket-operator`) | `ConfigResolved`/`VaultReachable=False`, backoff 30s→5m |
| 2 | EnsureBucket | имя из `status.bucketName`, иначе по конвенции (§6); `configurationId` из `spec.bucket.configurationId` (fallback — флаг `--default-s3-configuration-id`); если бакета ещё нет → `CloudService.Create{CustomerIdentifier: <custLogin>, ConfigurationId, DisplayName: "k8s cluster <name> backup", Region: "ru1" (хардкод cloud-manager, П3), S3Params{BucketName, Public: false, ManagedBy: SYSTEM}}`. **`status.bucketName` фиксируется сразу.** Идемпотентность/adopt: `s3_error`/`BUCKET_NAME_ALREADY_EXISTS(=8)` → перейти к Step 3 FindAll и проверить владельца; при коллизии имени — индекс-суффикс `-N` (§6) | `INVALID_BUCKET_NAME(=9)` → terminal `Failed`; `BUCKET_LIMIT_REACHED(=10)` → `BucketProvisioned=False` reason=`QuotaExceeded`, RequeueAfter 5m (см. П2 — carve-out квоты); `CONFIGURATION_NOT_FOUND(=2)` → terminal `Failed` reason=`ConfigurationMissing` (запись каталога не заведена, П1); `INSUFFICIENT_FUNDS(=1)`/`INVALID_DISPLAY_NAME(=4)` → `Failed` + event |
| 3 | FetchCreds | `CloudS3Service.FindAll(ByCustomer=<custLogin> + ByBucket=<bucketName>)` → `bucketList[0]`. **Валидация владельца** `bucket.CustLogin == custLogin` (иначе terminal `Failed` — чужой бакет). `Status`: `RUNNING`+непустые ключи → дальше; `CREATING` → RequeueAfter 15s (backoff до 1m); `ERROR` → `Failed`; `REMOVING`/`REMOVED` → `Failed` (внешнее вмешательство). Пусто → RequeueAfter 5s (гонка после Create) | ключи пустые при `RUNNING` → `Failed` reason=`NoKeys` |
| 4 | WriteVault | read-modify-write в `{kvMount}/data/{secretsPrefix}/{destinationPath}` (формат §3.2, endpoint = `s3.<region>.storage.beget.cloud`); запись только при смене hash | Vault-ошибки → `KeysWritten=False`, backoff; circuit-breaker `internal/vault` |
| 5 | Ready | `phase=Ready`, RequeueAfter 10m: `FindAll` → сравнить ключи с `keysWrittenHash` — детект внешней ротации → перезапись Vault | — |

Требования к реализации: интерфейс `internal/cloudmanager.BucketAPI{Create, FindByCustomerBucket, Remove}` поверх **уже существующего** вендоренного proto (копия из `capi-provider-beget/internal/grpc/cloud-manager/proto`; проверено — `CloudServiceClient.Create`, `CloudS3ServiceClient.FindAll` со scope'ами `ByCustomer`/`ByBucket`, `RemoveBucket`, `S3BucketManagedBy_SYSTEM`, `Bucket.AccessKey/SecretKey`, `CreateParams` — всё на месте; перепин на `s3Bucket=19` НЕ нужен для v1) + mock для envtest. Адрес cloud-manager — флаг/ENV `grpc-internal.svc-cloud-manager[-<env>].service.consul:50051` (**не** hardcode, урок `capi-csr-approver`). Физически бакет создаёт downstream `svc-s3-manager` — оператор его не зовёт напрямую.

---

## 5. Удаление (finalizer)

Finalizer `vault.in-cloud.io/s3bucketclaim-finalizer`, ставится контроллером при первом reconcile.

| deletionPolicy | Действия finalizer'а |
|---|---|
| `Purge` (дефолт) | `RemoveBucket(status.bucketName)` → поллинг до `REMOVED` (RequeueAfter 15s) → `DeleteKVMetadata({secretsPrefix}/{destinationPath})` → снять finalizer |
| `Retain` | снять finalizer; бакет и ключи остаются (ручная очистка) |

- Ошибки cloud-manager/Vault при Purge → retry с backoff и requeue; `phase=Deleting` + event; после N неудачных попыток — метрика/алерт (§9), finalizer **не снимается** (иначе осиротевший бакет). Reverse-pipeline ClusterClaim работает через `deleteAndWait` — ожидание встроено в существующий механизм; блок удаления S3BucketClaim ставится первым (рядом с VaultClaim/VaultSecretClaim), kubeconfig ему не нужен.
- Бакет в `CREATING` на момент удаления — семантика `RemoveBucket` уточняется у cloud-manager (§10 П4); до ответа — дождаться `RUNNING`, затем удалить.
- **Пересоздание кластера с тем же именем** после удаления: бакет создаётся заново с тем же детерминированным именем (старый удалён Purge'ем); бекапы прошлой инкарнации не восстанавливаются — осознанное решение продукта (эпик §2.3).

---

## 6. Идемпотентность и имя бакета

Правила cloud-manager (`CreateParams.BucketName`): латиница/цифры/`-`, `-` не в начале/конце и не дважды подряд; лимит длины — 63 (S3-стандарт).

**Конвенция:** `k8s-<custLogin>-<clusterName>` (например `k8s-dlputi1u-ec8a00`), санитизация custLogin: lowercase, `_`→`-`, схлопнуть повторные `-`. Включение custLogin даёт глобальную уникальность (имена ClusterClaim namespaced — глобальная уникальность не гарантирована) и мгновенную атрибуцию бакета для саппорта.

Инварианты:

1. `status.bucketName` — источник правды после первого успешного Create/adopt (в т.ч. если применён fallback-суффикс).
2. `BUCKET_NAME_ALREADY_EXISTS` → `FindAll(ByBucket)`: свой SYSTEM-бакет этого кастомера → adopt (повторный reconcile после краша между Create и записью status); чужой → детерминированный fallback-суффикс `-2` + event, итог в status *(альтернатива — terminal Failed; зафиксировать на ревью, PLAN «Решения по ходу»)*.
3. Повторный reconcile при `RUNNING`-бакете — только сравнение hash ключей; Vault пишется лишь при изменении.
4. Краш между Create и WriteVault — восстановление через `status.bucketName`/adopt, дублей не возникает.

---

## 7. Интеграция и деплой

### 7.1. cluster-claim-operator (третий прогон рецепта Story 010)

- `api/v1alpha1/clusterclaim_types.go`: `S3BucketClaimTemplateRef *TemplateRef` (skip шагов при nil — рычаг поэтапного раската); conditions `S3BucketClaimCreated`/`S3BucketClaimReady`; `status.s3Bucket *S3BucketStatusSummary` (копия `VaultStatusSummary` + `BucketName string`).
- `internal/controller/pipeline.go`: `EnsureS3BucketClaim` — **сразу после `Application`** (бакету не нужен kubeconfig/CP — создание параллелится со всем VPS-провижинингом, в отличие от VaultClaim после Step 7); `WaitS3BucketClaim` — последним (гейтит `ClusterClaim Ready`, консистентно с Vault-паттерном «Ensure рано — Wait поздно»).
- `gvk.go`, `naming.go` (`S3BucketClaimName = claim.Name`), `status.go` (`mirrorS3BucketStatus`), `clusterclaim_controller.go` (reverse-pipeline: removeResourceFinalizer → deleteAndWait, блок рядом с VaultSecretClaim), watch по ownerRef.

### 7.2. Шаблон в mgmt (GitOps, без релиза оператора)

`ClusterClaimObserveResourceTemplate` `<k8sVersion>-bucketclaim` рендерит §2.1 из `{{ .ClusterClaim.metadata.name }}`, `{{ .ClusterClaim.metadata.namespace }}`, `{{ .ClusterClaim.spec.extraEnvs.begetClusterCustomerLogin }}`, `{{ .ClusterClaim.spec.extraEnvs.begetClusterRegion }}` — все поля уже проставляются proxy (`svc-k8s-proxy/internal/service/cluster.go:154-157`). `spec.bucket.configurationId` задаётся **в самом шаблоне** (константа `s3_v1`, или производное от `region` при мульти-регионе) — менять привязку к тарифу можно правкой шаблона в mgmt, без релиза оператора и без изменений proxy/ClusterClaim.

### 7.3. svc-k8s-proxy

`buildClusterClaimYAML`: `spec.s3BucketClaimTemplateRef.name = <K8sVersion>-bucketclaim` в create + update-ветке (внутри `if params.K8sVersion != ""`) — точный образец MR31 (`-vaultclaim`), ~6-10 строк. При переезде на V2 версионирования шаблонов (`template_version` как база) мигрирует вместе с остальными ref'ами.

### 7.4. Деплой bucket-operator

`cmd/bucket/main.go` (по образцу `cmd/vaultsecret/`), overlay `config/bucket-operator/`: Deployment `bucket-operator`, SA `bucket-operator-controller`, RBAC (S3BucketClaim + VaultConfig get/list/watch, events, leases). Флаги: `--cloud-manager-addr`, `--default-s3-configuration-id` (fallback, если `spec.bucket.configurationId` пуст), `--metrics-bind-address`, `--leader-elect`. Образ/репозиторий — общий с vault-operator, различается entrypoint (паттерн vault-secret-operator).

### 7.5. Без изменений в v1

svc-k8s-manager, cp-2-0, api0, Hub-события — готовность бакета уже влияет на `ClusterClaim.status.phase`, публикуемый существующими «тонкими» событиями.

---

## 8. Архитектурные решения (Decisions)

| D# | Решение | Обоснование |
|----|---------|-------------|
| **D1** | Новый CRD + контроллер, а НЕ item `type: s3Bucket` в VaultSecretClaim | VaultSecretClaim специфицирован как событийный apply-слой без поллинга; бакет требует поллинга CREATING→RUNNING, retry на квоты, outbound gRPC. Провал бакета не должен ронять генерацию остальных секретов (`Phase=Failed` на весь VaultSecretClaim заблокировал бы argocd/vmagent-пароли). Blast radius единственного секрето-писателя не растёт (он не получает права создавать облачные ресурсы). Статус бакета — first-class, а не размазан по `status.items[]` |
| **D2** | Хостинг в репо vault-operator (третий контроллер), а не capi-provider-beget / новый репозиторий | Переиспользуется дорогое: `internal/vault` (login, circuit-breaker, KV), механизм owner-scoped VaultConfig, паттерн «отдельный entrypoint/Deployment/SA», e2e-харнесс. У capi-provider другой домен (CAPI infra) и релизный поезд, Vault-клиента там нет. Новый репозиторий — плата (CI, чарты, копия Vault-клиента; shared-библиотек нет) не оправдана для v1; при росте домена бекапов контроллер выносится без смены CRD. Граница привилегий — та же, что vault-operator ↔ vault-secret-operator: репо общее, процесс/SA/роль раздельные |
| **D3** | Удаление сразу (Purge дефолт), без отложенного удаления/tombstone | Решение продукта 2026-07-02. Упрощение: не нужен cluster-scoped tombstone-CR, retention-механика и resurrect-семантика |
| **D4** | Имя бакета `k8s-<custLogin>-<clusterName>` | Глобальная уникальность (ClusterClaim namespaced), атрибуция для саппорта, детерминизм для adopt |
| **D5** | `EnsureS3BucketClaim` сразу после `Application` | Бакет не зависит ни от чего в кластере — CREATING (минуты) параллелится с VPS-провижинингом, а не добавляется к нему |
| **D6** | `WaitS3BucketClaim` гейтит `ClusterClaim Ready` | Консистентно с VaultClaim/VaultSecretClaim; ключи — пререквизит платформенных бекапов. Риск «не Ready из-за квоты» закрыт П3 (SYSTEM-бакеты вне customer-квоты) |
| **D7** | Биллинг не участвует | Решение продукта: SYSTEM-бакет, стоимость в услуге кластера; для `ManagedBy=SYSTEM` cloud-manager пропускает биллинг (`SystemCreationStrategy.updateBillingOption()` no-op) |
| **D8** | `configurationId` — **поле спеки клейма** (`spec.bucket.configurationId`), рендерится mgmt-шаблоном, дефолт-fallback на флаге оператора. Значение = `s3_v1` (существующий статичный конфиг) | `configuration_id` — обязательный вход create и ссылка на запись каталога cloud-manager (не биллинг-поле у нас). Не варьируется per-cluster сегодня (один ru1-конфиг `s3_v1`), но `Configuration` привязан к региону → при мульти-регионе шаблон отрендерит id из `region` без изменений оператора/CRD. Держим по образцу `region`/`secretsPrefix` (template-driven), а не хардкодом в операторе (урок `capi-csr-approver`); флаг-fallback — чтобы клейм без поля не падал. Заводить запись НЕ нужно — `s3_v1` уже есть (подтв. cloud-manager 2026-07-09) |

---

## 9. Error handling & observability

- **Events** на CR: `BucketCreated`, `BucketAdopted`, `KeysWritten`, `KeysRotatedExternally`, `BucketRemoveFailed`, `QuotaExceeded`.
- **Метрики** (Prometheus, стиль vault-operator):
  - `s3bucketclaim_provisioning_duration_seconds` (histogram, Create→Ready);
  - `s3bucketclaim_cloudmanager_calls_total{method,result}`;
  - `s3bucketclaim_deletion_stuck` (gauge: CR в `Deleting` дольше порога) — **алерт**: застрявший finalizer блокирует удаление кластера.
- **Backoff**: cloud-manager недоступен → экспоненциальный 30s→5m; Vault — существующий circuit-breaker `internal/vault` (5 fail → 2 min open).
- Терминальные ошибки (`INVALID_BUCKET_NAME`, чужой бакет без fallback) — `phase=Failed`, без requeue-шторма (terminal error по паттерну cluster-claim-operator).

---

## 10. Пререквизиты и открытые вопросы

### Пререквизиты к команде cloud-manager (гейтят старт — эпик §4)

> **Разведка приватного GitLab (2026-07-02..09) установила: механизм полностью существует и в проде** — SYSTEM-бакет с `configuration_id` создаётся `CloudService.create` (`cloud/svc-cloud-manager` → downstream `svc-s3-manager`), а прод-сервис `vps/svc-vps-image-manager` делает ровно наш флоу (create → findAll(creds) → removeBucket). Вендоренного Go-proto достаточно. Пререквизиты сузились до **одного must-have** (`configuration_id`) + операционных подтверждений. Детали — эпик [notes.md](../../realization/stories/platform/004-backup-bucket/notes.md).

| # | Что нужно | Критичность |
|---|---|---|
| ✅ **П1 (разрешён 2026-07-09)** | `configuration_id` = статичный **`s3_v1`** (существует в каталоге cloud-manager; подтвердил Д. Колбин: «конфигов единицы, в нашем случае s3_v1»). Отдельную запись заводить НЕ нужно. Создание — через `cloud-manager s3/create` (= `CloudService.create` с `s3_params`), не vps-manager. `CONFIGURATION_NOT_FOUND(=2)` теперь не ожидается при валидном `s3_v1`. | — (снят) |
| **П2** | Квота/привязка: SYSTEM-бакет привязан к customer-логину, **считается в `maxBuckets`** и требует S3-услугу кастомера `RUNNING` (`requireAccess(Scope::S3)`, проверки в `Creator::run()`). Нужен carve-out для SYSTEM (иначе `BUCKET_LIMIT_REACHED` при нескольких кластерах кастомера) + решение, под каким customer identity создавать. | гейт Ready |
| **П3** | Регион: cloud-manager для s3 сейчас **хардкодит `ru1`** (TODO в `svc-vps-image-manager/Creator.php` + `getS3URL()` захардкожен `s3.ru1.storage.beget.cloud`). Кластеры не в ru1 → нужен проброс региона в create и корректный ceph-endpoint. Пока — ограничение (бакеты только ru1). | scope-ограничение |
| **П4** | Семантика `RemoveBucket` для бакета в `CREATING`; ротация ключей — в контракте нет rotate RPC и нет TTL (delete+recreate? out-of-band?). | finalizer + ротация |
| **П5 (снято с крит. пути)** | Благословить/снять proto-аннотацию `// todo … не доделан` над общим `CreateRequest` и (опц.) дать ревизию с `Service.s3Bucket=19` для inline-ключей. **Не блокер v1**: креды берём через `FindAll` (как референс), вендоренный proto достаточен. | nice-to-have |

### Открытые вопросы

| # | Вопрос | Кто/когда |
|---|---|---|
| D-open-1 | Deny-правило на `clusters/+/backup/s3` в policy vault-secret-operator (жёсткая эксклюзивность писателей); функционально не требуется | безопасники, ревью П4 |
| D-open-2 | Fallback-суффикс vs terminal Failed при чужом бакете с конвенционным именем (§6 п.2) | ревью ТЗ |
| D-open-3 | Показ бакета/endpoint в панели (поле в Hub-события + api0 + manager) | продукт, v2 |
| D-open-4 | Вынос вендоренного cloud-manager proto в `api0/cloud/` (появляется вторая копия после capi-provider-beget) | техдолг-тикет |
