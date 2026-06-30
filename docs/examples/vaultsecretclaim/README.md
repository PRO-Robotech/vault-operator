# VaultSecretClaim

Наполнение Vault **значениями** секретов для одного кластера: генерация паролей (`generate`) и копирование общих секретов в per-cluster пути (`copy`). Этим занимается **отдельный** контроллер `vault-secret-operator` (свой Deployment + ServiceAccount), а не `vault-operator` — тот настраивает только доступ (auth method, policies, roles).

## Состав

| Файл | Что |
|---|---|
| [vaultconfig.yaml](vaultconfig.yaml) | Отдельный VaultConfig `vault-secret` с write-ролью (label `vault.in-cloud.io/owner=vault-secret`) |
| [vaultsecretclaim.yaml](vaultsecretclaim.yaml) | Per-cluster список секретов: два `generate` + один `copy` |
| [vault-secret-operator-admin.hcl](vault-secret-operator-admin.hcl) | Bootstrap-policy в Vault (платформа создаёт разово, вне скоупа контроллера) |

## Предусловия

- `vault-secret-operator` установлен (overlay `config/secret-manager/`).
- В Vault есть policy `vault-secret-operator-admin` и роль `vault-secret-operator`, привязанная к SA `vault-secret-operator-controller-manager`
- Общий KV-v2 mount `secret/` существует.
- Для `copy` источники уже лежат в Vault (например, `secret/data/system/dex#staticClient`) — их заводит платформа.
- `secretsPrefix` совпадает с `VaultClaim.secretsPrefix` того же кластера: именно на эти пути `vault-operator` выдаёт consumer'ам read-доступ.

## Применение

```bash
kubectl apply -f docs/examples/vaultsecretclaim/vaultconfig.yaml
kubectl wait vaultconfig/vault-secret --for=condition=Reachable=True --timeout=2m

kubectl apply -f docs/examples/vaultsecretclaim/vaultsecretclaim.yaml
kubectl wait vaultsecretclaim/ec8a00 -n dlputi1u --for=condition=Ready=True --timeout=2m
```

## Проверка

```bash
kubectl get vaultsecretclaim -n dlputi1u ec8a00 -o wide
# NAME     PHASE   CLUSTER   AGE
# ec8a00   Ready   ec8a00    20s

kubectl get vaultsecretclaim -n dlputi1u ec8a00 \
  -o jsonpath='{range .status.items[*]}{.name}{"\t"}{.state}{"\n"}{end}'
# argocd-admin    Applied
# vmagent         Applied
# grafana-oidc    Applied
```

В Vault под `secret/data/clusters/ec8a00/` появятся:

- `argocd` → `admin.password` (16 симв.) + `admin.passwordBcrypt` (`$2a$…`)
- `monitoring/vmagent` → `password` (24 симв.)
- `grafana` → `staticClient` (скопирован из `system/dex`)

## Поведение

- **generate** — create-once: значение перегенерируется только если ключа нет в Vault либо сменились критерии (`length`/`charset`/`hash`). Пересоздание CR не перегенерирует уже существующее значение.
- **copy** — перекопирует только при смене значения источника (`hash(path+key+value)`); соседние ключи в destination сохраняются (KV-v2 пишет full-replace → read-modify-write).
- **Retain** (дефолт) — при удалении CR значения остаются в Vault; **Purge** — удаляет записанные ключи (нужен `delete` в policy).
- Удалённый в Vault извне секрет контроллер не отслеживает и не восстанавливает (reconcile событийный, без поллинга).

## Чистка

```bash
kubectl delete vaultsecretclaim ec8a00 -n dlputi1u
# deletionPolicy: Retain → значения остаются в Vault, снимается finalizer
# deletionPolicy: Purge  → записанные ключи удаляются из Vault

kubectl delete vaultconfig vault-secret   # только если referencedBy=0
```
