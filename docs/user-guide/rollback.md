# Откат оператора на v0.0.9

Выпуск с журналом и гостевыми заявками отказывает в том, что v0.0.9 применил бы, и удаляет только своё. v0.0.9 так не умеет: роли он чистит по `LIST − spec` и политики пишет без проверок. Поэтому откат разрешён только при двух условиях.

## Условие 1: нет заявок нового вида

Гостевая заявка или заявка с `rolePruning: Owned` под v0.0.9 удалит чужие роли на своём mount — например, роли самих операторов.

```bash
kubectl --kubeconfig <kubeconfig> --context <context> get vaultclaims -A -o json \
  | jq '[.items[] | select(.spec.auth.manageConfig == false or .spec.auth.rolePruning == "Owned")] | length'
```

Должно быть `0`. Иначе откат запрещён.

## Условие 2: нет отвергнутых заявок

Заявка, которой новый выпуск отказал, под v0.0.9 будет применена: политика вне ограды запишется, чужая роль перезапишется.

```bash
kubectl --kubeconfig <kubeconfig> --context <context> get vaultclaims -A -o json \
  | jq '[.items[] | select(any(.status.conditions[]?; .reason as $r
        | ["OwnershipConflict","PolicyGuardViolation","PolicyReferenceForbidden","MountConflict","KeyAdoptionRestricted","MountNotOwned"]
        | index($r)))] | length'
```

Должно быть `0`. Каждую такую заявку удаляют **до** отката, пока работает новый выпуск: он снимает только имена из её журнала, а отвергнутого в журнале нет.

## Что остаётся после отката

- CRD остаются новыми; v0.0.9 новые поля игнорирует.
- v0.0.9 перезапишет `appliedPolicies`/`appliedRoles` по `spec`. Это безопасно, пока выполнено условие 1.
- Проверка в коде — `TestUpgradeFromLegacyKeepsVaultByteForByte` (`make test-e2e-pipeline`): v0.0.9 → новый выпуск → отвергнутая заявка удалена → v0.0.9; снимок Vault после отката совпадает с последним снимком нового выпуска байт в байт.
