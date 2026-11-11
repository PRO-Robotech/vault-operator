# Yandex backup buckets

With `--leader-elect=false`, run a single active bucket-operator instance.
Use leader election when instances can overlap.

For a Yandex-only installation, run `bucket-operator --cloud-manager-addr=`.
In a Deployment, replace the Cloud Manager address argument with
`--cloud-manager-addr=`. Claims with `provider: yandex` can reconcile using
Vault and Yandex Cloud. Claims for the internal provider report
`ProviderUnavailable`.

In the shared KV v2 mount of the claim's `VaultConfig`, create
`providers/yandex/profiles/yandex-system`. The record
contains the system `folder_id` and the authorized key fields `id`,
`service_account_id` and `private_key`. The operator
exchanges the key for an IAM token. It issues a separate S3 key to the agent
and writes the agent's connection to the claim's configured Vault destination.
The `providers/` namespace is reserved for the operator.

Add the following paths to the existing bucket-operator Vault policy. Replace
`secret` with the VaultConfig's shared KV mount.

```hcl
path "secret/data/providers/yandex/profiles/yandex-system" {
  capabilities = ["read"]
}

path "secret/data/providers/yandex/state/+/+" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/providers/yandex/state/+/+" {
  capabilities = ["read", "delete"]
}
```

Select Yandex in a separate template for new clusters:

```yaml
spec:
  vaultConfigRef:
    name: vault-bucket
  bucket:
    provider: yandex
    providerConfigRef: yandex-system
```

The profile's folder and Vault configuration must be available through claim
deletion. Provisioner key rotation uses the same Vault path. The agent needs
the endpoint, region and path style from the same Vault record as the bucket
name and S3 keys. Vault stores the endpoint as `storage.yandexcloud.net`.
The backup chart adds `https://` when configuring the agent. Verify this
wiring before assigning the template to a cluster.
