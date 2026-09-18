# Key Vault

ARM vault CRUD lite plus data-plane secrets and keys with sealed storage.

## Status

**lab.** Vault create/get; secret set/get/soft-delete/recover (immediate lab theatre); key create/get; certificates (public `cer`, exportable private key via the same-name secret); values sealed with master key.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT`/`GET` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{name}` |
| Data plane | `/keyvault/{name}/secrets/{secret}` , `/keyvault/{name}/keys/{key}` , `/keyvault/{name}/certificates/{cert}` |
| Soft-delete | `DELETE /keyvault/{name}/secrets/{secret}` ; `POST /keyvault/{name}/deletedsecrets/{secret}/recover` |

Bearer required on data plane (WWW-Authenticate on 401). Data plane resource is `https://vault.azure.net` (not ARM `aud`).

## Authz

- ARM vault CRUD: token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- `Microsoft.KeyVault/vaults/read|write`
- Data plane secret/key access under vault scope for a valid Bearer (ARM `aud` is not required)

## Detailed actions

- Create vault metadata
- Set/get secret versions (sealed)
- Soft-delete and recover secrets (timers are immediate in lab)
- Create/get key material (sealed)
- PUT/GET certificates. GET certificate returns public `cer` only. When policy `key_props.exportable` (or `keyProperties.exportable`) is true, the private key is stored as the addressable secret of the same name (PKCS#8 PEM). GET secret without an exportable policy is denied. The exported PEM can be registered with Graph `addKey` and used as `private_key_jwt`.

## Not implemented

- HSM, managed HSM
- Soft-delete retention timers / purge protection delays
- Access policies vs RBAC dual mode beyond lab Bearer
- Full Key Vault REST version matrix

## Emulator limits

- Single listener path prefix `/keyvault/{name}` (not per-vault hostnames)
- No real FIPS HSM

## Deferred depth

- Certificate issuance from a public CA and rotation
- Private endpoints / network ACLs theatre

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus","properties":{}}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1/providers/Microsoft.KeyVault/vaults/kv1?api-version=2022-07-01"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"value":"s3cret"}' \
  "http://127.0.0.1:4599/keyvault/kv1/secrets/demo"
```
