# Storage

Blob, queue, and table endpoints with Shared Key / SAS on the shared HTTP listener.

## Status

**lab**: Storage account ARM lite; blob put/get/list/delete; queue create/send/peek/receive (visibility timeout lite); table endpoint advertised; Shared Key HMAC and SAS HMAC (`se`, `sp`).

## Wire protocol

| Surface | Path prefix |
|---------|-------------|
| ARM account | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}` |
| Blob | `/blob/{account}/...` |
| Queue | `/queue/{account}/...` |
| Table | `/table/{account}/...` (see [table.md](table.md)) |

Auth: ARM account CRUD uses Bearer. Blob/queue/table use `Authorization: SharedKey ...` or SAS query HMAC. Well-known Azurite `devstoreaccount1` key refused on non-loopback listen.

## Authz / authn

- ARM storage account: token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- Shared Key HMAC-SHA256 of method + path with the storage account key
- SAS query HMAC-SHA256 of `sp`, `st`, `se`, and path with the same account key. `se` is expiry (expired or unparseable is denied). `sp` is permissions (GET blob needs `r`, list needs `l`, PUT needs `w`/`c`/`a`, DELETE needs `d`). Missing account, unknown account, or garbage `sig` is HTTP 403 `AuthenticationFailed`
- Account keys sealed at rest

## Detailed actions

- Create storage account (sealed account key; `primaryEndpoints` for blob/queue/table)
- List containers; create/delete container; put/get/list/delete blobs
- Create queue; enqueue; peek (`peekonly=true`); dequeue with optional `visibilitytimeout`

## Not implemented

- Files, Data Lake Gen2 hierarchical namespace depth
- Azurite multi-port drop-in (`10000`/`10001`/`10002`) as default
- Soft delete / immutability policies
- Object replication / block blob commit stages beyond put-as-block theatre

## Emulator limits

- Single HTTP port path prefixes (not separate blob/queue hosts by default)
- No host `docker.sock`

## Deferred depth

- Full Azurite wire compatibility matrix
- Static website hosting

## Verification / CLI smoke

```bash
# After creating an account and obtaining the lab account key:
# Use Azure Storage SDK or curl SharedKey against
# http://127.0.0.1:4599/blob/{account}/{container}/{blob}
curl -fsS http://127.0.0.1:4599/_noctaxris-az/ready
```
