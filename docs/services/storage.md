# Storage

Blob, queue, and table endpoints with Shared Key / SAS on the shared HTTP listener.

## Status

**lab** — Storage account ARM lite; blob put/get/list/delete; queue create/send/peek/receive (visibility timeout lite); table endpoint advertised; Shared Key and SAS.

## Wire protocol

| Surface | Path prefix |
|---------|-------------|
| ARM account | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}` |
| Blob | `/blob/{account}/...` |
| Queue | `/queue/{account}/...` |
| Table | `/table/{account}/...` (see [table.md](table.md)) |

Auth: `Authorization: SharedKey ...` or SAS query. Well-known Azurite `devstoreaccount1` key refused on non-loopback listen.

## Authz / authn

- Shared Key HMAC theatre for account key
- SAS token query validation lite
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
