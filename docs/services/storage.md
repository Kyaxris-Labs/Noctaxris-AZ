# Storage

Blob, queue, and table endpoints with Shared Key / SAS on the shared HTTP listener.

## Status

**lab**: Storage account ARM lite; blob put/get/list/delete; queue create/send/peek/receive (visibility timeout lite); table endpoint advertised; Shared Key HMAC and SAS HMAC (`se`, `sp`).

## Wire protocol

| Surface | Path prefix |
|---------|-------------|
| ARM account | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}` |
| ARM listKeys | `POST` the account path plus `/listKeys` |
| Blob | `/blob/{account}/...` (Host `{account}.blob.core.windows.net` rewrites onto this prefix) |
| Queue | `/queue/{account}/...` |
| Table | `/table/{account}/...` (see [table.md](table.md)) |

Auth: ARM account CRUD uses Bearer. Blob/queue/table use `Authorization: SharedKey ...`, SAS query HMAC, or Entra Bearer with Storage data roles. Well-known Azurite `devstoreaccount1` key refused on non-loopback listen.

Container and blob list default to JSON (`{"containers":[...]}` / `{"blobs":[...]}`) for lab curl parsers. Azure `EnumerationResults` XML is returned when the request has `restype=container` or `restype=service` with `comp=list`, `Accept: application/xml` / `text/xml`, or an `x-ms-version` header with `comp=list` / those restypes (stock `az storage` / SDKs). Content type does not skip auth: Shared Key, SAS, or Entra Storage data roles still apply before the body is written.

## Authz / authn

- ARM storage account: token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- Global Bearer middleware skips `/blob/`, `/queue/`, and `/table/` when the request already carries Shared Key or SAS so handlers can verify HMAC. That skip is intentional (not an unauthenticated open path).
- Shared Key Lite-shaped HMAC-SHA256: Verb, Content-MD5, Content-Type, Date (`x-ms-date` preferred), canonicalized `x-ms-*` headers, path
- SAS query HMAC-SHA256 of `sp`, `st`, `se`, and path with the same account key. `se` is expiry (expired or unparseable is denied). `sp` is permissions (GET blob needs `r`, list needs `l`, PUT needs `w`/`c`/`a`, DELETE needs `d`; Create Table needs `c`). Shared Key missing/unknown account is HTTP 404 `AccountNotFound`. SAS unknown account or garbage `sig` is HTTP 403 `AuthenticationFailed`. Table entity paths are `/table/{account}/{table}/{pk}/{rk}` (not OData `Tables('…')`); SAS verifies against that entity path
- Entra Bearer on blob/queue/table: `aud` `https://storage.azure.com` (or ARM theatre / root) plus Storage Blob / Queue / Table data roles (Azure published GUIDs: Blob Data Owner/Contributor/Reader, Queue Data Contributor/Reader, Table Data Contributor/Reader). Owner/Contributor/Reader alone do not authorize data-plane read/write
- `listKeys` authorizes `Microsoft.Storage/storageAccounts/listKeys/action` on the account resource id from the URL, `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}`. Owner is allowed. Reader is denied. The body is that subscription, resource group, and name's account key (`key1` and `key2` both carry the one stored key). The wrong resource group, a missing name, or the same name in another subscription is HTTP 404 and does not return the other account's key
- A storage account name already stored on any other subscription or resource group is HTTP 409. Putting the same account again updates it and keeps its key
- Blob, queue, and table lookup by account name is HTTP 404 when the name is missing or stored on more than one account. That 404 does not build an RBAC scope on the default subscription, so a data role there does not return bytes for a name that is not in the store. Shared Key for one account name does not read a different account name
- Account keys sealed at rest

## Detailed actions

- Create storage account (sealed account key; `primaryEndpoints` for blob/queue/table). Names are unique across subscriptions
- List account keys (`listKeys`) for the subscription, resource group, and name in the URL
- List containers; create/delete container; put/get/list/delete blobs
- Create queue; enqueue; peek (`peekonly=true`); dequeue with optional `visibilitytimeout`

## Not implemented

- Files, Data Lake Gen2 hierarchical namespace depth
- Azurite multi-port drop-in (`10000`/`10001`/`10002`) as default
- Soft delete / immutability policies
- Object replication / block blob commit stages beyond put-as-block theatre

## Emulator limits

- Single HTTP port path prefixes by default; optional Host rewrite for `*.blob.core.windows.net` (and queue/table siblings) onto those prefixes
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
