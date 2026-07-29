# Table Storage

Azure Table Storage lab data plane under `/table/{account}/...` with Shared Key / SAS.

## Status

**lab** — Table create/delete/list; entity insert/get/update/merge/delete; OData `$filter`/`$top` equality lite; ETag.

## Wire protocol

| Surface | Path |
|---------|------|
| List tables | `GET /table/{account}` |
| Create / delete table | `PUT` / `DELETE /table/{account}/{table}` |
| Query entities | `GET /table/{account}/{table}?$filter=...&$top=N` |
| Insert entity | `POST /table/{account}/{table}` (JSON with PartitionKey/RowKey) |
| Entity by key | `GET` / `PUT` / `MERGE` / `DELETE /table/{account}/{table}/{pk}/{rk}` |

Auth: Shared Key, SAS query (`sig`+`se`), or root Bearer. Table endpoint is also advertised on storage account `primaryEndpoints.table`.

## Detailed actions

- Create table; list tables
- Insert entity; point get; replace (`PUT`) and merge (`MERGE`)
- Query with `PartitionKey` / `RowKey` / property `eq` filters and `$top`
- Delete entity / delete table

## Not implemented

- `$batch` / changeset transactions
- Full OData operators (`ge`, `le`, `and`/`or` nesting beyond simple `eq`)
- Continuation tokens / server-side pagination cursors
- Geo-replication / premium tables

## Emulator limits

- Same HTTP listener as blob/queue (path prefix, not separate table host)
- Soft filters are equality-only

## Deferred depth

- Full Azure Tables REST matrix and Azurite table port drop-in

## Verification / CLI smoke

```bash
# After creating a storage account and obtaining the lab account key:
# SharedKey PUT /table/{account}/{table}
# SharedKey POST entity JSON to /table/{account}/{table}
curl -fsS http://127.0.0.1:4599/_noctaxris-az/ready
```
