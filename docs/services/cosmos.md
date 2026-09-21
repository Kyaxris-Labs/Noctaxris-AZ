# Cosmos DB

Status: **lab**

## Detailed actions

- ARM `Microsoft.DocumentDB/databaseAccounts`
- Data plane under `/cosmos/{account}/dbs/...` (database, container, point read, id equality query)
- `GET /cosmos/{account}/dbs/{db}/colls/{coll}/changefeed` returns current container documents as `"Documents"` (latest-version lite; no per-write history table)
- Bearer or `x-ms-cosmos-account-key` for data plane

## Not implemented

- Multi-API engines (Mongo/Cassandra/Gremlin); RU/s and multi-region
- All versions and deletes change feed; continuation tokens / leases

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmo1"
```

## Deferred depth

Continuation tokens, deletes-as-changes, and live `az cosmosdb` smokes are not in this cut (soft-skip when `az` is missing).

SQL API depth beyond equality-on-id stays deferred.
