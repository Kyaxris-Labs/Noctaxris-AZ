# Cosmos DB

Status: **lab**

## Detailed actions

- ARM `Microsoft.DocumentDB/databaseAccounts`
- Data plane under `/cosmos/{account}/dbs/...` (database, container, point read, id equality query)
- `GET /cosmos/{account}/dbs/{db}/colls/{coll}/changefeed` returns `200` with `"Documents": []` (no version store)
- Bearer or `x-ms-cosmos-account-key` for data plane

## Not implemented

- Multi-API engines (Mongo/Cassandra/Gremlin); RU/s and multi-region

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/cosmo1"
```

## Deferred depth

Change-feed remains an empty `200` list (`"Documents": []`). A version store and live `az cosmosdb` smokes are not in this cut (soft-skip when `az` is missing).

SQL API depth beyond equality-on-id stays deferred.
