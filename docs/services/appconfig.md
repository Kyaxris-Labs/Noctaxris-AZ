# App Configuration

ARM configuration store CRUD plus data-plane key-values under `/appconfig/{store}/kv`.

## Status

**lab** — Store create/get/list/delete; key-value GET/PUT/list.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT`/`GET`/`DELETE` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.AppConfiguration/configurationStores/{name}` |
| `GET` | `.../configurationStores` (list by RG) |
| `PUT`/`GET` | `/appconfig/{store}/kv/{key}` |
| `GET` | `/appconfig/{store}/kv` (`?key=` optional filter) |

Optional `?label=` on KV get/put. Response fields: `key`, `label`, `value`, `etag`, `locked`.

## Authz

- `Microsoft.AppConfiguration/configurationStores/read|write|delete`
- `Microsoft.AppConfiguration/configurationStores/keyValues/read|write`

## Detailed actions

- Upsert store with `location`; endpoint property points at lab data plane
- Set and get key-values (label defaults empty)
- List key-values for a store
- Delete store removes KV rows

## Not implemented

- Feature flags / FeatureManagement schema depth
- Snapshots, revisions, geo-replication
- Customer-managed keys
- Private link

## Emulator limits

- Data plane path prefix on `:4599` (not per-store hostname)
- Labels are strings only (no label filter algebra beyond exact match on get)

## Deferred depth

- Push notifications / Event Grid
- Configuration snapshots

## Verification / CLI smoke

```bash
go test ./internal/services/appconfig/ -count=1
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
BASE="http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1/providers/Microsoft.AppConfiguration/configurationStores/cfg1"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H "Content-Type: application/json" \
  -d '{"location":"eastus"}' "$BASE?api-version=2023-03-01"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H "Content-Type: application/json" \
  -d '{"value":"v1"}' "http://127.0.0.1:4599/appconfig/cfg1/kv/my.key"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/appconfig/cfg1/kv/my.key"
```
