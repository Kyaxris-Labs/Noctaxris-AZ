# App Configuration

ARM configuration store CRUD plus data-plane key-values under `/appconfig/{store}/kv`.

## Status

**lab.** Store create/get/list/delete; key-value GET/PUT/list; feature flags; snapshots that freeze the current KV set.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT`/`GET`/`DELETE` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.AppConfiguration/configurationStores/{name}` |
| `GET` | `.../configurationStores` (list by RG) |
| `PUT`/`GET` | `/appconfig/{store}/kv/{key}` |
| `GET` | `/appconfig/{store}/kv` (`?key=` optional filter; `?snapshot=` reads a captured set) |
| `PUT`/`GET` | `/appconfig/{store}/snapshots/{name}` |
| `GET` | `/appconfig/{store}/snapshots` |

Optional `?label=` on KV get/put and on snapshot read. Response fields: `key`, `label`, `value`, `etag`, `locked`. Snapshot GET also returns `items` (the captured rows) plus `status` and `createdAt`.

## Authz

- ARM store CRUD: token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.
- `Microsoft.AppConfiguration/configurationStores/read|write|delete`
- Data plane KV / feature flags / snapshots: `Microsoft.AppConfiguration/configurationStores/keyValues/read|write` (Bearer; ARM `aud` is not required)

## Detailed actions

- Upsert store with `location`; endpoint property points at lab data plane
- Set and get key-values (label defaults empty)
- List key-values for a store
- Delete store removes KV rows
- PUT snapshot copies every current key-value, including labels. Later live PUTs do not change that snapshot. List snapshots. Read by name (`?label=` filters the captured set) or `GET /kv?snapshot=`

## Not implemented

- Feature flags / FeatureManagement schema depth
- Revisions, geo-replication
- Customer-managed keys
- Private link

## Emulator limits

- Data plane path prefix on `:4599` (not per-store hostname)
- Labels are strings only (no label filter algebra beyond exact match on get)

## Deferred depth

- Push notifications / Event Grid

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
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H "Content-Type: application/json" \
  -d '{}' "http://127.0.0.1:4599/appconfig/cfg1/snapshots/freeze1"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/appconfig/cfg1/snapshots"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/appconfig/cfg1/snapshots/freeze1"
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/appconfig/cfg1/kv?snapshot=freeze1"
```
