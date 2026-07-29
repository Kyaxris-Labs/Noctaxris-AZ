# Azure Functions

ARM Function App (`Microsoft.Web/sites` kind `functionapp`) CRUD lite plus in-process mock invoke.

## Status

**lab** — Create/get/list/delete Function App; `POST /functions/{name}/invoke` returns configured `labMockResponse`.

## Wire protocol

| Method | Path |
|--------|------|
| `PUT`/`GET`/`DELETE` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}` |
| `GET` | `.../providers/Microsoft.Web/sites` (list by RG) |
| `POST` | `/functions/{name}/invoke` |

Set `properties.labMockResponse` on create (JSON string or plain text). Invoke returns that body when valid JSON; otherwise wraps as `{"result":"..."}`.

## Authz

- `Microsoft.Web/sites/read|write|delete`
- `Microsoft.Web/sites/functions/write` for invoke

## Detailed actions

- Upsert Function App metadata (`kind=functionapp`)
- Store mock response for invoke theatre
- Delete removes the app row

## Not implemented

- Real workers, Kudu, deployment slots
- Consumption / Premium plans
- Event Grid / Service Bus trigger wiring
- Nested DinD function hosts (default is mock)

## Emulator limits

- Invoke is in-process only (`engine` mock)
- No host `docker.sock`

## Deferred depth

- Nested runtime via opt-in DinD
- Durable Functions orchestration

## Verification / CLI smoke

```bash
go test ./internal/services/functions/ -count=1
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
BASE="http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1/providers/Microsoft.Web/sites/fn1"
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H "Content-Type: application/json" \
  -d '{"location":"eastus","kind":"functionapp","properties":{"labMockResponse":"{\"ok\":true}"}}' \
  "$BASE?api-version=2022-03-01"
curl -s -H "Authorization: Bearer $TOKEN" -X POST \
  "http://127.0.0.1:4599/functions/fn1/invoke" -d '{}'
```
