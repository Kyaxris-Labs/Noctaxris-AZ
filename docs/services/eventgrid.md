# Event Grid

Status: **lab**

## Detailed actions

- ARM topics and event subscriptions
- `POST /eventgrid/{topic}/api/events` publish
- Delivery only when `NOCTAXRIS_AZ_HTTP_EGRESS=1` and destination is allowlisted

## Not implemented

- Advanced filters; dead-letter storage destinations

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventGrid/topics/t1"
```

## Deferred depth

Partner topics and domain delivery stay deferred.
