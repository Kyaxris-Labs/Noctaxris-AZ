# Event Grid

Status: **lab**

## Authz / authn

- ARM topics and subscriptions: ARM `aud` plus RBAC
- Publish `POST /eventgrid/{topic}/api/events`: Event Grid `aud` (`https://eventgrid.azure.net`) plus Event Grid Data Sender (`topics/send/action`), or root. Graph or any-Bearer alone is denied.

## Detailed actions

- ARM topics and event subscriptions
- `POST /eventgrid/{topic}/api/events` publish
- Delivery only when `NOCTAXRIS_AZ_HTTP_EGRESS=1` and destination is allowlisted. Redirects are denied. DNS hostnames that resolve to private, loopback, link-local, or metadata addresses are denied (literal IPs and dial-time pin).

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
