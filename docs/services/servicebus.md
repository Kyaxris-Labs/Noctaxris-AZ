# Service Bus

ARM namespace / queue lite plus AMQP 1.0 send/receive for `azservicebus` clients.

## Status

**lab** — Namespace and queue CRUD; AMQP lite on `127.0.0.1:5672` with connection string / SAS.

## Wire protocol

| Method | Path / endpoint |
|--------|-----------------|
| ARM | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{name}` |
| Queues | `.../namespaces/{name}/queues/{queue}` |
| AMQP | `amqp://127.0.0.1:5672` |

## Authz / authn

- ARM Bearer + RBAC
- `GET .../namespaces/{name}/connectionString` requires `Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action` (not namespace `read`). Reader is denied; Owner / Contributor / root succeed.
- AMQP (`:5672`) and HTTP message paths use different authn mechanisms by design:
  - AMQP attach requires a signed `SharedAccessSignature` token (HMAC over `sr`/`se` with the namespace key). Bare `SharedAccessKey` property equality is rejected. A connection string may supply key material that the lite client uses to mint a short-lived SAS for attach; verification always uses the sealed namespace key from the store.
  - HTTP `/servicebus/.../messages` requires Service Bus `aud` (`https://servicebus.azure.net`) plus Service Bus data roles (Data Owner / Sender / Receiver) or root. Graph or any-Bearer alone is denied. Owner/Contributor do not grant HTTP send/receive.
- Entra Bearer is not accepted on AMQP lite; SAS is not accepted on the HTTP message routes.

## Detailed actions

- Create namespace (sealed SAS key)
- Create queue
- AMQP send and receive with lock theatre (SAS required on attach)

## Not implemented

- Topics / subscriptions / sessions depth
- Premium messaging units
- Geo-disaster recovery
- Full AMQP management node surface

## Emulator limits

- Loopback AMQP only by default
- Queue-centric lite (not full broker parity)

## Deferred depth

- Event Hubs compatible AMQP
- JMS / Spring binders

## Verification / CLI smoke

```bash
TOKEN=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN
SUB=$NOCTAXRIS_AZ_SUBSCRIPTION_ID
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
  -H "Content-Type: application/json" \
  -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourcegroups/rg1/providers/Microsoft.ServiceBus/namespaces/sb1?api-version=2021-11-01"
# Point azservicebus at amqp://127.0.0.1:5672 with the lab connection string
```
