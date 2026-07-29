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
- Data plane connection string / SAS (key sealed at rest)

## Detailed actions

- Create namespace (sealed SAS key)
- Create queue
- AMQP send and receive with lock theatre

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
