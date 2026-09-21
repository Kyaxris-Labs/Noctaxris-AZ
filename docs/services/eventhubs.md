# Event Hubs

Status: **lab**

## Authz / authn

- ARM namespace, hub, and consumer group routes use Bearer plus RBAC (`Microsoft.EventHub/...`)
- HTTP `/eventhubs/{ns}/hubs/{hub}/messages` send/receive stay root Bearer. Other directory tokens get HTTP 403. Missing Bearer is 401.
- `GET /eventhubs/{ns}/hubs/{hub}/capturedEvents` (and `.../capturedEvents/{id}`) allows root, or a principal with Reader (or Event Hubs Data Receiver) on the namespace resource group. Unauthorized directory tokens stay 403.

## Detailed actions

- ARM CRUD for namespaces, event hubs, and consumer groups
- HTTP message enqueue/dequeue under `/eventhubs/{ns}/hubs/{hub}/messages` (root Bearer)
- Enqueue copies the payload into a capture table. List/get captured events does not dequeue live messages.

## Not implemented

- Kafka capture to Blob; Schema Registry; full AMQP SDK parity (HTTP lab is primary)
- Azure Event Hubs Data Sender on the HTTP send path (send remains root)

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
```

## Deferred depth

HTTP send/receive remain root-only. Capture list is the data-plane read path for an authorized principal. Richer AMQP entity mapping and Kafka remain deferred. Live `az eventhubs` smokes skip when `az` is missing.
