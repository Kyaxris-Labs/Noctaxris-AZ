# Event Hubs

Status: **lab**

## Authz / authn

- ARM namespace, hub, and consumer group routes use Bearer plus RBAC (`Microsoft.EventHub/...`)
- HTTP `/eventhubs/{ns}/hubs/{hub}/messages` send requires Event Hubs or ARM `aud`, then root or Event Hubs Data Sender / Data Owner (`send/action`). Receive requires root or Event Hubs Data Receiver / Data Owner (`receive/action`). Owner/Contributor alone are denied. Missing Bearer is 401. Authz missing for non-root is 403.
- `GET /eventhubs/{ns}/hubs/{hub}/capturedEvents` (and `.../capturedEvents/{id}`) requires Event Hubs or ARM `aud`, then root or Event Hubs Data Receiver / Data Owner (`receive/action`) on each matching namespace resource group. Captured payloads are keyed by the ARM namespace id, so receive on one resource group does not list events from a same-named namespace in another RG. Graph `aud` and Subscription Reader are denied. Unauthorized directory tokens stay 403.

## Detailed actions

- ARM CRUD for namespaces, event hubs, and consumer groups
- HTTP message enqueue/dequeue under `/eventhubs/{ns}/hubs/{hub}/messages` (root or dedicated Event Hubs data roles)
- Enqueue copies the payload into a capture table. List/get captured events does not dequeue live messages.

## Not implemented

- Kafka capture to Blob; Schema Registry; full AMQP SDK parity (HTTP lab is primary)

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
```

## Deferred depth

Richer AMQP entity mapping and Kafka remain deferred. Live `az eventhubs` smokes skip when `az` is missing.
