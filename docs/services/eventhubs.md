# Event Hubs

Status: **lab**

## Authz / authn

- ARM namespace, hub, and consumer group routes use Bearer plus RBAC (`Microsoft.EventHub/...`)
- HTTP `/eventhubs/{ns}/hubs/{hub}/messages` and `capturedEvents` require root Bearer. Azure Event Hubs Data Sender / Receiver / Owner are not assigned in this lab, so any other directory token is HTTP 403. Missing Bearer is 401.

## Detailed actions

- ARM CRUD for namespaces, event hubs, and consumer groups
- HTTP message enqueue/dequeue under `/eventhubs/{ns}/hubs/{hub}/messages` (root Bearer)
- `GET /eventhubs/{ns}/hubs/{hub}/capturedEvents` returns `200` with `"value": []` for root (no capture store). Other directory Bearer tokens get `403`. Missing Bearer is `401`.

## Not implemented

- Kafka capture; Schema Registry; full AMQP SDK parity (HTTP lab is primary)

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
```

## Deferred depth

Captured-events remains an empty `200` list (`"value": []`) for root Bearer. There is no capture store. Other directory tokens cannot send, receive, or list captured events (HTTP 403). Azure Event Hubs Data Sender / Receiver / Owner role GUIDs are not in the lab RBAC catalogue yet, so data-plane HTTP is root-only rather than any minted access token. Richer AMQP entity mapping and Kafka remain deferred. Live `az eventhubs` smokes skip when `az` is missing.
