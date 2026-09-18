# Event Hubs

Status: **lab**

## Detailed actions

- ARM CRUD for namespaces, event hubs, and consumer groups
- HTTP message enqueue/dequeue under `/eventhubs/{ns}/hubs/{hub}/messages`
- `GET /eventhubs/{ns}/hubs/{hub}/capturedEvents` returns `200` with `"value": []` (no capture store)

## Not implemented

- Kafka capture; Schema Registry; full AMQP SDK parity (HTTP lab is primary)

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
```

## Deferred depth

Captured-events remains an empty `200` list (`"value": []`). There is no capture store. Richer AMQP entity mapping and Kafka remain deferred. Live `az eventhubs` smokes skip when `az` is missing.
