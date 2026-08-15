# Event Hubs

Status: **lab**

## Detailed actions

- ARM CRUD for namespaces, event hubs, and consumer groups
- HTTP message enqueue/dequeue under `/eventhubs/{ns}/hubs/{hub}/messages`

## Not implemented

- Kafka capture; Schema Registry; full AMQP SDK parity (HTTP lab is primary)

## CLI smoke

```bash
curl -H "Authorization: Bearer $ROOT_TOKEN" -H "Content-Type: application/json" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"
```

## Deferred depth

Richer AMQP entity mapping and Kafka remain deferred.
