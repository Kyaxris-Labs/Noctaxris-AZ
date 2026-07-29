# Services

Implemented lab surface on `127.0.0.1:4599` (HTTP) and `127.0.0.1:5672` (AMQP lite). Status **lab** means CLI/SDK-usable with honest emulator limits on each page.

| Service | Status | Doc | Protocol |
|---------|--------|-----|----------|
| Microsoft Entra ID | lab | [entra.md](entra.md) | OAuth2 client credentials theatre `/{tenant}/oauth2/v2.0/token` |
| Subscriptions / resource groups | lab | [subscriptions.md](subscriptions.md) | ARM subscriptions + resourceGroups CRUD lite |
| Authorization (RBAC) | lab | [authorization.md](authorization.md) | Role assignments CRUD lite |
| Key Vault | lab | [keyvault.md](keyvault.md) | ARM vault + data plane secrets/keys |
| Storage | lab | [storage.md](storage.md) | Blob + queue Shared Key / SAS |
| Service Bus | lab | [servicebus.md](servicebus.md) | ARM namespace/queue + AMQP send/receive lite |
| App Configuration | lab | [appconfig.md](appconfig.md) | ARM stores + data plane `/appconfig/{store}/kv` |
| Azure Functions | lab | [functions.md](functions.md) | ARM Function App CRUD lite + mock invoke |
| Monitor / Activity Log | lab | [monitor.md](monitor.md) | Activity Log list + metrics theatre |

Default tenant: `00000000-0000-0000-0000-000000000001` (`NOCTAXRIS_AZ_TENANT_ID`).
Default subscription: `00000000-0000-0000-0000-000000000002` (`NOCTAXRIS_AZ_SUBSCRIPTION_ID`).

## Emulator limits (summary)

Per-service deferred depth lives on each page. Shared gaps:

- Bearer required on ARM / Key Vault / Monitor / App Configuration / Functions (health/ready/version and Entra token are public)
- Root principal bypasses RBAC evaluation (lab operator)
- No host `docker.sock`; nested DinD opt-in only when Compose engine overlay is present
- AMQP is queue send/receive lite for Service Bus (not full broker parity)
- Functions invoke is in-process mock only

## Nested DinD

Default `docker run` / Compose leave `NOCTAXRIS_AZ_DOCKER_HOST` empty. Opt-in nested engine (when `compose.engine.yaml` is present) uses TLS DinD only. See [security-defaults.md](../security-defaults.md).
