# Services

Implemented lab surface on `127.0.0.1:4599` (HTTP) and `127.0.0.1:5672` (AMQP lite). Status **lab** means CLI/SDK-usable with honest emulator limits on each page.

| Service | Status | Doc | Protocol |
|---------|--------|-----|----------|
| Microsoft Entra ID | lab | [entra.md](entra.md) | OIDC/JWKS; client credentials + ROPC; app registration lite |
| Managed Identity | lab | [managedidentity.md](managedidentity.md) | User + system-assigned ARM; IMDS theatre |
| Subscriptions / resource groups | lab | [subscriptions.md](subscriptions.md) | ARM subscriptions + resourceGroups lite |
| Authorization (RBAC) | lab | [authorization.md](authorization.md) | Role assignments CRUD + list-by-scope |
| Key Vault | lab | [keyvault.md](keyvault.md) | Secrets/keys/certificates + soft-delete theatre |
| Storage | lab | [storage.md](storage.md) | Blob + queue Shared Key / SAS |
| Table Storage | lab | [table.md](table.md) | Entity CRUD + OData lite |
| Cosmos DB | lab | [cosmos.md](cosmos.md) | NoSQL in-process point read/query |
| Azure SQL | lab | [azuresql.md](azuresql.md) | Server ARM + connection theatre |
| PostgreSQL | lab | [postgres.md](postgres.md) | Flexible server ARM + theatre |
| Redis | lab | [rediscache.md](rediscache.md) | Cache ARM + theatre |
| ACR | lab | [acr.md](acr.md) | Registry ARM + theatre |
| Service Bus | lab | [servicebus.md](servicebus.md) | Queues/topics + AMQP lite |
| Event Hubs | lab | [eventhubs.md](eventhubs.md) | Namespaces/hubs + HTTP messages |
| Event Grid | lab | [eventgrid.md](eventgrid.md) | Topics + allowlisted egress delivery |
| Virtual Network | lab | [network.md](network.md) | VNet ARM lite |
| NSG / NIC | lab | [nsg.md](nsg.md) / [nic.md](nic.md) | ARM lite |
| Virtual Machines | lab | [virtualmachines.md](virtualmachines.md) | Lifecycle theatre |
| AKS | lab | [aks.md](aks.md) | Cluster + kubeconfig theatre |
| DNS / LB / App Gateway | lab | [dns.md](dns.md) / [loadbalancer.md](loadbalancer.md) / [appgateway.md](appgateway.md) | ARM lite |
| App Configuration | lab | [appconfig.md](appconfig.md) | KV + feature flags + snapshots |
| Azure Functions | lab | [functions.md](functions.md) | ARM + mock invoke |
| App Service / Container Apps / Logic / APIM | lab | [appservice.md](appservice.md) / [containerapps.md](containerapps.md) / [logic.md](logic.md) / [apim.md](apim.md) | Control-plane lite |
| Front Door / Email / OpenAI / SignalR | lab | [frontdoor.md](frontdoor.md) / [email.md](email.md) / [openai.md](openai.md) / [signalr.md](signalr.md) | Edge/AI theatre |
| Monitor / Log Analytics | lab | [monitor.md](monitor.md) | Activity Log + KQL subset |

Default tenant: `00000000-0000-0000-0000-000000000001` (`NOCTAXRIS_AZ_TENANT_ID`).
Default subscription: `00000000-0000-0000-0000-000000000002` (`NOCTAXRIS_AZ_SUBSCRIPTION_ID`).

## Emulator limits (summary)

Per-service deferred depth lives on each page. Shared gaps:

- Bearer required on ARM (health/ready/version, Entra token/discovery/JWKS, and IMDS token are public)
- Root principal bypasses RBAC evaluation (lab operator)
- No host `docker.sock`; nested DinD opt-in via `compose.engine.yaml`
- AMQP is Service Bus queue send/receive lite (not full broker parity)
- Functions invoke is in-process mock by default
- Event Grid open-internet delivery requires `NOCTAXRIS_AZ_HTTP_EGRESS=1` + allowlist

## Nested DinD

Default `docker run` / Compose leave `NOCTAXRIS_AZ_DOCKER_HOST` empty. Opt-in nested engine uses TLS DinD only. See [security-defaults.md](../security-defaults.md) and [ops.md](../ops.md).
