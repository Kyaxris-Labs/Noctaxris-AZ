# Services

Implemented lab surface on `127.0.0.1:4599` (HTTP) and `127.0.0.1:5672` (AMQP lite). Status **lab** means CLI/SDK-usable with honest emulator limits on each page.

| Service | Status | Doc | Protocol |
|---------|--------|-----|----------|
| Microsoft Entra ID | lab | [entra.md](entra.md) | OIDC/JWKS; v1/v2 token on tenant/`common`/`organizations`; lab OIDC token mint; Graph directory lists and `POST /servicePrincipals`; device code lite; WIF vs private_key_jwt with FIC bound to `client_id`; Conditional Access at token mint (`AADSTS53003`, include-list scoped); `client_credentials` requires secret or assertion; Graph `addPassword` / `addKey` / owners gated by owner or Application Administrator (`directoryScopeId`) |
| Managed Identity | lab | [managedidentity.md](managedidentity.md) | User + system-assigned ARM; IMDS theatre |
| Subscriptions / resource groups | lab | [subscriptions.md](subscriptions.md) | ARM list/get subscriptions, tenants, MGs, ARG, subscription-scope LISTs |
| Authorization (RBAC) | lab | [authorization.md](authorization.md) | Role assignments PUT/GET/LIST/DELETE; group expansion; extra built-in GUIDs |
| Key Vault | lab | [keyvault.md](keyvault.md) | Secrets/keys/certificates (exportable PKCS#8 as same-name secret) + soft-delete theatre |
| Storage | lab | [storage.md](storage.md) | Blob + queue Shared Key HMAC / SAS HMAC |
| Table Storage | lab | [table.md](table.md) | Entity CRUD + OData lite |
| Cosmos DB | lab | [cosmos.md](cosmos.md) | NoSQL in-process point read/query; change-feed current documents |
| Azure SQL | lab | [azuresql.md](azuresql.md) | Server ARM + connection theatre |
| PostgreSQL | lab | [postgres.md](postgres.md) | Flexible server ARM + theatre |
| Redis | lab | [rediscache.md](rediscache.md) | Cache ARM + theatre |
| ACR | lab | [acr.md](acr.md) | Registry ARM + theatre; AcrPull GUID mapped; no Registry V2 |
| Service Bus | lab | [servicebus.md](servicebus.md) | Queues/topics + AMQP lite |
| Event Hubs | lab | [eventhubs.md](eventhubs.md) | Namespaces/hubs + HTTP messages (root); captured-events list/get for Reader |
| Event Grid | lab | [eventgrid.md](eventgrid.md) | Topics + allowlisted egress delivery |
| Virtual Network | lab | [network.md](network.md) | VNet ARM lite |
| NSG / NIC | lab | [nsg.md](nsg.md) / [nic.md](nic.md) | ARM lite |
| Virtual Machines | lab | [virtualmachines.md](virtualmachines.md) | Lifecycle theatre |
| AKS | lab | [aks.md](aks.md) | Cluster + kubeconfig theatre |
| DNS / LB / App Gateway | lab | [dns.md](dns.md) / [loadbalancer.md](loadbalancer.md) / [appgateway.md](appgateway.md) | ARM lite |
| App Configuration | lab | [appconfig.md](appconfig.md) | KV + feature flags + captured-KV snapshots |
| Azure Functions | lab | [functions.md](functions.md) | ARM + mock invoke |
| App Service / Container Apps / Logic / APIM | lab | [appservice.md](appservice.md) / [containerapps.md](containerapps.md) / [logic.md](logic.md) / [apim.md](apim.md) | Control-plane lite |
| Front Door / Email / OpenAI / SignalR | lab | [frontdoor.md](frontdoor.md) / [email.md](email.md) / [openai.md](openai.md) / [signalr.md](signalr.md) | Edge/AI theatre |
| Monitor / Log Analytics | lab | [monitor.md](monitor.md) | Activity Log (`$top` default 1000) + workspace query for Reader + KQL subset + diagnostic settings store |

Default tenant: `00000000-0000-0000-0000-000000000001` (`NOCTAXRIS_AZ_TENANT_ID`).
Default subscription: `00000000-0000-0000-0000-000000000002` (`NOCTAXRIS_AZ_SUBSCRIPTION_ID`).

## Emulator limits (summary)

Per-service deferred depth lives on each page. Shared gaps:

- Bearer required on ARM and Graph (health/ready/version, Entra token/discovery/JWKS, lab OIDC `/_noctaxris-az/oidc-lab`, and IMDS token are public). SOAP `/provisioningwebservice.svc` is not public. ARM control-plane `aud` must be `https://management.azure.com` or `https://management.core.windows.net`. Key Vault data plane, Storage Shared Key/SAS, table/blob, and Event Hubs HTTP data plane do not use that ARM `aud`.
- Root principal bypasses RBAC evaluation (lab operator)
- No host `docker.sock`; nested DinD opt-in via `compose.engine.yaml`
- AMQP is Service Bus queue send/receive lite (not full broker parity)
- Functions invoke is in-process mock by default
- Event Grid open-internet delivery requires `NOCTAXRIS_AZ_HTTP_EGRESS=1` + allowlist

## Nested DinD

Default `docker run` / Compose leave `NOCTAXRIS_AZ_DOCKER_HOST` empty. Opt-in nested engine uses TLS DinD only. See [security-defaults.md](../security-defaults.md) and [ops.md](../ops.md).
