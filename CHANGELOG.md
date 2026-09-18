# Changelog

## Unreleased

- Conditional Access: Graph POST/GET `/identity/conditionalAccess/policies`. Enabled policies run at token mint (`includeApplications` vs `client_id`, exclude wins, User-Agent include / non-enum `clientAppTypes` prefix). Deny is OAuth `invalid_grant` with `AADSTS53003` and `BlockedByConditionalAccess`. Disabled policies are skipped.
- App Configuration snapshots copy the live KV set (labels included). Later KV writes do not change snapshot reads. List snapshots. Read with `?label=` or `GET /kv?snapshot=`.
- Key Vault certificates: GET certificate stays public `cer`. Exportable policy publishes PKCS#8 PEM as the same-name secret. GET secret without exportable is denied.
- Workload identity federation: `claimsMatchingExpression` `{value, languageVersion}` with `eq`, `matches` (`*` / `?`), and `and`. Exact `subject` still matches when the expression is empty.
- Graph `addPassword`, `addKey`, and `owners/$ref` succeed for application owners and Application Administrator (template `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`). Other principals are denied. Root Bearer still provisions. Audience check is unchanged.
- Toolchain: Go 1.27.1. Digest-pinned `golang:1.27.1-bookworm`, `docker:29-dind`, `busybox:1.37`, and distroless `static-debian12:nonroot`. CI govulncheck `v1.8.0`. Go modules refreshed. Nested Engine stays `github.com/moby/moby/client`. Lab alpine pin is `alpine:3.23` (`alpine:3.20` and `docker:27-dind` remain allowlisted).
- Management group descendants load `{id}` and that group's `tenant_id`. Unknown or foreign-tenant ids return 404 and do not list every subscription. Direct child groups are included; same-tenant subscriptions appear under the tenant-root group only.
- Activity Log list (`GET .../eventtypes/management/values`) returns events for the subscription in the path (`resourceId` prefix), not every row stamped with that id. `POST /loganalytics/{workspace}/ingest/{table}` is off unless `NOCTAXRIS_AZ_LOGS_INJECT=1` and the caller is Bearer root (same gate as `POST /_noctaxris-az/lab/logs:inject`).
- Graph `addKey` proof is RS256-verified against stored app/SP key PEMs (`nbf`/`exp`). First key may omit proof. `PATCH` `keyCredentials` after a key exists requires the same proof.
- Unknown Graph POST under `/v1.0` and `/beta` returns 404 and does not mutate `addPassword`, `addKey`, owners, or members from substring path matches.
- Graph `DELETE /applications/{id}` and owners `$ref` use directory object id. Client id in that slot returns 404. `POST /servicePrincipals/{appId}/owners/$ref` does not write application owners.
- `POST /provisioningwebservice.svc` requires Bearer (directory read). The path is not public.
- Graph rejects lab JWTs whose `aud` is ARM or the token issuer. ARM control-plane `require` helpers (subscriptions, AKS, VMs, Storage accounts, Key Vault vaults, network, and other provider CRUD) reject Graph `aud` with HTTP 403 `InvalidAuthenticationTokenAudience`. Hash lookup still reads `aud` from the JWT. Key Vault data plane, Storage Shared Key/SAS, table/blob, Event Hubs HTTP data plane, Graph, and SOAP do not require ARM `aud`.
- Storage blob/queue/table SAS: HMAC-SHA256 of `sp`, `st`, `se`, and path against the account key. `se` is expiry (expired or unparseable denied). `sp` permissions are enforced. Missing account, unknown account, or garbage `sig` is HTTP 403. Shared Key HMAC is unchanged.
- Event Hubs HTTP send/receive and captured-events require root Bearer. Other directory tokens get HTTP 403 (captured-events is no longer a 200 empty list for those callers). Missing Bearer is 401.
- Lab clock on the HTTP server (`clockMu` / `clockOverride`): `POST /_noctaxris-az/lab/clock:freeze`, `:unfreeze`, `:set`, and `POST /_noctaxris-az/lab/bulkSeed` (`suspicious-signin`, `blob-exfil`, `crypto-mining`) behind `NOCTAXRIS_AZ_LAB_FORENSICS` (default off, Bearer root). Activity Log, Log Analytics `TimeGenerated`, and ARG inject timestamps use the lab clock. Bearer expiry stays wall clock.
- Activity Log inject (`NOCTAXRIS_AZ_ACTIVITY_INJECT`), named Log Analytics table inject (`NOCTAXRIS_AZ_LOGS_INJECT`), and ARG `SecurityResources` assessment inject (`NOCTAXRIS_AZ_DEFENDER_INJECT`): default off, Bearer root, batch cap 50, secret-like JSON keys redacted
- Diagnostic settings ARM CRUD lite (`Microsoft.Insights/diagnosticSettings`, api-version `2021-05-01-preview`); PUT and DELETE append Activity Log; settings store only (no export pipeline)
- Log Analytics KQL subset: `take`, `where Col == 'x'`, `TimeGenerated` range with `datetime()`, `project` of stored columns (not full Azure Monitor)
- Entra client-credentials and IMDS token mint append redacted sign-in rows (`AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`)
- Container Apps revision list; Cosmos change-feed returns an empty `200` list (no version store). Event Hubs captured-events empty `200` is root Bearer only (see above).
- Client recipes: `az cloud register` (`--endpoint-resource-manager`, `--endpoint-active-directory`, `--endpoint-microsoft-graph-resource-id`, `--skip-endpoint-discovery`); Az PowerShell `Add-AzEnvironment` (`-ResourceManagerEndpoint`, `-ActiveDirectoryEndpoint`, `-MicrosoftGraphUrl`, `-MicrosoftGraphEndpointResourceId`); `Add-MgEnvironment` (`-AzureADEndpoint`, `-GraphEndpoint`). Live `az` / AzureHound / `Connect-MgGraph` / `prowler` not executed; smokes soft-skip
- Entra: login/token/JWKS/AAD Graph on literal tenant aliases (`NOCTAXRIS_AZ_TENANT_ID`, `common`, `organizations`) so ServeMux no longer panics against Graph `/v1.0/{path...}`
- Entra: device code lite auto-succeeds on token exchange; refresh tokens hashed once with `authn.HashToken`; WIF `client_assertion` from lab OIDC issuer `/_noctaxris-az/oidc-lab`; OBO `jwt-bearer` rejected
- Graph: directory lists; `addPassword` one-time `secretText` + `keyId`; owners/members `$ref`; FIC create 201 with default audience `api://AzureADTokenExchange`; unknown collections return empty `value`
- ARM: `GET /subscriptions` list vs `GET /subscriptions/{id}` get (`api-version` required); `GET /tenants`; ARG `Resources` / `SecurityResources`; subscription-scope LISTs query full ARM types such as `Microsoft.Compute/virtualMachines`
- Cloud hosts TLS stays opt-in (`NOCTAXRIS_AZ_CLOUD_HOSTS`, listen `127.0.0.1:8443`, lab CA next to `master.key`); HTTP `:4599` remains the default

## 1.0.2

Patch after 1.0.1: ARM accepts Resource Groups REST `resourcegroups` on nested provider routes. Docker Hub: `kyaxris/noctaxris-az` (`1.0.2`, `1.0`, `1`, `latest`). Cut steps: [docs/release.md](docs/release.md).

- ARM: canonicalize `resourcegroups` to `resourceGroups` so Go ServeMux matches Storage, Key Vault, and other provider paths (Resource Groups PUT uses lowercase; resource IDs use camelCase)

## 1.0.1

Patch after 1.0.0: Go 1.26.6 for stdlib govulncheck findings. Docker Hub: `kyaxris/noctaxris-az` (`1.0.1`, `1.0`, `1`, `latest`). Cut steps: [docs/release.md](docs/release.md).

- Toolchain: Go 1.26.6 (clears GO-2026-5026, GO-2026-5942, GO-2026-5972, GO-2026-6089, GO-2026-6090, GO-2026-6218)

## 1.0.0

First major release after the hybrid lab-complete surface (identity, storage, messaging, nested data/compute theatre, edge/AI labs, Hub release CI). Docker Hub: `kyaxris/noctaxris-az` (`1.0.0`, `1.0`, `1`, `latest`). Cut steps: [docs/release.md](docs/release.md).

### Identity and crypto

- Entra ROPC lite and app registration CRUD lite (alongside client credentials JWT)
- Managed Identity system-assigned theatre; IMDS prefers sole system-assigned when `client_id` unset
- Key Vault certificates lite; App Configuration feature flags and snapshots lite
- Service Bus session/dead-letter theatre on queue messages

### Messaging

- Service Bus topics and subscriptions with HTTP fan-out lab
- Event Hubs namespaces/hubs/consumer groups with HTTP message lab
- Event Grid topics/subscriptions; publish; delivery via allowlisted HTTP egress only

### Data platforms

- Cosmos DB NoSQL in-process (account ARM, databases/containers, point read/query lite)
- Azure SQL, PostgreSQL, Redis, ACR ARM control plane with connection theatre (DinD-on-Create when `NOCTAXRIS_AZ_DOCKER_HOST` set)

### Network and compute

- Virtual Network, NSG, NIC, DNS, Load Balancer, Application Gateway ARM lite
- Virtual Machines lifecycle theatre
- AKS managed cluster ARM with kubeconfig theatre

### App, edge, and observe

- API Management, App Service (staticSites path), Container Apps, Logic Apps control-plane lite
- Front Door/CDN profiles, ACS Email capture (`/emails:send`), SignalR negotiate theatre
- Cognitive / Azure OpenAI allowlisted canned chat completions (unknown models fail-closed)
- Log Analytics workspaces with KQL subset (`take` / `where`) and ingest

### Testing

- Unit coverage for `./internal/...` at lab bar (~70%); PR gates remain unit + image + govulncheck (coverage profiles are local-only)

### Fixed

- Entra OIDC mounts the configured tenant as a literal path (and Graph apps under `/v1.0/applications`) so ServeMux no longer panics against ARM `/subscriptions/...` or storage `/blob/...`

## 0.2.0

Minor after 0.1.0: nested TLS DinD overlay and image pull allowlist, Table Storage lab, Entra OIDC/JWKS plus Managed Identity theatre, Key Vault soft-delete, Moby Engine client, Syft SBOM in CI, and Docker Hub publish gated on required CI. Docker Hub: `kyaxris/noctaxris-az` (`0.2.0`, `0.2`, `0`, `latest`). Cut steps: [docs/release.md](docs/release.md).

### Nested compute and security defaults

- Nested TLS DinD overlay (`docker/compose.engine.yaml` + privileged overlay), image pull allowlist (`NOCTAXRIS_AZ_IMAGE_PULL_ALLOWLIST`), and compose tests that reject host `docker.sock` on engine files
- Nested compute client migrates from `github.com/docker/docker` to `github.com/moby/moby/client` v0.5.1 (`client.New`); govulncheck allowlist drops Fixed-N/A Engine IDs that tracked the legacy module
- Release: `v*` tag publish runs `ci-required.yml` (unit, compose-static, govulncheck, race, image, smoke-core) and pushes to Docker Hub only when those gates succeed; nightly `docker-nightly.yml` for `nightly` / `nightly-YYYYMMDD` / `sha-*` (does not move `latest` or semver)
- CI adds Syft SBOM for the API image; bump lab deps (`modernc.org/sqlite` v1.55.0)

### Identity and control plane

- Entra OIDC discovery + JWKS + RS256 lab JWTs; Managed Identity ARM + IMDS token theatre; role-assignment list-by-scope; subscriptions resources/providers lite
- Key Vault secret soft-delete/recover (immediate lab timers)

### Storage and data plane

- Table Storage lab under `/table/{account}/...` (create/list/delete tables; insert/query/get/replace/merge/delete entities; Shared Key / SAS / root Bearer)
- Blob list/delete containers and blobs; queue peek and optional visibility timeout on dequeue; ARM `primaryEndpoints` includes `table`
- Soft-skip SDK/Terraform coverage for table and IMDS when `NOCTAXRIS_AZ_ENDPOINT` is set

## 0.1.0

Bootstrap Azure-shaped lab emulator: loopback HTTP `:4599`, AMQP lite `:5672`, Entra token theatre, ARM subscriptions/resource groups/RBAC, Key Vault, Storage blob/queue (Shared Key + SAS), Service Bus, App Configuration, Functions mock invoke, Activity Log / Monitor lite. Secure defaults match Noctaxris siblings (no host docker.sock, master key outside data root, distroless nonroot).
