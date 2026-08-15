# Changelog

## Unreleased

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
