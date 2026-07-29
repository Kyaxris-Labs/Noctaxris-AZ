# Security defaults

Noctaxris-AZ fails closed. Defaults favor a loopback lab on a single laptop.

## Network

| Setting | Default | Notes |
|---------|---------|-------|
| HTTP listen | `127.0.0.1:4599` | Non-loopback without TLS requires `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1` |
| AMQP listen | `127.0.0.1:5672` | Non-loopback requires the same allow opt-in |
| Compose publish | `127.0.0.1:4599` (and optional AMQP) | Container bind may be `0.0.0.0` with the opt-in above |
| Host Docker socket | never mounted | Nested DinD is opt-in only via `docker/compose.engine.yaml` when present |

## Nested engine (opt-in)

- Empty `NOCTAXRIS_AZ_DOCKER_HOST` disables nested compute. Unit tests and default
  Compose stay green without Docker / DinD.
- Never mount host `/var/run/docker.sock` on the API service. Runtime rejects
  `unix://`, `npipe://`, and any host string containing `docker.sock`.
- Opt-in overlay (when shipped) starts a restricted DinD engine over TLS and sets
  `NOCTAXRIS_AZ_DOCKER_HOST` plus `NOCTAXRIS_AZ_DOCKER_CERT_PATH`. The engine API
  is not published to the host.

## Authentication

| Surface | Credential |
|---------|------------|
| ARM / RBAC / Key Vault / Monitor / App Configuration / Functions | `Authorization: Bearer <token>` |
| Storage blob / queue | Shared Key (`SharedKey <account>:<sig>`), SAS query, or connection string |
| Service Bus AMQP lite | Connection string / SAS |

- Root token comes from `NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN` and maps to `NOCTAXRIS_AZ_ROOT_CLIENT_ID`.
- Other tokens are SHA-256 hashed and looked up in `access_tokens`.
- Missing or invalid credentials return Azure ARM `AuthenticationFailed` (HTTP 401).
- Public paths: `/_noctaxris-az/health`, `/_noctaxris-az/ready`, `/_noctaxris-az/version`,
  and Entra `POST /{tenant}/oauth2/v2.0/token` (client credentials theatre).

## Example root refusal

The pair shipped in `docker/.env.example` is refused when listen is non-loopback
(Compose container bind). Generate unique roots before `compose up`.
Well-known Azurite `devstoreaccount1` credentials are likewise refused on
non-loopback listen.

## Authorization

- Azure RBAC role assignments are stored per scope in SQLite.
- Deny by default.
- The authenticated root principal bypasses RBAC evaluation. This matches lab
  operator convenience in the AWS/GCP sibling products and is intentional.
  Documented here so CTF authors do not treat root as a normal app registration.
- Built-in Owner / Contributor / Reader role definition IDs are recognized.
  Contributor cannot mutate role assignments. Reader is read-only.

## Secrets at rest

- Master key file defaults to a sibling path outside the data root
  (`…/noctaxris-az-secrets/master.key`).
- ChaCha20-Poly1305 seals storage account keys, Key Vault secret/key material,
  and Service Bus SAS keys.
- Compose mounts a dedicated secrets volume and runs the API with `read_only: true`
  when Compose is present.

## Container

- Distroless `nonroot` (UID 65532) when the image is built.
- No host `docker.sock`.
- Healthcheck uses the binary (`noctaxris-az healthcheck`), not curl.

## Vulnerability scan (govulncheck)

- CI installs `govulncheck` at a pinned module version (not `@latest`) and runs
  `go run ./scripts/govulncheck-ci`, which fails on any symbol-reachable finding
  whose OSV ID is not listed in `scripts/govulncheck-allowlist.txt`.
- Prefer toolchain and dependency upgrades over allowlisting. The allowlist is
  only for residuals with no module-path fix (documented when an ID is added).
- Adding `github.com/docker/docker` (Engine client SDK) surfaces Docker Engine
  CVEs with Fixed in: N/A on that module path (`GO-2026-4883`, `GO-2026-4887`,
  `GO-2026-5668`; siblings may still list `GO-2026-5617` when that ID is
  reachable). CI allowlists those IDs in
  `scripts/govulncheck-allowlist.txt` so new app vulns still fail the job.
  Noctaxris-AZ does not call `CopyToContainer` / `CopyFromContainer`; nested
  one-shots (when the engine overlay is wired) use create/start/wait/logs only.
  AuthZ-plugin bypass findings do not apply to the packaged engine path (no
  AuthZ plugins). Residual is still the nested engine binary version and who
  can talk to it over TLS on the Compose network. Re-run
  `go run ./scripts/govulncheck-ci` after bumps; add only new Fixed N/A IDs
  that appear locally.
- Go toolchain tracks a current patch (see `go.mod`); API image build stage uses
  a digest-pinned `golang` bookworm base matching that version.
