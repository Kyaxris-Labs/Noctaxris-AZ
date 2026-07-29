# Operations

Durable single-host lab ops for Noctaxris-AZ. This is not a multi-tenant HA guide.

## Single API replica

Run **one** Noctaxris-AZ API process against a given data root (Compose named volume or host path). Do not scale replicas against the same `state.db`. Multi-instance access is unsupported and can corrupt SQLite state.

## Listen and example roots

Process HTTP listen is loopback only for `localhost`, `127.0.0.0/8`, and `::1`. Port-only (`:4599`), `0.0.0.0`, and `::` are non-loopback and require TLS or `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1` (Compose sets the opt-in for the in-container `0.0.0.0` bind; host publish stays `127.0.0.1:4599`). The same rule applies to `NOCTAXRIS_AZ_AMQP_LISTEN`.

The shipped `docker/.env.example` root pair is allowed on loopback listen only. Startup refuses that pair when listen is non-loopback, including default Compose. Copy `.env.example` to `.env` and replace both root values with unique lab credentials before `compose up`.

## Master key

Default `NOCTAXRIS_AZ_MASTER_KEY_FILE` is outside `NOCTAXRIS_AZ_DATA_ROOT` (sibling `…/noctaxris-az-secrets/master.key`). Startup refuses a master key under the data root unless `NOCTAXRIS_AZ_ALLOW_MASTER_KEY_IN_DATA_ROOT=1`. Without `master.key`, sealed columns cannot be decrypted even if `state.db` is restored.

## Backup and restore

1. Stop the API so writers are idle.
2. Archive data and secrets volumes (or the host data root plus master key path). Minimum set: `master.key`, `state.db`, blob trees under the data root, and `audit.jsonl` when present.
3. Restore into empty volumes or a fresh host path, confirm the files exist, then start.

## Published images

Docker Hub image: **`kyaxris/noctaxris-az`** (canonical GitHub repo `Kyaxris-Labs/Noctaxris-AZ`).

| Tags | Source |
|------|--------|
| `0.x.y`, `0.x`, `0`, `latest`, `sha-<short>` | Tag push `v*` when release workflow secrets are configured (see [release.md](release.md)) |
| Local / CI | `docker build -f docker/Dockerfile .` when Dockerfile is present |

Repository secrets for Hub publish (never commit): `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`. Product version: file `VERSION`, OCI label when set at build, and open probe `GET /_noctaxris-az/version`.

## Image upgrades

1. Stop the API / Compose.
2. Take a backup (above).
3. Pull a Hub tag (`docker pull kyaxris/noctaxris-az:0.1.0`) or rebuild.
4. Start and confirm `/_noctaxris-az/ready` returns ready (optional: `/_noctaxris-az/version`).

Schema changes are additive (`CREATE TABLE IF NOT EXISTS`). There is no down-migration.

## Health vs ready

| Probe | Path | Meaning |
|-------|------|---------|
| Liveness | `GET /_noctaxris-az/health` | Process accepts HTTP |
| Readiness | `GET /_noctaxris-az/ready` | SQLite reachable |
| Version | `GET /_noctaxris-az/version` | Product version string |

## Nested engine (opt-in)

From `docker/`:

```bash
docker compose -f compose.yaml -f compose.engine.yaml --env-file .env up --build
```

Sets `NOCTAXRIS_AZ_DOCKER_HOST=tcp://noctaxris-az-engine:2376` and mounts engine TLS
certs into the API. Engine ports stay on the Compose network (no host `2375`/`2376`).
Never mount host `docker.sock`. If restricted DinD cannot start nested containers on
your host, add `-f compose.engine-privileged.yaml`.

Optional lab HTTPS for Terraform `azurerm` metadata discovery:

```bash
export NOCTAXRIS_AZ_TLS_CERT=/path/to/cert.pem
export NOCTAXRIS_AZ_TLS_KEY=/path/to/key.pem
```

## CI matrix

When GitHub Actions are present, expect unit tests, image build, and vulnerability scan jobs on PRs. Nested DinD remains opt-in and is not required for default green CI.

## Compose overlays (lab opt-in)

Default `docker/compose.yaml` stays loopback-published and nested engine off. Use overlays only when nested compute is needed.

| Overlay | When |
|---------|------|
| `docker/compose.engine.yaml` | Opt-in restricted DinD (`noctaxris-az-engine`). Sets `NOCTAXRIS_AZ_DOCKER_HOST` / `NOCTAXRIS_AZ_DOCKER_CERT_PATH`. No host publish of 2375/2376. Never mounts host `docker.sock` |
| `docker/compose.engine-privileged.yaml` | Restricted DinD cannot start nested containers (Desktop/WSL edge cases). Privileged DinD is a host workaround, not the secure default. Keep publish on `127.0.0.1:4599` |
