# Configuration

All settings use the `NOCTAXRIS_AZ_*` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `NOCTAXRIS_AZ_LISTEN` | `127.0.0.1:4599` | HTTP bind address |
| `NOCTAXRIS_AZ_AMQP_LISTEN` | `127.0.0.1:5672` | Service Bus AMQP lite bind |
| `NOCTAXRIS_AZ_DATA_ROOT` | `/var/lib/noctaxris-az` | SQLite + object blobs + audit |
| `NOCTAXRIS_AZ_MASTER_KEY_FILE` | sibling `…-secrets/master.key` | 32-byte ChaCha20-Poly1305 key path (outside data root) |
| `NOCTAXRIS_AZ_TLS_CERT` | empty | Optional TLS certificate PEM |
| `NOCTAXRIS_AZ_TLS_KEY` | empty | Optional TLS private key PEM |
| `NOCTAXRIS_AZ_ROOT_CLIENT_ID` | required at startup | Root principal / app client id |
| `NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN` | required at startup | Root Bearer token (held in memory) |
| `NOCTAXRIS_AZ_TENANT_ID` | `00000000-0000-0000-0000-000000000001` | Lab tenant seeded by EnsureRoot |
| `NOCTAXRIS_AZ_SUBSCRIPTION_ID` | `00000000-0000-0000-0000-000000000002` | Lab subscription seeded by EnsureRoot |
| `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN` | unset / false | Permit non-loopback HTTP/AMQP without TLS (Compose) |
| `NOCTAXRIS_AZ_ALLOW_MASTER_KEY_IN_DATA_ROOT` | unset / false | Permit master key under data root |
| `NOCTAXRIS_AZ_DOCKER_HOST` | empty | Nested DinD engine URL. Empty disables nested compute. Rejects `unix://`, `npipe://`, and `docker.sock`. |
| `NOCTAXRIS_AZ_DOCKER_CERT_PATH` | empty | Directory with `ca.pem`, `cert.pem`, and `key.pem` for engine TLS. Required whenever Docker host is set. |

## Compose

When `docker/compose.yaml` is present it typically sets:

- `NOCTAXRIS_AZ_LISTEN=0.0.0.0:4599`
- `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1`
- `NOCTAXRIS_AZ_DATA_ROOT=/var/lib/noctaxris-az`
- `NOCTAXRIS_AZ_MASTER_KEY_FILE=/var/lib/noctaxris-az-secrets/master.key`
- Host publish `127.0.0.1:4599:4599` (AMQP publish optional)
- Volumes: data + secrets
- `read_only: true` and `tmpfs: /tmp`
- No `docker.sock`
- No nested engine (leave `NOCTAXRIS_AZ_DOCKER_HOST` unset)

Copy `docker/.env.example` to `docker/.env` and replace the example root pair
before starting. Startup refuses that pair on the non-loopback container bind.

## Client endpoints

| Client | How to point at the lab |
|--------|-------------------------|
| curl / raw HTTP | `http://127.0.0.1:4599` + `Authorization: Bearer <token>` |
| Azure CLI | `az rest` / ARM against `http://127.0.0.1:4599` with Bearer |
| Storage SDK | account endpoint `http://127.0.0.1:4599/blob/{account}` (Shared Key / SAS) |
| Key Vault SDK | vault base `http://127.0.0.1:4599/keyvault/{name}` + Bearer |
| Service Bus | AMQP `amqp://127.0.0.1:5672` with connection string / SAS |
| App Configuration | data plane `http://127.0.0.1:4599/appconfig/{store}` + Bearer |
| Functions mock invoke | `POST http://127.0.0.1:4599/functions/{name}/invoke` + Bearer |
| Monitor / Activity Log | ARM paths under `/subscriptions/.../providers/Microsoft.Insights/...` + Bearer |

## Data layout

| Path | Contents |
|------|----------|
| `$DATA_ROOT/state.db` | SQLite lab state |
| `$DATA_ROOT/blobs/` | Storage blob bytes |
| `$DATA_ROOT/audit.jsonl` | Audit trail when enabled |
| sibling `…-secrets/master.key` | AEAD master key (outside data root) |
