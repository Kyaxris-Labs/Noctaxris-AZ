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
| `NOCTAXRIS_AZ_CLOUD_HOSTS` | unset / false | Second TLS listener with AzureCloud SANs (`login.microsoftonline.com`, `graph.microsoft.com`, `management.azure.com`, and related hosts) |
| `NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN` | `127.0.0.1:8443` when cloud hosts is on | Cloud-hosts TLS bind. Keep loopback unless `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1` |
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
| Azure CLI | `az rest` / ARM against `http://127.0.0.1:4599` with Bearer, or `az cloud register` (`--endpoint-resource-manager`, `--endpoint-active-directory`, `--endpoint-microsoft-graph-resource-id`, `--skip-endpoint-discovery`; see README) |
| Storage SDK | account endpoint `http://127.0.0.1:4599/blob/{account}` (Shared Key / SAS) |
| Key Vault SDK | vault base `http://127.0.0.1:4599/keyvault/{name}` + Bearer |
| Service Bus | AMQP `amqp://127.0.0.1:5672` with connection string / SAS |
| App Configuration | data plane `http://127.0.0.1:4599/appconfig/{store}` + Bearer |
| Functions mock invoke | `POST http://127.0.0.1:4599/functions/{name}/invoke` + Bearer |
| Monitor / Activity Log | ARM paths under `/subscriptions/.../providers/Microsoft.Insights/...` + Bearer |
| Microsoft Graph PowerShell | `Add-MgEnvironment` then `Connect-MgGraph -AccessToken` |
| Host/SNI AzureCloud | `NOCTAXRIS_AZ_CLOUD_HOSTS=1` on `127.0.0.1:8443`; HTTP `:4599` stays the default |

## Cloud hosts TLS

HTTP `:4599` remains the default. Set `NOCTAXRIS_AZ_CLOUD_HOSTS=1` to start a second listener on `127.0.0.1:8443` (override with `NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN`). The process writes a lab CA and server cert into the secrets directory next to `master.key`:

| File | Role |
|------|------|
| `lab-ca.crt` | Lab CA (install this if a client verifies TLS) |
| `cloud-hosts.crt` | Server cert with AzureCloud DNS SANs plus `127.0.0.1` / `::1` |
| `cloud-hosts.key` | Server private key (mode `0600`; do not commit) |

Generate the same PEMs without starting the API:

```bash
go run ./scripts/generatelabca ./lab-ca
```

Wrappers: `scripts/generate-lab-ca.sh` and `scripts/generate-lab-ca.ps1`. Output belongs in a local directory (`./lab-ca` is gitignored). Never commit private keys.

`IssuerBase` in cloud-hosts mode is `https://login.microsoftonline.com` so clients that pin that host see a matching `iss`.

### Redirect 443 to 8443

Windows (loopback only):

```bat
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=443 connectaddress=127.0.0.1 connectport=8443
```

Linux (loopback example):

```bash
sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 443 -j REDIRECT --to-ports 8443
```

### Hosts file

Mapping `login.microsoftonline.com`, `graph.microsoft.com`, or `management.azure.com` to `127.0.0.1` hijacks those names for every process on the machine, including real Microsoft sign-in. Use a dedicated lab VM or a tool-specific hosts override. Remove the entries when the lab is done.

### Install the lab CA

Windows: import `lab-ca.crt` into "Trusted Root Certification Authorities" for the lab user or local machine. Linux: copy it into `/usr/local/share/ca-certificates/` and run `update-ca-certificates` (Debian/Ubuntu) or the distro equivalent. Trust this CA only on lab hosts.

## Data layout

| Path | Contents |
|------|----------|
| `$DATA_ROOT/state.db` | SQLite lab state |
| `$DATA_ROOT/blobs/` | Storage blob bytes |
| `$DATA_ROOT/audit.jsonl` | Audit trail when enabled |
| sibling `…-secrets/master.key` | AEAD master key (outside data root) |
