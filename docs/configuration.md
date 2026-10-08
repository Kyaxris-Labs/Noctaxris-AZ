# Configuration

All settings use the `NOCTAXRIS_AZ_*` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `NOCTAXRIS_AZ_LISTEN` | `127.0.0.1:4599` | API bind address (HTTPS when TLS is on) |
| `NOCTAXRIS_AZ_AMQP_LISTEN` | `127.0.0.1:5672` | Service Bus AMQP lite bind |
| `NOCTAXRIS_AZ_DATA_ROOT` | `/var/lib/noctaxris-az` | SQLite + object blobs + audit |
| `NOCTAXRIS_AZ_MASTER_KEY_FILE` | sibling `…-secrets/master.key` | 32-byte ChaCha20-Poly1305 key path (outside data root) |
| `NOCTAXRIS_AZ_TLS_CERT` | empty | Optional TLS certificate PEM (pair with `NOCTAXRIS_AZ_TLS_KEY`) |
| `NOCTAXRIS_AZ_TLS_KEY` | empty | Optional TLS private key PEM |
| `NOCTAXRIS_AZ_TLS_AUTO` | unset / false | Mint lab CA + `listen.crt` / `listen.key` under the secrets dir and serve TLS on the main listener. Stock Compose sets `1`. |
| `NOCTAXRIS_AZ_PUBLIC_URL` | empty | Client-facing origin for OIDC `iss`, `/metadata/endpoints`, and ARM resource-manager URLs (no trailing slash required). Stock Compose sets `https://127.0.0.1:4599`. When unset, wildcard listen hosts rewrite to loopback. |
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
| `NOCTAXRIS_AZ_LAB_FORENSICS` | unset / false | Enable `POST /_noctaxris-az/lab/clock:freeze`, `:unfreeze`, `:set`, and `POST /_noctaxris-az/lab/bulkSeed` (Bearer root). Lab clock is in-memory on the HTTP server. Activity Log, Log Analytics `TimeGenerated`, and ARG inject timestamps follow it. Bearer expiry stays wall clock. Default off returns AccessDenied. See [services/monitor.md](services/monitor.md). |
| `NOCTAXRIS_AZ_ACTIVITY_INJECT` | unset / false | Enable `POST /_noctaxris-az/lab/activityLog:inject` into the same store `az monitor activity-log` lists. Bearer root. Default off returns AccessDenied. |
| `NOCTAXRIS_AZ_LOGS_INJECT` | unset / false | Enable `POST /_noctaxris-az/lab/logs:inject` and `POST /loganalytics/{workspace}/ingest/{table}`. Bearer root. Default off returns AccessDenied. |
| `NOCTAXRIS_AZ_DEFENDER_INJECT` | unset / false | Enable `POST /_noctaxris-az/lab/securityAssessments:inject` into ARG `SecurityResources`. Bearer root. Default off returns AccessDenied. |
| `NOCTAXRIS_AZ_STRIP_PRODUCT` | unset / false | When `1` or `true`, expose only `/_lab/health`, `/_lab/ready`, and `/_lab/version` (product `/_noctaxris-az/health|ready|version` are not registered), use generic `Lab` display names for subscription/tenant/Graph/AAD/SOAP, and mint the lab CA as `Lab CA` / Org `Lab`. Default keeps `/_noctaxris-az/health|ready|version`, display name `Noctaxris-AZ Lab`, and CA `Noctaxris-AZ Lab CA` / Org `Noctaxris-AZ`. Recreate the data root (or subscription row) to refresh seeded display names. Binary `healthcheck` follows the same ready path. |

## HTTP auth

Discovery, JWKS, token, device code, `POST /device`, lab OIDC discovery/JWKS/token (`/_noctaxris-az/oidc-lab/*`, intentional public WIF assertion mint), health/ready/version (`/_noctaxris-az/…` by default, or `/_lab/…` when `NOCTAXRIS_AZ_STRIP_PRODUCT=1`), lab CA PEM (`/_noctaxris-az/ca.pem` or `/_lab/ca.pem`), anonymous `GET /metadata/endpoints`, and IMDS token skip Bearer. IMDS still requires `Metadata: true`, a known managed identity, and a loopback or link-local peer (RFC1918 peers are denied even when Host is the metadata address). `POST /provisioningwebservice.svc` does not skip Bearer; send a directory Bearer (`aud` `https://graph.microsoft.com` or `https://graph.windows.net`). Graph rejects tokens whose `aud` is ARM (`https://management.azure.com`, `https://management.core.windows.net`) or the token `iss`. ARM control-plane routes reject Graph `aud` (HTTP 403 `InvalidAuthenticationTokenAudience`). Key Vault data plane requires vault `aud` (`https://vault.azure.net`) plus data-plane RBAC. Storage `/blob|/queue|/table` skip the global Bearer envelope when the request already has `SharedKey` or SAS so handlers verify HMAC; Entra Bearer on those paths needs storage `aud` plus Storage Blob / Queue / Table data roles (Owner/Contributor alone do not authorize). Event Hubs HTTP send/receive accept root or Event Hubs Data Sender / Receiver / Data Owner; captured-events accept root or Data Receiver / Data Owner. Graph and SOAP do not require ARM `aud`. Root Bearer skips audience. Cloud-hosts TLS (`NOCTAXRIS_AZ_CLOUD_HOSTS=1`) enforces Host/SNI against the AzureCloud lab SAN list.

Azure CLI and azure-core based SDKs refuse Bearer tokens over cleartext HTTP. Prefer `NOCTAXRIS_AZ_TLS_AUTO=1` (or explicit `NOCTAXRIS_AZ_TLS_CERT` / `NOCTAXRIS_AZ_TLS_KEY`), set `NOCTAXRIS_AZ_PUBLIC_URL` to the HTTPS origin clients use, download the lab CA from `GET …/ca.pem`, and trust it before `az cloud register` / `az login`.

## Compose

When `docker/compose.yaml` is present it typically sets:

- `NOCTAXRIS_AZ_LISTEN=0.0.0.0:4599`
- `NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1`
- `NOCTAXRIS_AZ_TLS_AUTO=1`
- `NOCTAXRIS_AZ_PUBLIC_URL=https://127.0.0.1:4599`
- `NOCTAXRIS_AZ_DATA_ROOT=/var/lib/noctaxris-az`
- `NOCTAXRIS_AZ_MASTER_KEY_FILE=/var/lib/noctaxris-az-secrets/master.key`
- Host publish `127.0.0.1:4599:4599` and `127.0.0.1:5672:5672` (AMQP lite always published on stock Compose)
- Volumes: data + secrets
- `read_only: true` and `tmpfs: /tmp`
- No `docker.sock`
- No nested engine (leave `NOCTAXRIS_AZ_DOCKER_HOST` unset)

Copy `docker/.env.example` to `docker/.env` and replace the example root pair
before starting. Startup refuses that pair on the non-loopback container bind.

## Client endpoints

Stock Compose and the TLS-auto path use `https://127.0.0.1:4599`. Cleartext `http://` remains available only when TLS is off (not usable by Azure CLI / azure-core Bearer clients).

| Client | How to point at the lab |
|--------|-------------------------|
| curl / raw HTTPS | `https://127.0.0.1:4599` + lab CA (`/_noctaxris-az/ca.pem`) + `Authorization: Bearer <token>` |
| Azure CLI | Trust the lab CA, then `az cloud register` against `https://127.0.0.1:4599` (resource-manager, active-directory, microsoft-graph). Prefer discovery via anonymous `/metadata/endpoints`, or pass `--skip-endpoint-discovery` with explicit endpoints. Login with a seeded app registration secret: `az login --service-principal -u <appId> -p <secret> --tenant <tenant>` |
| Az PowerShell | `Add-AzEnvironment` with HTTPS endpoints, then `Connect-AzAccount -Environment ... -ServicePrincipal ...` |
| Storage SDK | account endpoint `https://127.0.0.1:4599/blob/{account}` (Shared Key HMAC, SAS HMAC with `se`/`sp`, or Entra Bearer + Storage data roles) |
| Key Vault SDK | vault base `https://127.0.0.1:4599/keyvault/{name}` + Bearer |
| Service Bus | AMQP `amqp://127.0.0.1:5672` (stock Compose always publishes this port) with signed SAS on attach; HTTP messages need Service Bus `aud` + data roles |
| App Configuration | data plane `https://127.0.0.1:4599/appconfig/{store}` + Bearer |
| Functions mock invoke | `POST https://127.0.0.1:4599/functions/{name}/invoke` + Bearer |
| Monitor / Activity Log | ARM paths under `/subscriptions/.../providers/Microsoft.Insights/...` + Bearer |
| Microsoft Graph PowerShell | `Add-MgEnvironment` with HTTPS Graph/AAD endpoints, then `Connect-MgGraph -Environment ...` |
| Host/SNI AzureCloud | Optional second listener: `NOCTAXRIS_AZ_CLOUD_HOSTS=1` on `127.0.0.1:8443` |
| Lab inject flags | Process env (default off): `NOCTAXRIS_AZ_LAB_FORENSICS`, `NOCTAXRIS_AZ_ACTIVITY_INJECT`, `NOCTAXRIS_AZ_LOGS_INJECT`, `NOCTAXRIS_AZ_DEFENDER_INJECT`. Bearer root required. |

## Official CLI and PowerShell recipes

Learn flag names: `az cloud register` uses `--endpoint-resource-manager`, `--endpoint-active-directory`, `--endpoint-microsoft-graph-resource-id`, `--skip-endpoint-discovery`. Az.Accounts uses `-ResourceManagerEndpoint`, `-ActiveDirectoryEndpoint`, `-MicrosoftGraphUrl`, `-MicrosoftGraphEndpointResourceId`. Microsoft.Graph uses `-AzureADEndpoint` and `-GraphEndpoint`.

```bash
curl -fsS -o lab-ca.pem https://127.0.0.1:4599/_noctaxris-az/ca.pem
# trust lab-ca.pem in the OS / REQUESTS_CA_BUNDLE / SSL_CERT_FILE as appropriate

az cloud register -n NoctaxrisAZ \
  --endpoint-resource-manager https://127.0.0.1:4599 \
  --endpoint-active-directory https://127.0.0.1:4599 \
  --endpoint-microsoft-graph-resource-id https://127.0.0.1:4599
az cloud set -n NoctaxrisAZ
# Prefer a seeded app registration + secret (durable session) over a static one-hour JWT:
# az login --service-principal -u "$APP_ID" -p "$SECRET" --tenant "$TENANT_ID"
```

```powershell
Add-AzEnvironment -Name NoctaxrisAZ `
  -ResourceManagerEndpoint https://127.0.0.1:4599 `
  -ActiveDirectoryEndpoint https://127.0.0.1:4599/ `
  -MicrosoftGraphUrl https://127.0.0.1:4599 `
  -MicrosoftGraphEndpointResourceId https://127.0.0.1:4599
Connect-AzAccount -Environment NoctaxrisAZ -ServicePrincipal `
  -ApplicationId $AppId -Credential $SecretCredential -Tenant $TenantId

Add-MgEnvironment -Name NoctaxrisAZ `
  -AzureADEndpoint https://127.0.0.1:4599 `
  -GraphEndpoint https://127.0.0.1:4599
Connect-MgGraph -Environment NoctaxrisAZ
```

Live `az`, AzureHound, `Connect-MgGraph`, and `prowler` runs are not executed in CI. SDK smokes skip when those binaries are missing. Main-listener TLS auto and optional Host/SNI cloud-hosts share the same lab CA file.

## Main listener TLS (`NOCTAXRIS_AZ_TLS_AUTO`)

When TLS auto is on (stock Compose), the process writes PEMs next to `master.key`:

| File | Role |
|------|------|
| `lab-ca.crt` | Lab CA (also served at `GET /_noctaxris-az/ca.pem`) |
| `listen.crt` / `listen.key` | Main API server cert (SANs include loopback plus any host from `NOCTAXRIS_AZ_PUBLIC_URL`) |

## Cloud hosts TLS

Optional second listener. Set `NOCTAXRIS_AZ_CLOUD_HOSTS=1` for `127.0.0.1:8443` (override with `NOCTAXRIS_AZ_CLOUD_HOSTS_LISTEN`). Shares `lab-ca.crt` and adds:

| File | Role |
|------|------|
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
