<p align="center">
  <img src="assets/noctaxris_az_bg.png" alt="Noctaxris-AZ" width="640">
</p>

<p align="center">
  <b>Run Azure-shaped security labs on your laptop without a cloud bill or a host Docker socket.</b>
</p>

```bash
docker pull kyaxris/noctaxris-az:latest
# Container bind is 0.0.0.0; generate unique roots (shipped example pair is refused).
ROOT_ID="$(openssl rand -hex 16)"
ROOT_TOKEN="$(openssl rand -hex 32)"
docker run -d --name noctaxris-az -p 127.0.0.1:4599:4599 -p 127.0.0.1:5672:5672 \
  -e NOCTAXRIS_AZ_LISTEN=0.0.0.0:4599 \
  -e NOCTAXRIS_AZ_AMQP_LISTEN=0.0.0.0:5672 \
  -e NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1 \
  -e NOCTAXRIS_AZ_ROOT_CLIENT_ID="$ROOT_ID" \
  -e NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN="$ROOT_TOKEN" \
  kyaxris/noctaxris-az:latest
curl http://127.0.0.1:4599/_noctaxris-az/health
# ok
```

<p align="center">
  <a href="https://github.com/Kyaxris-Labs/Noctaxris-AZ/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Kyaxris-Labs/Noctaxris-AZ/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://hub.docker.com/r/kyaxris/noctaxris-az"><img src="https://img.shields.io/docker/pulls/kyaxris/noctaxris-az" alt="Docker pulls"></a>
  <a href="https://hub.docker.com/r/kyaxris/noctaxris-az/tags"><img src="https://img.shields.io/docker/v/kyaxris/noctaxris-az?sort=semver&label=image" alt="Docker image version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Kyaxris-Labs/Noctaxris-AZ" alt="MIT License"></a>
</p>

Point Azure clients at `http://127.0.0.1:4599` with `Authorization: Bearer <token>` (Storage Shared Key / SAS; Service Bus AMQP on `:5672`).

Go module: [`github.com/Kyaxris-Labs/Noctaxris-AZ`](https://github.com/Kyaxris-Labs/Noctaxris-AZ). Image tags: `latest`, semver releases, and Hub `kyaxris/noctaxris-az`.

## Why this exists

| | |
|---|---|
| Lab fidelity | Entra token theatre, ARM subscriptions/RGs/RBAC, Key Vault, Storage, Service Bus, App Configuration, Functions mock, Activity Log |
| Secure defaults | Loopback publish only. No host `docker.sock`. Master key outside the data root |
| Dual listeners | HTTP `:4599` plus AMQP lite `:5672` for Service Bus clients |
| Nested compute | DinD via Compose engine over TLS is opt-in when present. Default Functions invoke stays mock |

## Quick start

Pull the Hub image, run it on loopback `:4599`, then hit the subscription with the same root Bearer you passed in.

```bash
docker pull kyaxris/noctaxris-az:latest

ROOT_ID="$(openssl rand -hex 16)"
ROOT_TOKEN="$(openssl rand -hex 32)"

docker run -d --name noctaxris-az -p 127.0.0.1:4599:4599 -p 127.0.0.1:5672:5672 \
  -e NOCTAXRIS_AZ_LISTEN=0.0.0.0:4599 \
  -e NOCTAXRIS_AZ_AMQP_LISTEN=0.0.0.0:5672 \
  -e NOCTAXRIS_AZ_ALLOW_NONLOOPBACK_LISTEN=1 \
  -e NOCTAXRIS_AZ_ROOT_CLIENT_ID="$ROOT_ID" \
  -e NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN="$ROOT_TOKEN" \
  kyaxris/noctaxris-az:latest

curl http://127.0.0.1:4599/_noctaxris-az/health
curl http://127.0.0.1:4599/_noctaxris-az/ready

SUB=00000000-0000-0000-0000-000000000002
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB?api-version=2022-12-01"
```

When Compose files are present, copy `docker/.env.example` to `docker/.env`, replace both root values with unique lab credentials, then `docker compose -f docker/compose.yaml --env-file docker/.env up --build`. Default host publish is `127.0.0.1:4599` (AMQP optional). Per-service smoke: [docs/services/](docs/services/index.md).

## Services

| Area | Services |
|------|----------|
| Identity | Microsoft Entra ID, Subscriptions / resource groups, Authorization (RBAC) |
| Crypto | Key Vault |
| Data | Storage (blob, queue) |
| Messaging | Service Bus |
| App | App Configuration, Azure Functions |
| Observe | Monitor / Activity Log |

Open the service matrix for detailed actions and gaps. Full notes and CLI smoke: [docs/services/](docs/services/index.md).

<details>
<summary><b>Service matrix</b> (detailed actions / not implemented)</summary>

<table>
  <thead>
    <tr>
      <th>Area</th>
      <th>Services</th>
      <th>Detailed actions</th>
      <th>Not implemented</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="3" align="center" valign="middle">Identity</td>
      <td>Microsoft Entra ID</td>
      <td>Client credentials token theatre at <code>/{tenant}/oauth2/v2.0/token</code>.</td>
      <td>Real Microsoft-signed JWTs; Graph; auth code / device code.</td>
    </tr>
    <tr>
      <td>Subscriptions / RGs</td>
      <td>Seeded subscription get; resource group create/get/list.</td>
      <td>Subscription create/delete; management groups.</td>
    </tr>
    <tr>
      <td>Authorization</td>
      <td>Role assignments CRUD lite; Owner/Contributor/Reader evaluation; root bypass.</td>
      <td>Custom roles; deny assignments; PIM.</td>
    </tr>
    <tr>
      <td align="center" valign="middle">Crypto</td>
      <td>Key Vault</td>
      <td>Vault ARM lite; sealed secrets/keys on data plane Bearer paths.</td>
      <td>Certificates; managed HSM; soft-delete timers.</td>
    </tr>
    <tr>
      <td align="center" valign="middle">Data</td>
      <td>Storage</td>
      <td>Account ARM lite; blob put/get; queue send/receive; Shared Key + SAS.</td>
      <td>Tables/Files/HNS depth; Azurite multi-port drop-in default.</td>
    </tr>
    <tr>
      <td align="center" valign="middle">Messaging</td>
      <td>Service Bus</td>
      <td>Namespace/queue ARM; AMQP lite send/receive on <code>:5672</code>.</td>
      <td>Topics/sessions premium depth; Event Hubs.</td>
    </tr>
    <tr>
      <td rowspan="2" align="center" valign="middle">App</td>
      <td>App Configuration</td>
      <td>Store CRUD; data plane <code>/appconfig/{store}/kv</code> GET/PUT.</td>
      <td>Feature flags depth; snapshots; geo-replication.</td>
    </tr>
    <tr>
      <td>Azure Functions</td>
      <td>Function App CRUD lite; <code>POST /functions/{name}/invoke</code> mock response.</td>
      <td>Real workers; Kudu; nested runtime default.</td>
    </tr>
    <tr>
      <td align="center" valign="middle">Observe</td>
      <td>Monitor / Activity Log</td>
      <td>Activity Log list; metrics POST/GET theatre.</td>
      <td>Log Analytics KQL; alert evaluation; App Insights ingest.</td>
    </tr>
  </tbody>
</table>

</details>

## Security posture

| Control | Default |
|---------|---------|
| Listen | `127.0.0.1:4599` and `127.0.0.1:5672` |
| Host `docker.sock` | Never |
| Master key | Outside data root |
| Auth | Bearer (ARM) / Shared Key+SAS (Storage) / connection string (Service Bus) |
| AuthZ | Azure RBAC; deny by default; root bypass documented |

Details: [docs/security-defaults.md](docs/security-defaults.md). Configuration: [docs/configuration.md](docs/configuration.md).

## Docs and tests

| | |
|---|---|
| Docs index | [docs/index.md](docs/index.md) |
| Services | [docs/services/index.md](docs/services/index.md) |
| Integration suites | [tests/README.md](tests/README.md) (soft-skip when `NOCTAXRIS_AZ_ENDPOINT` unset) |

## Contributors

Thanks to everyone contributing on [GitHub](https://github.com/Kyaxris-Labs/Noctaxris-AZ/graphs/contributors).

## License

[MIT](LICENSE)
