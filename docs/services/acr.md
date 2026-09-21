# Azure Container Registry

Status: **lab**

## Wire protocol

ARM control plane stays on the usual resource-group path. Registry V2 shares HTTP `:4599` (no second port, no nested engine).

| Method | Path |
|--------|------|
| `PUT` / `GET` / `DELETE` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ContainerRegistry/registries/{name}` |
| `GET` | `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ContainerRegistry/registries` |
| `GET` / `HEAD` | `/v2/` |
| `POST` | `/v2/{name}/blobs/uploads/` |
| `PUT` | `/v2/{name}/blobs/uploads/{uuid}?digest=sha256:...` |
| `HEAD` / `GET` | `/v2/{name}/blobs/{digest}` |
| `PUT` / `HEAD` / `GET` | `/v2/{name}/manifests/{reference}` |
| `GET` / `POST` | `/oauth2/token?service=&scope=` |

`{name}` may include `/` (nested repositories). Blob and manifest bodies live in SQLite (`acr_blobs`, `acr_uploads`, `acr_manifests`). There is no host `docker.sock` and no DinD daemon.

## Authz

Missing Bearer on `/v2/` and `/oauth2/token` is HTTP 401 with `WWW-Authenticate: Bearer realm="http://{host}/oauth2/token",service="containerregistry.azure.net"` and `Docker-Distribution-API-Version: registry/2.0`.

Authenticated callers:

| Caller | Pull (`GET`/`HEAD`, ping) | Push (`POST` uploads, `PUT` blob/manifest) |
|--------|---------------------------|--------------------------------------------|
| Root Bearer | yes | yes |
| AcrPull (`7f951dda-4ed3-4680-a7ca-43fe172d538d`) | yes (`registries/pull/read`, `registries/read`) | no |
| Reader (and other `*/read` roles) | yes | no |
| Contributor / Owner | yes | yes (`registries/push/write`, `registries/write`) |

ARM evaluation uses the registry resource id when an ARM row matches. Match order: `{name}.azurecr.io` / `{name}.containerregistry.azure.net` Host, then the first repository path segment. PUT the ARM registry first if you want that scoped id. When no row matches, evaluation uses `/subscriptions/{id}` (`NOCTAXRIS_AZ_SUBSCRIPTION_ID` unless the handler overrides it). Graph `aud` is HTTP 403 `DENIED`. Directory ARM Bearer is accepted on V2 (same token as ARM CRUD).

`GET /oauth2/token` (and `POST`) is optional docker-login theatre. A valid root, ARM, or ACR Bearer (or Basic where the password is that token) returns `token` / `access_token` as an RS256 lab JWT (`aud` `https://containerregistry.azure.net`). `/v2/` accepts that JWT. RBAC still runs on each V2 call; the JWT `scope` query string does not grant push.

## Detailed actions

- ARM CRUD for `Microsoft.ContainerRegistry/registries` with JSON properties theatre
- Monolithic blob upload (`POST` then `PUT ?digest=`) and manifest put/get by tag or digest
- AcrPull and Reader pull-only on V2

## Not implemented

- `_catalog` / tag list APIs
- Chunked `PATCH` blob uploads
- Nested engine image build or host Docker socket

## CLI smoke

```bash
# Requires NOCTAXRIS_AZ root Bearer and running emulator on :4599
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  -X PUT -d '{"location":"eastus"}' \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/demo?api-version=2023-07-01"

curl -i http://127.0.0.1:4599/v2/
# 401 WWW-Authenticate Bearer realm=... service=containerregistry.azure.net

curl -H "Authorization: Bearer $ROOT_TOKEN" http://127.0.0.1:4599/v2/
# 200 {}
```

## Deferred depth

Geo-replication, retention policies, and admin-user passwords stay out of this cut. Live `az acr` / `docker login` against a TLS login host is optional operator smoke.
