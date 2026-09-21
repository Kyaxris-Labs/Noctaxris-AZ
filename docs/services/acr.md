# Azure Container Registry

Status: **lab**

## Detailed actions

- ARM CRUD for `Microsoft.ContainerRegistry/registries` (lab)
- Properties stored as JSON theatre
- The AcrPull built-in GUID (`7f951dda-4ed3-4680-a7ca-43fe172d538d`) is recognized by ARM RBAC for `registries/read` and `registries/pull/read`

## Not implemented

- Registry V2 (`/v2/` docker pull/push) without nested DinD. Assigning AcrPull does not start a registry daemon.

## CLI smoke

```bash
# Requires NOCTAXRIS_AZ root Bearer and running emulator on :4599
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/demo?api-version=2023-07-01"
```

## Deferred depth

Registry V2 data plane stays deferred until nested engine work lands. ARM CRUD and the AcrPull GUID map are what this cut ships.
