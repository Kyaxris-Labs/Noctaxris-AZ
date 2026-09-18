# AKS

Status: **lab**

## Authz

- Bearer required. Token `aud` must be `https://management.azure.com` or `https://management.core.windows.net` (Graph `aud` is HTTP 403 `InvalidAuthenticationTokenAudience`). Root Bearer skips audience.

## Detailed actions

- ARM CRUD for `Microsoft.ContainerService/managedClusters` (lab)
- Properties stored as JSON theatre

## Not implemented

- Full k3s parity when engine unset; production CNI

## CLI smoke

```bash
# Requires NOCTAXRIS_AZ root Bearer and running emulator on :4599
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/.../managedClusters/demo"
```

## Deferred depth

Further Azure parity beyond the lab actions above stays deferred until a later cut.
