# Container Apps

Status: **lab**

## Detailed actions

- ARM CRUD for `Microsoft.App/containerApps` (lab)
- Properties stored as JSON theatre
- `GET .../containerApps/{name}/revisions` lists a theatre revision (`latestRevisionName`, `runningStatus`). `CrashLoopBackOff` / `Failed` maps to Unhealthy/inactive; default is Running/Healthy

## Not implemented

- Real revision replicas

## CLI smoke

```bash
# Requires NOCTAXRIS_AZ root Bearer and running emulator on :4599
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/.../containerApps/demo"
```

## Deferred depth

Further Azure parity beyond the lab actions above stays deferred until a later cut.
