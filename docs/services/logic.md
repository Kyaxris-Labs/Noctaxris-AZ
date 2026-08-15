# Logic Apps

Status: **lab**

## Detailed actions

- ARM CRUD for `Microsoft.Logic/workflows` (lab)
- Properties stored as JSON theatre

## Not implemented

- Designer / connector runtime

## CLI smoke

```bash
# Requires NOCTAXRIS_AZ root Bearer and running emulator on :4599
curl -H "Authorization: Bearer $ROOT_TOKEN" \
  "http://127.0.0.1:4599/subscriptions/$SUB/resourceGroups/rg/providers/.../workflows/demo"
```

## Deferred depth

Further Azure parity beyond the lab actions above stays deferred until a later cut.
