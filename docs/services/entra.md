# Microsoft Entra ID

Lab Entra token theatre for client credentials against the shared HTTP listener.

## Status

**lab** — `POST /{tenant}/oauth2/v2.0/token` returns an access token for known lab clients; no real Microsoft identity platform.

## Wire protocol

| Method | Path |
|--------|------|
| `POST` | `/{tenantId}/oauth2/v2.0/token` |

Form body: `grant_type=client_credentials`, `client_id`, `client_secret`, `scope` (optional).

## Authz

Public (no Bearer). Issued tokens authenticate subsequent ARM calls when registered.

## Detailed actions

- Client credentials grant theatre
- Token hash stored for non-root principals when minted by lab flows

## Not implemented

- Authorization code / device code / ROPC / on-behalf-of
- Real JWT signature verify against Microsoft JWKS
- Microsoft Graph beyond token minting
- Conditional Access, MFA, PIM

## Emulator limits

- Tokens are lab opaque / theatre strings, not Microsoft-signed JWTs
- Tenant id defaults to `NOCTAXRIS_AZ_TENANT_ID`

## Deferred depth

- Full OpenID Connect discovery and JWKS
- App registration CRUD beyond env root client

## Verification / CLI smoke

```bash
TENANT=$NOCTAXRIS_AZ_TENANT_ID
curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$NOCTAXRIS_AZ_ROOT_CLIENT_ID&client_secret=$NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN"
```
