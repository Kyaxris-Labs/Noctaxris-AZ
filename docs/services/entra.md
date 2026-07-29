# Microsoft Entra ID

Lab Entra OIDC / OAuth2 theatre against the shared HTTP listener.

## Status

**lab** — Client credentials mint RS256 lab JWTs; OIDC discovery + JWKS; tokens accepted as ARM Bearer.

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/{tenantId}/v2.0/.well-known/openid-configuration` |
| `GET` | `/{tenantId}/discovery/v2.0/keys` |
| `POST` | `/{tenantId}/oauth2/v2.0/token` |

Form body: `grant_type=client_credentials`, `client_id`, optional `client_secret`, `scope` or `resource`.

## Authz

Public discovery / JWKS / token. Issued JWTs authenticate subsequent ARM calls (also hashed for opaque lookup).

## Detailed actions

- Client credentials grant with RS256 access_token (`aud`/`iss`/`sub`/`oid`/`tid`/`azp`/`exp`)
- OIDC discovery document (`token_endpoint`, `jwks_uri`, `issuer`, auth methods) and JWKS (`n`/`e`/`kid`/`issuer`)
- Authenticator verifies lab JWTs after root / opaque hash lookup

Paths mirror the Microsoft identity platform v2 layout under the lab base URL
(`/{tenant}/v2.0/.well-known/openid-configuration`, `/{tenant}/discovery/v2.0/keys`,
`/{tenant}/oauth2/v2.0/token`).

## Not implemented

- Authorization code / device code / ROPC / on-behalf-of
- Microsoft-signed JWTs / real Microsoft identity platform
- Microsoft Graph beyond token minting
- Conditional Access, MFA, PIM

## Emulator limits

- Lab-signed JWTs only (not Microsoft-signed)
- Tenant id defaults to `NOCTAXRIS_AZ_TENANT_ID`

## Deferred depth

- App registration CRUD beyond env root client
- ROPC lite when needed for interactive lab packs

## Verification / CLI smoke

```bash
TENANT=${NOCTAXRIS_AZ_TENANT_ID:-00000000-0000-0000-0000-000000000001}
curl -fsS "http://127.0.0.1:4599/$TENANT/v2.0/.well-known/openid-configuration"
curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default"
```
