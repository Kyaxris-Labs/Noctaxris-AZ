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
| `GET`/`POST` | `/v1.0/applications` |
| `GET`/`PATCH`/`DELETE` | `/v1.0/applications/{appId}` |

Form body: `grant_type=client_credentials` or `password` (ROPC lite), `client_id` / `username`+`password`, optional `client_secret`, `scope` or `resource`.

## Authz

Public discovery / JWKS / token. Issued JWTs authenticate subsequent ARM calls (also hashed for opaque lookup). Graph app registration routes require a Bearer principal.

## Detailed actions

- Client credentials and ROPC lite grants with RS256 access_token (`aud`/`iss`/`sub`/`oid`/`tid`/`azp`/`exp`)
- OIDC discovery document (`token_endpoint`, `jwks_uri`, `issuer`, auth methods) and JWKS (`n`/`e`/`kid`/`issuer`)
- Authenticator verifies lab JWTs after root / opaque hash lookup
- Graph-shaped app registration CRUD lite under `/v1.0/applications` (tenant from config, not path)

OIDC paths mirror the Microsoft identity platform v2 layout under the configured
tenant id (literal path segment, not a wildcard). App registration uses Graph-shaped
`/v1.0/applications`. Literal tenant + Graph paths avoid Go ServeMux conflicts with
ARM `/subscriptions/...` and storage `/blob/...`.

## Not implemented

- Authorization code / device code / on-behalf-of
- Microsoft-signed JWTs / real Microsoft identity platform
- Full Microsoft Graph (directory objects, groups, PIM, Conditional Access, MFA)

## Emulator limits

- Lab-signed JWTs only (not Microsoft-signed)
- Tenant id defaults to `NOCTAXRIS_AZ_TENANT_ID`

## Deferred depth

- Broader Graph directory CRUD beyond app registration lite

## Verification / CLI smoke

```bash
TENANT=${NOCTAXRIS_AZ_TENANT_ID:-00000000-0000-0000-0000-000000000001}
curl -fsS "http://127.0.0.1:4599/$TENANT/v2.0/.well-known/openid-configuration"
curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default"
```
