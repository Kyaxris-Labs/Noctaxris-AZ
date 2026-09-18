# Microsoft Entra ID

Lab Entra OIDC / OAuth2 and Microsoft Graph theatre on the shared HTTP listener (`:4599` by default). Optional cloud-hosts TLS is documented in [configuration.md](../configuration.md).

## Status

**lab.** v1 and v2 token endpoints on the configured tenant plus `common` and `organizations`; RS256 lab JWTs; Graph directory lists; AAD Graph 1.6 and SOAP ListUsers. Tokens are lab-signed, not Microsoft-signed.

## Wire protocol

| Method | Path |
|--------|------|
| `GET` | `/{tenant}/v2.0/.well-known/openid-configuration` |
| `GET` | `/{tenant}/.well-known/openid-configuration` |
| `GET` | `/{tenant}/discovery/v2.0/keys` |
| `GET` | `/{tenant}/discovery/keys` |
| `POST` | `/{tenant}/oauth2/v2.0/token` |
| `POST` | `/{tenant}/oauth2/token` |
| `POST` | `/{tenant}/oauth2/v2.0/devicecode` |
| `POST` | `/{tenant}/oauth2/devicecode` |
| `GET` | `/v1.0/` and `/beta/` Graph collections (users, groups, applications, servicePrincipals, devices, directoryRoles, organization, roleManagement, conditionalAccess) |
| `POST` | `/v1.0/applications/{id}/addPassword`, `addKey`, `owners/$ref`, `federatedIdentityCredentials` |
| `GET` | `/{tenant}/users?api-version=1.6` (AAD Graph) |
| `POST` | `/provisioningwebservice.svc` (SOAP `ListUsers`) |
| `GET` | `/api/Users` (IAM portal lite) |
| `GET` | `/_noctaxris-az/oidc-lab/.well-known/openid-configuration` |

`{tenant}` is a literal path: `NOCTAXRIS_AZ_TENANT_ID`, `common`, or `organizations`. Handlers remap `common` / `organizations` to the lab tenant. Wildcards are not used; they collide with Graph `/v1.0/{path...}` in Go ServeMux.

Form body: `grant_type=client_credentials` or `password` (ROPC lite) or `refresh_token` or `urn:ietf:params:oauth:grant-type:device_code`. Optional `client_secret`, `scope` or `resource`. Workload identity federation uses `client_credentials` plus `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

## Authz

Public: discovery, JWKS, token, device code, SOAP, lab OIDC issuer. Graph, AAD Graph, and `/api/Users` require a Bearer principal. Issued JWTs authenticate later ARM and Graph calls (hashed for opaque lookup). Token errors use the OAuth JSON envelope (`error` / `error_description`). Graph errors use the Graph envelope.

## Detailed actions

- Client credentials, ROPC lite, refresh (SHA-256 hash stored once), and device code lite (token exchange auto-succeeds)
- Workload identity federation: lab OIDC issuer `/_noctaxris-az/oidc-lab` as `iss`; `aud` defaults to `api://AzureADTokenExchange`. Entra-issued JWTs are rejected as federated assertions. On-Behalf-Of `urn:ietf:params:oauth:grant-type:jwt-bearer` is rejected.
- Certificate assertion (`private_key_jwt`): `iss`/`sub` equal the app client id; `aud` is the token endpoint
- RS256 access_token claims: `tid`, `oid`, `sub`, `appid`, `azp`, `iss`, `aud`, `exp`, `ver`
- Graph lists for organization, users, groups, applications, service principals, devices, directory roles
- `addPassword` returns one-time `secretText` and `keyId`. `addKey` requires proof JWT `aud=00000002-0000-0000-c000-000000000000` and `iss` equal to the app/SP object id when a key already exists
- `POST .../owners/$ref` and `POST .../members/$ref` (official Graph `$ref`). `applications(appId='...')` is accepted via `NormalizeAppIdFilter`
- Federated identity credentials create with HTTP 201; default audience `api://AzureADTokenExchange`
- Unknown Graph collection GET returns `200` and `"value": []`. Item GET by GUID returns Graph 404
- AAD Graph `api-version=1.6` users / tenantDetails / directoryRoles; SOAP ListUsers XML
- Client-credentials token mint appends a row to Log Analytics table `AADServicePrincipalSignInLogs` on workspace `default` (`TimeGenerated`, `AppId`, `IPAddress`, `ResourceDisplayName`). Secrets are not stored. `TimeGenerated` follows the lab clock when freeze/set is on. See [monitor.md](monitor.md).

OIDC paths follow the Microsoft identity platform v1 and v2 layout. Literal tenant prefixes plus Graph `/v1.0` and `/beta` catch-alls avoid ServeMux conflicts with ARM `/subscriptions/...` and storage `/blob/...`.

## Not implemented

- Authorization code
- On-Behalf-Of
- Microsoft-signed JWTs / real Microsoft identity platform
- PIM write APIs, MFA, full Conditional Access policy evaluation

## Emulator limits

- Lab-signed JWTs only
- Tenant id defaults to `NOCTAXRIS_AZ_TENANT_ID`
- Device code skips interactive user confirm; exchange succeeds while the code is unexpired
- IAM portal is `GET /api/Users` only (no `/api/{path...}` catch-all)

## Deferred depth

- Broader Graph write coverage (PIM schedules, CA policy CRUD, app role assignment writes)
- Live Microsoft Graph SDK / AzureHound / `az` / `prowler` smokes (soft-skip when the binary is missing; not executed in this cut)

## Verification / CLI smoke

```bash
TENANT=${NOCTAXRIS_AZ_TENANT_ID:-00000000-0000-0000-0000-000000000001}
curl -fsS "http://127.0.0.1:4599/$TENANT/v2.0/.well-known/openid-configuration"
curl -fsS "http://127.0.0.1:4599/common/v2.0/.well-known/openid-configuration"
curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=sp-lab-1&scope=https://management.azure.com/.default"
TOKEN=$(curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=sp-lab-1&scope=https://graph.microsoft.com/.default" \
  | python -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/v1.0/users"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/$TENANT/users?api-version=1.6"
```

Soft-skip live Azure CLI / AzureHound / Microsoft Graph PowerShell / `prowler` runs when those tools are not installed. Those live runs are not executed in this cut. `az cloud register` and `Add-MgEnvironment` examples are in [configuration.md](../configuration.md) and the root README.
