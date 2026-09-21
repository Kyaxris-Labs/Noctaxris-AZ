# Microsoft Entra ID

Lab Entra OIDC / OAuth2 and Microsoft Graph theatre on the shared HTTP listener (`:4599` by default). Optional cloud-hosts TLS is documented in [configuration.md](../configuration.md).

## Status

**lab.** v1 and v2 token endpoints on the configured tenant plus `common` and `organizations`; RS256 lab JWTs; Graph directory lists; AAD Graph 1.6 and SOAP ListUsers. Enabled Conditional Access policies run at token mint (`AADSTS53003`). Federated credentials honor Graph `claimsMatchingExpression` (`eq`, `matches`, `and`). Graph `addPassword` / `addKey` / `owners/$ref` require an application owner or Application Administrator, and Application Administrator assignments honor `directoryScopeId`. `client_credentials` needs a stored `client_secret`, a cert assertion, or a federated jwt-bearer assertion. Tokens are lab-signed, not Microsoft-signed.

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
| `POST` | `/v1.0/servicePrincipals` (create from existing `appId`; `/beta` too) |
| `POST` | `/v1.0/identity/conditionalAccess/policies` (create; list is GET on the same collection) |
| `POST` | `/v1.0/applications/{id}/addPassword`, `addKey`, `owners/$ref`, `federatedIdentityCredentials` |
| `GET` | `/{tenant}/users?api-version=1.6` (AAD Graph) |
| `POST` | `/provisioningwebservice.svc` (SOAP `ListUsers`) |
| `GET` | `/api/Users` (IAM portal lite) |
| `GET` | `/_noctaxris-az/oidc-lab/.well-known/openid-configuration` |
| `GET` | `/_noctaxris-az/oidc-lab/keys` |
| `POST` | `/_noctaxris-az/oidc-lab/token` |

`{tenant}` is a literal path: `NOCTAXRIS_AZ_TENANT_ID`, `common`, or `organizations`. Handlers remap `common` / `organizations` to the lab tenant. Wildcards are not used; they collide with Graph `/v1.0/{path...}` in Go ServeMux.

Form body: `grant_type=client_credentials` or `password` (ROPC lite) or `refresh_token` or `urn:ietf:params:oauth:grant-type:device_code`. `client_credentials` requires `client_secret` (hashed against Graph `addPassword` rows) or a jwt-bearer `client_assertion`. Missing proof is HTTP 401 `invalid_client` (`AADSTS7000218`); a secret that does not match is `AADSTS7000215`. Optional `scope` or `resource`. Workload identity federation uses `client_credentials` plus `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

## Authz

Public: discovery, JWKS, token, device code, lab OIDC issuer (including `POST /_noctaxris-az/oidc-lab/token`). Graph, AAD Graph, SOAP `POST /provisioningwebservice.svc`, and `/api/Users` require a Bearer principal. SOAP is directory read: the token `aud` must be Microsoft Graph (`https://graph.microsoft.com`) or Azure AD Graph (`https://graph.windows.net`), not ARM and not the token `iss`. Graph handlers reject ARM and issuer audiences (HTTP 403 `InvalidAuthenticationToken`). ARM control-plane handlers reject Graph audiences (HTTP 403 `InvalidAuthenticationTokenAudience`). Key Vault data plane, Storage Shared Key/SAS, table/blob, and Event Hubs HTTP data plane do not require ARM `aud`. Hash lookup of a lab JWT still reads `aud` from the compact token; it does not skip claims. Root Bearer skips audience. Token errors use the OAuth JSON envelope (`error` / `error_description`). Graph errors use the Graph envelope.

`addPassword`, `addKey`, and `owners/$ref` keep the Graph audience check, then allow the write when the caller is root, an owner of that application or service principal, or Application Administrator (directory role template `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`, seeded role id `99999999-9999-9999-9999-999999999999`). Unified role assignments with `directoryScopeId` `/` (or directory role membership with no scoped App Admin assignment) stay tenant-wide. `directoryScopeId` `/<application-object-id>` (or the client id) limits those writes to that application; other apps return Graph 403 `Authorization_RequestDenied`. Other principals get the same 403.

## Detailed actions

- Client credentials, ROPC lite, refresh (SHA-256 hash stored once), and device code lite (token exchange auto-succeeds)
- Workload identity federation: lab OIDC issuer `/_noctaxris-az/oidc-lab` as `iss`; `POST /_noctaxris-az/oidc-lab/token` mints `id_token` and `access_token` (same JWT) signed with the lab OIDC key. Form `subject`/`sub` is required; `audience`/`aud`/`resource`/`scope` default to `api://AzureADTokenExchange`. That JWT is what jwt-bearer FIC verifies. `aud` on the FIC defaults to `api://AzureADTokenExchange`. Entra-issued JWTs are rejected as federated assertions. On-Behalf-Of `urn:ietf:params:oauth:grant-type:jwt-bearer` is rejected. Matching uses the FIC whose application equals form `client_id`; another app's credential with the same `iss`/`sub` does not win. A credential with empty `claimsMatchingExpression` still matches exact `issuer` + `subject` + audience. When Graph stores `{ "value", "languageVersion" }` (FFL `languageVersion` 1), the lab matches issuer and audience and evaluates `claims['name'] eq '…'` / `matches 'glob'` with `*` / `?`, joined by `and`.
- Conditional Access: Graph list and POST `/identity/conditionalAccess/policies`. Enabled policies run at token mint. `conditions.applications.includeApplications` is compared to form `client_id` (`All` / `AllApplications` include every client). A policy that lists specific apps does not apply to other `client_id` values. `excludeApplications` wins. `conditions.userAgents.include` (string list) or a non-enum `conditions.clientAppTypes` entry is a User-Agent prefix; the header must match when the policy applies. Matching UA plus an included client succeeds. Wrong UA on an included client returns OAuth `invalid_grant` with `AADSTS53003` and `BlockedByConditionalAccess` in `error_description`. Disabled policies are skipped.
- Certificate assertion (`private_key_jwt`): `iss`/`sub` equal the app client id; `aud` is the token endpoint. Registered key PEMs may be a public key, a certificate, or an exported PKCS#8 private key (public key is derived).
- RS256 access_token claims: `tid`, `oid`, `sub`, `appid`, `azp`, `iss`, `aud`, `exp`, `ver`
- Graph lists for organization, users, groups, applications, service principals, devices, directory roles
- `POST /v1.0/servicePrincipals` creates a service principal from an existing application (`appId` in the body, or the application object id which is resolved to `appId`). HTTP 201. A second create for the same `appId` is 400 `Request_MultipleObjectsWithSameKeyValue`. Unknown `appId` is 400 `Request_BadRequest`. GET `/servicePrincipals/{id}` still accepts object id or `appId`.
- `addPassword` returns one-time `secretText` and `keyId`. `addKey` skips proof when the app or SP has no key credentials. After a key exists, proof is an RS256 JWT verified against stored key PEMs: `aud` `00000002-0000-0000-c000-000000000000`, `iss` equal to the app or SP object id, plus `nbf`/`exp`. `DecodeJWTUnverified` is not enough. `PATCH /applications/{id}` with `keyCredentials` after a key exists requires that same proof and otherwise fails closed. Those writes, plus `owners/$ref`, require an application owner or Application Administrator (root Bearer still provisions; scoped App Admin cannot write apps outside `directoryScopeId`).
- `POST .../owners/$ref` and `POST .../members/$ref` (official Graph `$ref`). `/applications/{id}` and `/servicePrincipals/{id}` take directory object id. Client id (`appId`) in that slot 404s. `POST /servicePrincipals/{appId}/owners/$ref` does not write application owners. `applications(appId='...')` remains the OData client-id form on GET.
- Unknown Graph POST under `/v1.0/{path...}` and `/beta/{path...}` returns 404 and does not substring-dispatch `addPassword`, `addKey`, `owners/$ref`, or `members/$ref`.
- Federated identity credentials create with HTTP 201; default audience `api://AzureADTokenExchange`. Graph accepts `claimsMatchingExpression` as `{ "value", "languageVersion" }`; `subject` may be empty when the expression is set.
- Unknown Graph collection GET returns `200` and `"value": []`. Item GET by GUID returns Graph 404
- AAD Graph `api-version=1.6` users / tenantDetails / directoryRoles; SOAP ListUsers XML requires Bearer (directory read)
- Client-credentials token mint appends a row to Log Analytics table `AADServicePrincipalSignInLogs` on workspace `default` (`TimeGenerated`, `AppId`, `IPAddress`, `ResourceDisplayName`). Secrets are not stored. `TimeGenerated` follows the lab clock when freeze/set is on. See [monitor.md](monitor.md).

OIDC paths follow the Microsoft identity platform v1 and v2 layout. Literal tenant prefixes plus Graph `/v1.0` and `/beta` catch-alls avoid ServeMux conflicts with ARM `/subscriptions/...` and storage `/blob/...`.

## Not implemented

- Authorization code
- On-Behalf-Of
- Microsoft-signed JWTs / real Microsoft identity platform
- MFA, device compliance, and PIM grant controls on Conditional Access

## Emulator limits

- Lab-signed JWTs only
- Tenant id defaults to `NOCTAXRIS_AZ_TENANT_ID`
- Device code skips interactive user confirm; exchange succeeds while the code is unexpired
- IAM portal is `GET /api/Users` only (no `/api/{path...}` catch-all)

## Deferred depth

- Broader Graph write coverage (PIM schedules, app role assignment writes)
- Conditional Access MFA, device compliance, and PIM
- Live Microsoft Graph SDK / AzureHound / `az` / `prowler` smokes (soft-skip when the binary is missing; not executed in this cut)

## Verification / CLI smoke

```bash
TENANT=${NOCTAXRIS_AZ_TENANT_ID:-00000000-0000-0000-0000-000000000001}
APP_OBJ=55555555-5555-5555-5555-555555555555
APP_ID=66666666-6666-6666-6666-666666666666
curl -fsS "http://127.0.0.1:4599/$TENANT/v2.0/.well-known/openid-configuration"
curl -fsS "http://127.0.0.1:4599/common/v2.0/.well-known/openid-configuration"
curl -fsS "http://127.0.0.1:4599/_noctaxris-az/oidc-lab/.well-known/openid-configuration"
curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$APP_ID&scope=https://graph.microsoft.com/.default"
# expect HTTP 401 invalid_client (AADSTS7000218) without client_secret or client_assertion
SECRET=$(curl -s -X POST "http://127.0.0.1:4599/v1.0/applications/$APP_OBJ/addPassword" \
  -H "Authorization: Bearer $NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passwordCredential":{"displayName":"lab"}}' \
  | python -c "import sys,json; print(json.load(sys.stdin).get('secretText',''))")
TOKEN=$(curl -s -X POST "http://127.0.0.1:4599/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$APP_ID&client_secret=$SECRET&scope=https://graph.microsoft.com/.default" \
  | python -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:4599/v1.0/users"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:4599/$TENANT/users?api-version=1.6"
curl -s -H "Authorization: Bearer $NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"appId\":\"$APP_ID\"}" \
  -X POST "http://127.0.0.1:4599/v1.0/servicePrincipals"
# seeded Lab App already has a service principal; expect 400 Request_MultipleObjectsWithSameKeyValue
```

Soft-skip live Azure CLI / AzureHound / Microsoft Graph PowerShell / `prowler` runs when those tools are not installed. Those live runs are not executed in this cut. `az cloud register` and `Add-MgEnvironment` examples are in [configuration.md](../configuration.md) and the root README.
