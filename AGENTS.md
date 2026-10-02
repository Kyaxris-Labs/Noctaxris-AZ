# AGENTS.md — Noctaxris-AZ

Guidance for coding agents in this repository. Follow unless a maintainer says otherwise.

## Product bar

- Go Azure-faithful local emulator built from scratch. Secure by default. Loopback HTTP `:4599` plus AMQP lite `:5672`.
- No host `docker.sock`. Nested DinD over TLS is opt-in when present.
- Authn: Bearer (injected root client id + access token), Storage Shared Key/SAS, Service Bus connection string/SAS.
- Authz: ARM `AllowsARM` + RBAC deny-by-default. Root bypass intentional. Key Vault Owner must not imply secret get.
- Prefer proper service packages. Official Azure APIs (Azure CLI, SDKs, Terraform).
- Public docs under `docs/`. No roadmap labels in public surfaces.
- Module path: `github.com/Kyaxris-Labs/Noctaxris-AZ`. Hub image: `kyaxris/noctaxris-az`.

## JWT and crypto

- Use `internal/kernel/authn` JWT helpers backed by `github.com/go-jose/go-jose/v4`.
- RS256 only for Entra access tokens unless a documented lab path requires otherwise. Reject `alg=none`.
- No new hand-rolled compact JWT Encode/Verify. Prefer verified claims for auth decisions.

## Authz attach (DRY)

- Control plane: `azauth.RequireARMBearer`. Data plane: `azauth.RequireDataPlaneBearer` with the correct audience predicate.
- When `Authz == nil`, require helpers must write 403 (never silent `return p.IsRoot` without a response).
- Dedicated data-plane actions (Key Vault, OpenAI, Event Hubs, App Config, etc.) must live in `isDedicatedDataPlaneAction` so Owner/Contributor do not over-grant.
- Create service principal must use the same directory-write / admin gate as Create App.
- AKS Cluster User vs Admin credential actions must not be interchangeable.
- Entra: empty audience must not default to ARM; Conditional Access must run when configured; FIC match requires client_id; refresh must not freely switch audience; IMDS must not accept RFC1918 peer + Host spoof as metadata.
- Never echo primary keys or passwords on GET/list without listKeys-class authorization.

## Service-add checklist (auditability)

1. **Authn** — Bearer audience, SharedKey/SAS, or documented public path (Entra token, JWKS, IMDS Metadata gate, health).
2. **Authz** — ARM action string + scope; data-plane role GUIDs must match Azure published IDs when marketed.
3. **Dedicated roles** — if data actions exist, classify them so Owner cannot perform them unless Azure does.
4. **Secrets** — scrub PropertiesJSON / connection strings on Reader GET; Cosmos keys only via listKeys.
5. **AMQP / wire** — document SAS vs Bearer split; prefer CBS/SAS-token theatre over plaintext key equality when deepening.
6. **Docs** — service page + `docs/security-defaults.md` + `docs/configuration.md` for ports (including `:5672`).
7. **Tests** — positive allow, negative deny (wrong aud / missing role), boundary (empty aud, omitted client_id), error-guessing (Authz nil, IMDS Host spoof). Soft-skip SDK/TF when `NOCTAXRIS_AZ_ENDPOINT` unset.
8. **Coverage** — keep `./internal/...` statement coverage at or above 75%. Feature-oriented test names. Do not commit coverage artifacts.

## Libraries

- go-jose for JWT; `golang.org/x/crypto` for HMAC/SharedKey. Do not replace RBAC with OPA/Casbin.
- Nested Engine: `github.com/moby/moby/client`. Latest deps; pin Actions majors.

## Docs and release

- Align CHANGELOG / README / release docs with Noctaxris siblings. No tag/push unless asked.
- `ci-required` before Hub publish.

## Intentional lab exceptions

- `/_noctaxris-az/oidc-lab/*` public WIF helper mint (document in security-defaults).
- Storage `/blob|/queue|/table` middleware skip with handler-side SharedKey/SAS verify (document; do not “fix” by forcing Bearer-only unless product decision changes).

## Privacy

- Do not put personal machine paths, home directories, or private workspace names in commits, docs, tests, comments, or CI logs.
- Keep public prose limited to this product and its cloud APIs.
