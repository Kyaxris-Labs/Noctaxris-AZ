# Changelog

## Unreleased

- Nested TLS DinD overlay (`docker/compose.engine.yaml` + privileged overlay),
  image pull allowlist (`NOCTAXRIS_AZ_IMAGE_PULL_ALLOWLIST`), and compose tests
  that reject host `docker.sock` on engine files.
- Table Storage lab under `/table/{account}/...` (create/list/delete tables;
  insert/query/get/replace/merge/delete entities; Shared Key / SAS / root Bearer).
  Blob list/delete containers and blobs; queue peek and optional visibility
  timeout on dequeue. ARM `primaryEndpoints` includes `table`.
- Entra OIDC discovery + JWKS + RS256 lab JWTs; Managed Identity ARM + IMDS
  token theatre; role-assignment list-by-scope; subscriptions resources/providers
  lite; Key Vault secret soft-delete/recover (immediate lab timers).
- Soft-skip SDK/Terraform coverage for table and IMDS when
  `NOCTAXRIS_AZ_ENDPOINT` is set.
- Bump lab deps (`modernc.org/sqlite` v1.55.0, Docker Engine client
  `github.com/docker/docker` v28.5.2). Govulncheck allowlists Docker Engine
  Fixed N/A IDs (`GO-2026-4883`, `GO-2026-4887`, `GO-2026-5668`) matching the
  Noctaxris / Noctaxris-GCP pattern. CI adds Syft SBOM for the API image.

## 0.1.0

- Bootstrap Azure-shaped lab emulator: loopback HTTP `:4599`, AMQP lite `:5672`,
  Entra token theatre, ARM subscriptions/resource groups/RBAC, Key Vault, Storage
  blob/queue (Shared Key + SAS), Service Bus, App Configuration, Functions mock
  invoke, Activity Log / Monitor lite. Secure defaults match Noctaxris siblings
  (no host docker.sock, master key outside data root, distroless nonroot).
