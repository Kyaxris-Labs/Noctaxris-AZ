# Noctaxris-AZ docs

Public reference for **Noctaxris-AZ** (module `github.com/Kyaxris-Labs/Noctaxris-AZ`). Product name is PascalCase `Noctaxris-AZ`.

Noctaxris-AZ is a Docker-first Azure-shaped emulator for cloud security labs. Lab cores ship loopback by default (`:4599` HTTP, `:5672` AMQP lite), no host `docker.sock`, master key outside the data root, Bearer auth with Azure RBAC evaluation, Shared Key / SAS for Storage, and connection-string / SAS for Service Bus. Nested DinD is opt-in via Compose when present.

## Reference

| Doc | Topic |
|-----|--------|
| [services/index.md](services/index.md) | Per-service APIs, authz, CLI smoke, deferred depth |
| [architecture.md](architecture.md) | Deploy graph, packages, and request path |
| [configuration.md](configuration.md) | Env vars, data layout, Compose, client endpoints |
| [ops.md](ops.md) | Single-replica rule, backup/restore, upgrades, CI matrix, Hub images |
| [release.md](release.md) | Cut a semver release and Docker Hub tags |
| [security-defaults.md](security-defaults.md) | Host, crypto, and auth posture |
| [../tests/README.md](../tests/README.md) | SDK (Go/Node/Python) / Terraform integration suites |
| [../CHANGELOG.md](../CHANGELOG.md) | Lab-core release notes |

Quick start stays in the root [README](../README.md).
