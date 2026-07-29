# Architecture

Noctaxris-AZ is a single Go process that serves Azure-shaped HTTP on loopback
`:4599` and Service Bus AMQP 1.0 lite on loopback `:5672`.

```mermaid
flowchart TB
  subgraph clients [Clients]
    SDK[Azure SDKs / az / curl]
    AMQPC[azservicebus AMQP]
  end

  subgraph process [noctaxris-az]
    HTTP[HTTP listener :4599]
    AMQP[AMQP lite :5672]
    MW[Request ID + authn]
    REST[REST ServeMux]
    AUTHZ[RBAC evaluator]
    STORE[(SQLite state.db)]
    AEAD[ChaCha20-Poly1305]
    AUDIT[audit.jsonl]

    subgraph services [Registered services]
      ID[Entra / Subscriptions / RBAC]
      CRYPTO[Key Vault]
      DATA[Storage blob/queue]
      MSG[Service Bus]
      APP[App Configuration / Functions]
      OBS[Activity Log / Monitor]
    end
  end

  subgraph volumes [Volumes]
    DATAVOL[noctaxris-az-data]
    SECRETS[noctaxris-az-secrets / master.key]
  end

  subgraph nested [Opt-in nested DinD]
    ENGINE[noctaxris-az-engine TLS]
  end

  SDK -->|127.0.0.1:4599| HTTP
  AMQPC -->|127.0.0.1:5672| AMQP
  HTTP --> MW
  MW --> REST
  REST --> ID
  REST --> CRYPTO
  REST --> DATA
  REST --> APP
  REST --> OBS
  AMQP --> MSG
  ID --> AUTHZ
  CRYPTO --> AUTHZ
  DATA --> AUTHZ
  APP --> AUTHZ
  OBS --> AUTHZ
  AUTHZ --> STORE
  STORE --> DATAVOL
  AEAD --> SECRETS
  STORE --> AEAD
  REST --> AUDIT
  AUDIT --> DATAVOL
  APP -.->|NOCTAXRIS_AZ_DOCKER_HOST set| ENGINE
```

## Packages

| Package | Role |
|---------|------|
| `cmd/noctaxris-az` | Process entry |
| `internal/config` | `NOCTAXRIS_AZ_*` env load and listen security |
| `internal/kernel/authn` | Bearer and Shared Key helpers |
| `internal/kernel/authz` | Azure RBAC evaluator |
| `internal/kernel/audit` | Audit writer |
| `internal/kernel/httpegress` | Outbound HTTP fail-closed helpers |
| `internal/store` | SQLite schema and resource helpers |
| `internal/services/*` | Per-product HTTP / AMQP handlers |
| `internal/azerrors` | ARM-shaped error envelopes |
| `internal/compute` | Nested Docker host validation (no host sock) |

## Request path

1. Health / ready / version and Entra token skip auth.
2. ARM and data-plane Bearer paths authenticate, then evaluate RBAC (root bypass).
3. Storage Shared Key / SAS paths authenticate without RBAC role lookup.
4. Mutations may append Activity Log rows for Monitor list theatre.
5. Sensitive material is sealed with the master key outside the data root.
