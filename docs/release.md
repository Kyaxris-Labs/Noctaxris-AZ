# Release checklist

How to cut a public Noctaxris-AZ release (example: **0.1.0**). Docker Hub image: **`kyaxris/noctaxris-az`**.

## Secrets (GitHub Actions)

Set on the canonical repo [`Kyaxris-Labs/Noctaxris-AZ`](https://github.com/Kyaxris-Labs/Noctaxris-AZ) (Settings → Secrets and variables → Actions). Never commit credentials.

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub account or org username that owns `kyaxris/noctaxris-az` |
| `DOCKERHUB_TOKEN` | Docker Hub access token with push rights (not the account password) |

Forks should skip publish. Missing secrets must fail closed on the canonical repo when a publish workflow is enabled.

## Before the tag

1. Bump `VERSION` (plain text, e.g. `0.1.0`) and keep any embedded version default in sync.
2. Move CHANGELOG notes under `## [0.1.0]` (feature-oriented sections; no internal delivery labels).
3. Confirm PR CI is green. Run nested Compose when the release touches DinD / engine overlays.
4. Confirm docs still describe loopback defaults and opt-in nested compute only.

## Cut the release

```bash
# On the commit you intend to ship (main tip after merge):
git tag -a v0.1.0 -m "Release Noctaxris-AZ 0.1.0"
git push origin v0.1.0
```

When a `v*` release workflow is configured on the canonical repo, it should build `docker/Dockerfile` and push:

| Tag | Meaning |
|-----|---------|
| `kyaxris/noctaxris-az:0.1.0` | Exact semver |
| `kyaxris/noctaxris-az:0.1` | Major.minor |
| `kyaxris/noctaxris-az:0` | Major |
| `kyaxris/noctaxris-az:latest` | Latest tagged release |
| `kyaxris/noctaxris-az:sha-<short>` | Git short SHA |

Then create the GitHub Release for `v0.1.0` using the CHANGELOG `0.1.0` section.

Until Hub publish automation lands, operators can still build and push locally after CI is green:

```bash
docker build -f docker/Dockerfile --build-arg VERSION=0.1.0 -t kyaxris/noctaxris-az:0.1.0 .
docker push kyaxris/noctaxris-az:0.1.0
```

## Local image check

```bash
docker build -f docker/Dockerfile --build-arg VERSION=0.1.0 -t kyaxris/noctaxris-az:local .
# Run with unique roots (see README); then:
curl -sS http://127.0.0.1:4599/_noctaxris-az/version
# 0.1.0
```

## Related

- [ops.md](ops.md)
- [configuration.md](configuration.md)
