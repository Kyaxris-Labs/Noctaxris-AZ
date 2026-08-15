# Release checklist

How to cut a public Noctaxris-AZ release (example: **1.0.2**). Docker Hub image: **`kyaxris/noctaxris-az`**.

## Secrets (GitHub Actions)

Set on the canonical repo [`Kyaxris-Labs/Noctaxris-AZ`](https://github.com/Kyaxris-Labs/Noctaxris-AZ) (Settings → Secrets and variables → Actions). Never commit credentials.

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub account or org username that owns `kyaxris/noctaxris-az` |
| `DOCKERHUB_TOKEN` | Docker Hub [access token](https://docs.docker.com/docker-hub/access-tokens/) with push rights (not the account password) |

Forks skip publish with a log line. Missing secrets fail closed on schedule and on dispatch for the canonical repo.

## Before the tag

1. Bump `VERSION` (plain text, e.g. `1.0.2`) and keep `internal/version/version.go` (and Dockerfile `ARG VERSION`) in sync.
2. Move CHANGELOG notes under `## 1.0.2` (feature-oriented sections; no internal delivery labels).
3. Confirm PR CI is green (`unit`, `image`, `govulncheck`). Run nested Compose when the release touches DinD / engine overlays.
4. Confirm docs still describe loopback defaults and opt-in nested compute only.

## Cut the release

```bash
# On the commit you intend to ship (main tip after merge):
git tag -a v1.0.2 -m "Release Noctaxris-AZ 1.0.2"
git push origin v1.0.2
```

Pushing tag `v*` runs [`.github/workflows/release.yml`](../.github/workflows/release.yml). That workflow first runs the required CI gates ([`.github/workflows/ci-required.yml`](../.github/workflows/ci-required.yml): unit, compose-static, govulncheck, race, image, smoke-core) against the tagged commit. Docker Hub push runs only when those gates succeed. Then it builds `docker/Dockerfile` and pushes:

| Tag | Meaning |
|-----|---------|
| `kyaxris/noctaxris-az:1.0.2` | Exact semver |
| `kyaxris/noctaxris-az:1.0` | Major.minor |
| `kyaxris/noctaxris-az:1` | Major |
| `kyaxris/noctaxris-az:latest` | Latest tagged release |
| `kyaxris/noctaxris-az:sha-<short>` | Git short SHA |

Then create the GitHub Release for `v1.0.2` (UI or `gh release create v1.0.2 --notes-file ...`) using the CHANGELOG `1.0.2` section.

Optional: Actions → **release** → Run workflow with an existing tag if you need to re-push Hub tags after fixing secrets.

## Nightly (separate)

[`.github/workflows/docker-nightly.yml`](../.github/workflows/docker-nightly.yml) runs on a UTC cron and `workflow_dispatch`. It pushes `nightly`, `nightly-YYYYMMDD`, and `sha-<short>` only. It does **not** move `latest` or semver tags.

## Local image check

```bash
docker build -f docker/Dockerfile --build-arg VERSION=1.0.2 -t kyaxris/noctaxris-az:local .
# Run with unique roots (see README); then:
curl -sS http://127.0.0.1:4599/_noctaxris-az/version
# 1.0.2
```

## Related

- Ops / CI matrix: [ops.md](ops.md)
- Security posture: [security-defaults.md](security-defaults.md)
