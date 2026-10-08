#!/usr/bin/env bash
# Nested DinD operator/CI smoke for Noctaxris-AZ.
# Requires Docker Compose and curl.
#
# Default compose.yaml leaves the engine off. This script adds the opt-in
# engine overlay (compose.engine.yaml). Optional privileged overlay:
#   COMPOSE_EXTRA_FILES="-f docker/compose.engine-privileged.yaml" bash docker/smoke-nested.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/docker/compose.yaml" -f "$ROOT/docker/compose.engine.yaml")
# shellcheck disable=SC2206
if [[ -n "${COMPOSE_EXTRA_FILES:-}" ]]; then
  # shellcheck disable=SC2206
  EXTRA=( ${COMPOSE_EXTRA_FILES} )
  COMPOSE+=("${EXTRA[@]}")
fi
COMPOSE+=(--env-file "$ROOT/docker/.env")
EP="${EP:-https://127.0.0.1:4599}"
CURL=(curl -fsSk)
READY_TIMEOUT_SEC="${READY_TIMEOUT_SEC:-240}"
KEEP_UP="${KEEP_UP:-0}"
SUB="${NOCTAXRIS_AZ_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000002}"

cleanup() {
  if [[ "$KEEP_UP" == "1" ]]; then
    return 0
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

EXAMPLE_ROOT_ID="00000000-0000-0000-0000-00000000root"
EXAMPLE_ROOT_TOKEN="noctaxris-az-example-root-token"

if [[ ! -f "$ROOT/docker/.env" ]]; then
  cp "$ROOT/docker/.env.example" "$ROOT/docker/.env"
fi

# shellcheck disable=SC1091
set -a
source <(tr -d '\r' < "$ROOT/docker/.env")
set +a

if [[ "${NOCTAXRIS_AZ_ROOT_CLIENT_ID:-}" == "$EXAMPLE_ROOT_ID" && \
      "${NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN:-}" == "$EXAMPLE_ROOT_TOKEN" ]]; then
  ROOT_ID="$(openssl rand -hex 16)"
  ROOT_TOKEN="$(openssl rand -hex 32)"
  awk -v id="$ROOT_ID" -v token="$ROOT_TOKEN" '
    /^NOCTAXRIS_AZ_ROOT_CLIENT_ID=/ { print "NOCTAXRIS_AZ_ROOT_CLIENT_ID=" id; next }
    /^NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN=/ { print "NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN=" token; next }
    { print }
  ' "$ROOT/docker/.env" > "$ROOT/docker/.env.tmp"
  mv "$ROOT/docker/.env.tmp" "$ROOT/docker/.env"
  # shellcheck disable=SC1091
  set -a
  source <(tr -d '\r' < "$ROOT/docker/.env")
  set +a
fi

TOKEN="${NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN:?missing NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN}"
AUTH="Authorization: Bearer ${TOKEN}"
RID="smoke$(date +%s)"

echo "==> compose up (API + nested engine overlay)"
"${COMPOSE[@]}" up --build -d

echo "==> wait for GET $EP/_noctaxris-az/ready"
deadline=$((SECONDS + READY_TIMEOUT_SEC))
until "${CURL[@]}" "$EP/_noctaxris-az/ready" 2>/dev/null | grep -q ok; do
  if (( SECONDS >= deadline )); then
    echo "timeout waiting for ready" >&2
    "${COMPOSE[@]}" ps >&2 || true
    "${COMPOSE[@]}" logs --no-color --tail=120 >&2 || true
    exit 1
  fi
  sleep 3
done
echo "ready"

echo "==> engine service healthy"
ENGINE_ID="$("${COMPOSE[@]}" ps -q noctaxris-az-engine)"
if [[ -z "$ENGINE_ID" ]]; then
  echo "noctaxris-az-engine not running" >&2
  exit 1
fi
docker inspect -f '{{.State.Health.Status}}' "$ENGINE_ID" | grep -qx healthy

echo "==> ARM resource group + Redis (API with engine attached)"
"${CURL[@]}" -H "$AUTH" -H "Content-Type: application/json" \
  -X PUT \
  -d '{"location":"eastus"}' \
  "${EP}/subscriptions/${SUB}/resourcegroups/rg-${RID}?api-version=2022-09-01" | grep -q "rg-${RID}"
"${CURL[@]}" -H "$AUTH" -H "Content-Type: application/json" \
  -X PUT \
  -d '{"location":"eastus","properties":{"sku":{"name":"Basic","family":"C","capacity":0}}}' \
  "${EP}/subscriptions/${SUB}/resourceGroups/rg-${RID}/providers/Microsoft.Cache/Redis/${RID}-redis?api-version=2024-03-01" \
  | grep -q "${RID}-redis"

echo "==> smoke-nested ok"
