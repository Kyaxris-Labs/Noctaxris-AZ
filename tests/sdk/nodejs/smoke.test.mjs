import { test } from "node:test";
import assert from "node:assert/strict";

function endpoint() {
  return (process.env.NOCTAXRIS_AZ_ENDPOINT || "").trim().replace(/\/$/, "");
}

function subscriptionID() {
  return (
    (process.env.NOCTAXRIS_AZ_SUBSCRIPTION_ID || "").trim() ||
    "00000000-0000-0000-0000-000000000002"
  );
}

async function requireReady(t) {
  const ep = endpoint();
  if (!ep) {
    t.skip("NOCTAXRIS_AZ_ENDPOINT unset; soft-skip live smoke");
    return null;
  }
  try {
    const res = await fetch(`${ep}/_noctaxris-az/ready`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) {
      t.skip(`Noctaxris-AZ not ready at ${ep}: status ${res.status}`);
      return null;
    }
  } catch (err) {
    t.skip(`Noctaxris-AZ not reachable at ${ep}: ${err}`);
    return null;
  }
  return ep;
}

function requireToken(t) {
  const token = (process.env.NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN || "").trim();
  if (!token) {
    t.skip("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN unset; soft-skip authenticated smoke");
    return null;
  }
  return token;
}

test("health ready and subscription GET smoke", async (t) => {
  const ep = await requireReady(t);
  if (!ep) return;
  const token = requireToken(t);
  if (!token) return;
  const sub = subscriptionID();

  const health = await fetch(`${ep}/_noctaxris-az/health`, {
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(health.status, 200, `health status=${health.status}`);

  const res = await fetch(
    `${ep}/subscriptions/${sub}?api-version=2022-12-01`,
    {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(5000),
    },
  );
  const body = await res.text();
  assert.equal(res.status, 200, `subscription status=${res.status} body=${body}`);
});
