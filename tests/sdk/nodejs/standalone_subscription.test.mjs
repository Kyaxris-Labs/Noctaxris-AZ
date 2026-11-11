import { test } from "node:test";
import assert from "node:assert/strict";

const SEED_PATH = "/_noctaxris-az/lab/subscriptions:seedStandalone";

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

function redact(body, secrets) {
  let text = body;
  for (const secret of secrets) {
    if (secret) {
      text = text.split(secret).join("[redacted]");
    }
  }
  return text;
}

async function postSeed(ep, token) {
  const res = await fetch(`${ep}${SEED_PATH}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: "sdk-node" }),
    signal: AbortSignal.timeout(5000),
  });
  const text = await res.text();
  return { status: res.status, text };
}

function parseSeed(status, text, secrets) {
  if (status !== 200) {
    throw new Error(`seed status=${status} body=${redact(text, secrets)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("seed status=200 body was not JSON");
  }
  const accessToken = parsed.accessToken;
  const subscriptionId = parsed.subscriptionId;
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    throw new Error("seed response missing accessToken");
  }
  if (typeof subscriptionId !== "string" || subscriptionId.length === 0) {
    throw new Error("seed response missing subscriptionId");
  }
  return { accessToken, subscriptionId };
}

test("standalone subscription seed smoke", async (t) => {
  const ep = await requireReady(t);
  if (!ep) return;
  const root = requireToken(t);
  if (!root) return;
  const labSub = subscriptionID();

  const first = await postSeed(ep, root);
  if (first.status === 404) {
    t.skip("standalone subscription seed returned 404");
    return;
  }
  const seeded = parseSeed(first.status, first.text, [root]);
  // Throw instead of assert.equal so a mismatch does not print the token.
  if (seeded.accessToken === root) {
    throw new Error("seed accessToken equals the root token");
  }

  const listRes = await fetch(`${ep}/subscriptions?api-version=2022-12-01`, {
    headers: { Authorization: `Bearer ${seeded.accessToken}` },
    signal: AbortSignal.timeout(5000),
  });
  const listBody = await listRes.text();
  const listDetail = redact(listBody, [root, seeded.accessToken]);
  assert.equal(listRes.status, 200, `list status=${listRes.status} body=${listDetail}`);
  let listed;
  try {
    listed = JSON.parse(listBody);
  } catch {
    throw new Error("subscription list body was not JSON");
  }
  const rows = Array.isArray(listed.value) ? listed.value : [];
  const ids = rows
    .map((row) => (row && typeof row.subscriptionId === "string" ? row.subscriptionId : ""))
    .filter((id) => id.length > 0);
  assert.ok(
    ids.includes(seeded.subscriptionId),
    `subscription list missing seeded subscriptionId; ids=${ids.join(",")}`,
  );
  assert.ok(
    !ids.includes(labSub) && !listBody.includes(labSub),
    "subscription list included the lab subscription id",
  );

  const labRes = await fetch(
    `${ep}/subscriptions/${labSub}?api-version=2022-12-01`,
    {
      headers: { Authorization: `Bearer ${seeded.accessToken}` },
      signal: AbortSignal.timeout(5000),
    },
  );
  const labBody = await labRes.text();
  assert.ok(
    labRes.status === 403 || labRes.status === 404,
    `lab subscription status=${labRes.status} body=${redact(labBody, [root, seeded.accessToken])}`,
  );

  const second = await postSeed(ep, root);
  const again = parseSeed(second.status, second.text, [root, seeded.accessToken]);
  if (again.accessToken !== seeded.accessToken) {
    throw new Error("reseed returned a different accessToken");
  }
});
