"""Soft-skip HTTP smoke for the standalone subscription seed."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

READY_PATH = "/_noctaxris-az/ready"
SEED_PATH = "/_noctaxris-az/lab/subscriptions:seedStandalone"


def endpoint() -> str | None:
    ep = os.environ.get("NOCTAXRIS_AZ_ENDPOINT", "").strip().rstrip("/")
    return ep or None


def subscription_id() -> str:
    return (
        os.environ.get("NOCTAXRIS_AZ_SUBSCRIPTION_ID", "").strip()
        or "00000000-0000-0000-0000-000000000002"
    )


def require_ready() -> str:
    ep = endpoint()
    if not ep:
        pytest.skip("NOCTAXRIS_AZ_ENDPOINT unset; soft-skip live smoke")
    url = f"{ep}{READY_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            if resp.status != 200:
                pytest.skip(f"Noctaxris-AZ not ready at {ep}: status {resp.status}")
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        pytest.skip(f"Noctaxris-AZ not reachable at {ep}: {err}")
    return ep


def require_token() -> str:
    token = os.environ.get("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN", "").strip()
    if not token:
        pytest.skip("NOCTAXRIS_AZ_ROOT_ACCESS_TOKEN unset; soft-skip authenticated smoke")
    return token


def redact(body: str, *secrets: str) -> str:
    text = body
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def do_get(url: str, token: str) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(errors="replace")


def do_post(url: str, token: str, payload: str) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=payload.encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(errors="replace")


def parse_seed(status: int, body: str, *secrets: str) -> tuple[str, str]:
    if status != 200:
        raise AssertionError(f"seed status={status} body={redact(body, *secrets)}")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        raise AssertionError("seed status=200 body was not JSON") from None
    access_token = parsed.get("accessToken")
    subscription = parsed.get("subscriptionId")
    if not isinstance(access_token, str) or not access_token:
        raise AssertionError("seed response missing accessToken")
    if not isinstance(subscription, str) or not subscription:
        raise AssertionError("seed response missing subscriptionId")
    return access_token, subscription


def test_standalone_subscription_smoke() -> None:
    ep = require_ready()
    root = require_token()
    lab_sub = subscription_id()
    payload = json.dumps({"name": "sdk-py"})

    status, body = do_post(f"{ep}{SEED_PATH}", root, payload)
    if status == 404:
        pytest.skip("standalone subscription seed returned 404")
    access_token, seeded_sub = parse_seed(status, body, root)
    # Raise instead of assert so a mismatch does not print the token.
    if access_token == root:
        raise AssertionError("seed accessToken equals the root token")

    list_status, list_body = do_get(
        f"{ep}/subscriptions?api-version=2022-12-01",
        access_token,
    )
    list_detail = redact(list_body, root, access_token)
    assert list_status == 200, f"list status={list_status} body={list_detail}"
    try:
        listed = json.loads(list_body)
    except json.JSONDecodeError:
        raise AssertionError("subscription list body was not JSON") from None
    rows = listed.get("value")
    if not isinstance(rows, list):
        raise AssertionError("subscription list missing value")
    ids = [
        row.get("subscriptionId")
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("subscriptionId"), str)
    ]
    assert seeded_sub in ids, f"subscription list missing seeded subscriptionId; ids={ids}"
    assert lab_sub not in ids and lab_sub not in list_body, (
        "subscription list included the lab subscription id"
    )

    lab_status, lab_body = do_get(
        f"{ep}/subscriptions/{lab_sub}?api-version=2022-12-01",
        access_token,
    )
    assert lab_status in (403, 404), (
        f"lab subscription status={lab_status} body={redact(lab_body, root, access_token)}"
    )

    again_status, again_body = do_post(f"{ep}{SEED_PATH}", root, payload)
    again_token, _ = parse_seed(again_status, again_body, root, access_token)
    if again_token != access_token:
        raise AssertionError("reseed returned a different accessToken")
