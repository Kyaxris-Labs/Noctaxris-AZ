"""Soft-skip HTTP smoke against a running Noctaxris-AZ process."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

READY_PATH = "/_noctaxris-az/ready"
HEALTH_PATH = "/_noctaxris-az/health"


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


def do_get(url: str, token: str | None = None) -> tuple[int, str]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(errors="replace")


def test_health_ready_and_subscription_smoke() -> None:
    ep = require_ready()
    token = require_token()
    sub = subscription_id()

    status, _ = do_get(f"{ep}{HEALTH_PATH}")
    assert status == 200

    status, body = do_get(
        f"{ep}/subscriptions/{sub}?api-version=2022-12-01",
        token=token,
    )
    assert status == 200, body
    if body.strip().startswith("{"):
        parsed = json.loads(body)
        assert "id" in parsed or "subscriptionId" in parsed or "displayName" in parsed, body


def test_imds_token_smoke() -> None:
    ep = require_ready()
    req = urllib.request.Request(
        f"{ep}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        headers={"Metadata": "true"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode()
        assert resp.status == 200
        assert "access_token" in body


def test_table_put_get_smoke() -> None:
    ep = require_ready()
    token = require_token()
    sub = subscription_id()
    acct = "sdktableacctp"

    def put(url: str, payload: str) -> int:
        req = urllib.request.Request(
            url,
            data=payload.encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as err:
            return err.code

    rg_status = put(
        f"{ep}/subscriptions/{sub}/resourceGroups/sdk-rg-p?api-version=2022-12-01",
        json.dumps({"location": "eastus"}),
    )
    if rg_status >= 300:
        pytest.skip(f"RG create status={rg_status}")
    sa_status = put(
        f"{ep}/subscriptions/{sub}/resourceGroups/sdk-rg-p/providers/Microsoft.Storage/storageAccounts/{acct}?api-version=2023-01-01",
        json.dumps({"location": "eastus"}),
    )
    if sa_status >= 300:
        pytest.skip(f"storage account create status={sa_status}")

    req = urllib.request.Request(
        f"{ep}/table/{acct}/sdkpeople",
        headers={"Authorization": f"Bearer {token}"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status in (200, 201)

    ins = urllib.request.Request(
        f"{ep}/table/{acct}/sdkpeople",
        data=json.dumps({"PartitionKey": "p", "RowKey": "r", "Name": "sdk"}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(ins, timeout=5) as resp:
            assert resp.status in (200, 201)
    except urllib.error.HTTPError as err:
        assert err.code == 409

    status, body = do_get(f"{ep}/table/{acct}/sdkpeople/p/r", token=token)
    assert status == 200, body
