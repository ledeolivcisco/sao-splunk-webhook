"""Inbound bearer-token authentication."""

from __future__ import annotations

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

from tests.conftest import TEST_HEC_EVENT_URL, TEST_WEBHOOK_TOKEN


@pytest.fixture
async def client():
    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        # ASGITransport does not run lifespan; do it explicitly so app.state is built.
        async with app.router.lifespan_context(app):
            yield c


@respx.mock
async def test_valid_token_is_accepted_and_forwarded(client, triggered_payload):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        return_value=httpx.Response(200, json={"text": "Success", "code": 0})
    )

    response = await client.post(
        "/webhook/sao",
        json=triggered_payload,
        headers={"Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert body["event_id"] == triggered_payload["event_id"]
    assert body["dedup_key"] == triggered_payload["dedup_key"]
    assert route.called


@respx.mock
@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="missing-header"),
        pytest.param({"Authorization": "Bearer wrong-token"}, id="wrong-token"),
        pytest.param({"Authorization": TEST_WEBHOOK_TOKEN}, id="no-bearer-scheme"),
        pytest.param({"Authorization": f"Basic {TEST_WEBHOOK_TOKEN}"}, id="wrong-scheme"),
        pytest.param({"Authorization": "Bearer "}, id="empty-token"),
    ],
)
async def test_bad_credentials_are_rejected_and_nothing_is_forwarded(
    client, triggered_payload, headers
):
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    response = await client.post("/webhook/sao", json=triggered_payload, headers=headers)

    assert response.status_code == 401
    assert response.json()["status"] == "unauthorized"
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert not route.called


@respx.mock
async def test_non_json_body_is_rejected(client):
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    response = await client.post(
        "/webhook/sao",
        content=b"this is not json",
        headers={
            "Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    assert not route.called


@respx.mock
async def test_json_that_is_not_an_object_is_rejected(client):
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    response = await client.post(
        "/webhook/sao",
        json=["a", "list"],
        headers={"Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}"},
    )

    assert response.status_code == 400
    assert not route.called


async def test_healthz(client):
    response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@respx.mock
async def test_insecure_mode_accepts_unauthenticated_requests(
    monkeypatch, triggered_payload
):
    monkeypatch.setenv("WEBHOOK_TOKEN", "")
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        async with app.router.lifespan_context(app):
            response = await c.post("/webhook/sao", json=triggered_payload)

    assert response.status_code == 200
    assert route.called


async def test_startup_fails_without_a_token(monkeypatch):
    monkeypatch.setenv("WEBHOOK_TOKEN", "")
    monkeypatch.setenv("ALLOW_INSECURE", "false")

    from app.main import app

    with pytest.raises(RuntimeError, match="Invalid configuration"):
        async with app.router.lifespan_context(app):
            pass


async def test_startup_fails_without_hec_settings(monkeypatch):
    monkeypatch.setenv("HEC_URL", "")
    monkeypatch.setenv("HEC_TOKEN", "")

    from app.main import app

    with pytest.raises(RuntimeError, match="HEC_URL is not set"):
        async with app.router.lifespan_context(app):
            pass
