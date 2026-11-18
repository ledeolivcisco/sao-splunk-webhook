"""Forwarding to Splunk HEC: envelope shape, retry policy, failure isolation."""

from __future__ import annotations

import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.hec import HECClient
from tests.conftest import TEST_HEC_EVENT_URL, TEST_HEC_TOKEN, TEST_WEBHOOK_TOKEN


@pytest.fixture
async def client():
    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        async with app.router.lifespan_context(app):
            yield c


@pytest.fixture
async def hec():
    settings = get_settings()
    async with httpx.AsyncClient() as http_client:
        yield HECClient(settings, http_client)


# --- envelope -----------------------------------------------------------------


@respx.mock
async def test_envelope_posted_to_hec_with_splunk_auth(client, triggered_payload):
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    await client.post(
        "/webhook/sao",
        json=triggered_payload,
        headers={"Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}"},
    )

    assert route.called
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"Splunk {TEST_HEC_TOKEN}"

    import json

    envelope = json.loads(request.content)
    assert envelope["index"] == "sao_alerts"
    assert envelope["sourcetype"] == "splunk:sao:alert"
    assert envelope["event"]["alert_name"] == "High hallucination rate"
    assert envelope["event"]["observed_value"] == 0.34
    assert envelope["event"]["original"] == triggered_payload


# --- retry policy ---------------------------------------------------------------


@respx.mock
@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
async def test_transient_errors_are_retried_up_to_the_cap(hec, status):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        return_value=httpx.Response(status, text="try again")
    )

    ok = await hec.send({"event": {"x": 1}})

    assert ok is False
    assert route.call_count == 3  # RETRY_MAX_ATTEMPTS from the test env


@respx.mock
async def test_retry_succeeds_after_a_transient_failure(hec):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        side_effect=[
            httpx.Response(503, text="busy"),
            httpx.Response(200, json={"text": "Success", "code": 0}),
        ]
    )

    ok = await hec.send({"event": {"x": 1}})

    assert ok is True
    assert route.call_count == 2


@respx.mock
@pytest.mark.parametrize("status", [400, 401, 403, 404])
async def test_client_errors_are_not_retried(hec, status):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        return_value=httpx.Response(status, json={"text": "Incorrect index", "code": 7})
    )

    ok = await hec.send({"event": {"x": 1}})

    assert ok is False
    assert route.call_count == 1


@respx.mock
async def test_connection_errors_are_retried(hec):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        side_effect=httpx.ConnectError("connection refused")
    )

    ok = await hec.send({"event": {"x": 1}})

    assert ok is False
    assert route.call_count == 3


@respx.mock
async def test_timeouts_are_retried_then_recover(hec):
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        side_effect=[
            httpx.ReadTimeout("too slow"),
            httpx.Response(200),
        ]
    )

    ok = await hec.send({"event": {"x": 1}})

    assert ok is True
    assert route.call_count == 2


# --- failure isolation ----------------------------------------------------------


@respx.mock
async def test_sao_still_gets_200_when_hec_is_down(client, triggered_payload):
    """Ack-fast: SAO must not see a failure just because Splunk is unavailable."""
    route = respx.post(TEST_HEC_EVENT_URL).mock(
        side_effect=httpx.ConnectError("splunk is down")
    )

    response = await client.post(
        "/webhook/sao",
        json=triggered_payload,
        headers={"Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert route.called


@respx.mock
async def test_unparseable_payload_is_still_forwarded(client):
    """A shape we don't recognise must reach Splunk, not be dropped."""
    route = respx.post(TEST_HEC_EVENT_URL).mock(return_value=httpx.Response(200))

    response = await client.post(
        "/webhook/sao",
        json={"conditions": [123], "surprise": "new-sao-field"},
        headers={"Authorization": f"Bearer {TEST_WEBHOOK_TOKEN}"},
    )

    assert response.status_code == 200
    import json

    envelope = json.loads(route.calls.last.request.content)
    assert envelope["event"]["parse_ok"] is False
    assert envelope["event"]["original"]["surprise"] == "new-sao-field"


def test_backoff_is_bounded_by_max_delay():
    settings = get_settings()
    import httpx as _httpx

    hec_client = HECClient(settings, _httpx.AsyncClient())
    for attempt in range(1, 12):
        assert 0 <= hec_client._backoff(attempt) <= settings.retry_max_delay
