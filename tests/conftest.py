"""Shared fixtures. Every test runs against a fully mocked HEC endpoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = REPO_ROOT / "samples"

TEST_WEBHOOK_TOKEN = "test-inbound-token"
TEST_HEC_TOKEN = "test-hec-token"
TEST_HEC_URL = "https://splunk.test:8088"
TEST_HEC_EVENT_URL = f"{TEST_HEC_URL}/services/collector/event"

# Environment vars take precedence over any .env on disk, so setting these
# keeps the suite independent of a developer's local configuration.
TEST_ENV = {
    "WEBHOOK_TOKEN": TEST_WEBHOOK_TOKEN,
    "ALLOW_INSECURE": "false",
    "HEC_URL": TEST_HEC_URL,
    "HEC_TOKEN": TEST_HEC_TOKEN,
    "HEC_INDEX": "sao_alerts",
    "HEC_SOURCETYPE": "splunk:sao:alert",
    "HEC_SOURCE": "sao:webhook",
    "HEC_HOST": "test-host",
    "HEC_VERIFY_TLS": "false",
    "HEC_TIMEOUT_SECONDS": "1",
    "RETRY_MAX_ATTEMPTS": "3",
    "RETRY_BASE_DELAY": "0.001",
    "RETRY_MAX_DELAY": "0.002",
    "LOG_LEVEL": "WARNING",
}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in TEST_ENV.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def settings():
    from app.config import get_settings

    return get_settings()


def _sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text())


@pytest.fixture
def triggered_payload() -> dict:
    return _sample("alert_triggered.json")


@pytest.fixture
def cleared_payload() -> dict:
    return _sample("alert_cleared.json")


@pytest.fixture
def minimal_payload() -> dict:
    return _sample("minimal_test_event.json")
