"""Async Splunk HEC client with bounded exponential-backoff retry."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

# Transient conditions worth retrying. Everything else in the 4xx range means
# the request itself is wrong (bad token, unknown index, malformed envelope) --
# retrying only burns attempts and delays the error being noticed.
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HECClient:
    """Posts event envelopes to Splunk HTTP Event Collector."""

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._client = client

    @property
    def url(self) -> str:
        return self._settings.hec_event_url

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at retry_max_delay."""
        ceiling = min(
            self._settings.retry_max_delay,
            self._settings.retry_base_delay * (2 ** (attempt - 1)),
        )
        return random.uniform(0, ceiling)

    async def send(self, envelope: dict[str, Any], *, context: str = "") -> bool:
        """Send one envelope to HEC. Returns True on success.

        Never raises: this runs as a background task, so failures are logged
        rather than propagated.
        """
        settings = self._settings
        headers = {
            "Authorization": f"Splunk {settings.hec_token}",
            "Content-Type": "application/json",
        }
        tag = f" [{context}]" if context else ""

        last_error = "unknown"
        for attempt in range(1, settings.retry_max_attempts + 1):
            try:
                response = await self._client.post(
                    self.url,
                    json=envelope,
                    headers=headers,
                    timeout=settings.hec_timeout_seconds,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "HEC attempt %d/%d failed%s: %s",
                    attempt,
                    settings.retry_max_attempts,
                    tag,
                    last_error,
                )
            else:
                if response.status_code == 200:
                    logger.info(
                        "Forwarded to HEC%s (attempt %d)", tag, attempt
                    )
                    return True

                body = (response.text or "").strip()[:500]
                last_error = f"HTTP {response.status_code}: {body}"
                if response.status_code not in RETRYABLE_STATUS:
                    # Splunk's body carries the actual reason, e.g.
                    # {"text":"Incorrect index","code":7}
                    logger.error(
                        "HEC rejected the event%s, not retrying: %s", tag, last_error
                    )
                    return False
                logger.warning(
                    "HEC attempt %d/%d failed%s: %s",
                    attempt,
                    settings.retry_max_attempts,
                    tag,
                    last_error,
                )

            if attempt < settings.retry_max_attempts:
                await asyncio.sleep(self._backoff(attempt))

        logger.error(
            "Giving up on HEC after %d attempts%s. Last error: %s",
            settings.retry_max_attempts,
            tag,
            last_error,
        )
        return False
