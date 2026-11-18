"""Reshape a SAO webhook payload into a Splunk HEC envelope.

Strategy: *flatten + keep original*. We emit flat, SPL-friendly top-level keys
so searches need no `spath`, while preserving the untouched payload under
`original` so nothing SAO sends is ever lost.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from app.config import Settings
from app.models import SAOWebhookPayload

logger = logging.getLogger(__name__)

# Mapping from the SAO alert status to a coarse severity. Kept in one place so
# it is trivial to retune without hunting through the codebase.
SEVERITY_BY_STATUS: dict[str, str] = {
    "triggered": "high",
    "firing": "high",
    "alerting": "high",
    "cleared": "informational",
    "resolved": "informational",
    "healthy": "informational",
    "ok": "informational",
}
DEFAULT_SEVERITY = "unknown"

_UNSAFE_KEY_CHARS = re.compile(r"[^0-9A-Za-z_]+")

# The path segment SAO emits for a stream, which some consoles spell differently.
_SOURCE_STREAM_SEGMENT = "log-streams"
# Everything from this segment onward is the part worth keeping from SAO's link.
_PATH_ANCHOR = "project"


def rewrite_deep_link(link: Any, settings: "Settings | None") -> Any:
    """Point a SAO deep link at the console this tenant actually uses.

    SAO stamps `deep_link` with its own console host and path layout, which does
    not always match where the customer's console lives. Rewriting swaps the
    origin, inserts the tenant segment, and renames the stream segment, while
    preserving the query string and fragment byte-for-byte - those carry the time
    range and filters that make the link land on the right traces.

    Conservative by design: anything unrecognised is returned untouched, because
    a link that goes to the wrong place is worse than one that goes nowhere new.
    """
    if not settings or not getattr(settings, "sao_console_url", ""):
        return link
    if not isinstance(link, str) or not link.strip():
        return link

    try:
        parts = urlsplit(link)
        target = urlsplit(settings.sao_console_url)
    except ValueError:
        logger.warning("deep_link is not a parseable URL; leaving it alone")
        return link

    if not parts.scheme or not parts.netloc or not target.netloc:
        logger.warning("deep_link or SAO_CONSOLE_URL is not absolute; leaving the link alone")
        return link

    segments = [seg for seg in parts.path.split("/") if seg]
    if _PATH_ANCHOR not in segments:
        logger.warning(
            "deep_link path %r has no %r segment; leaving the link alone",
            parts.path, _PATH_ANCHOR,
        )
        return link

    tail = segments[segments.index(_PATH_ANCHOR):]
    if settings.sao_stream_segment:
        tail = [
            settings.sao_stream_segment if seg == _SOURCE_STREAM_SEGMENT else seg
            for seg in tail
        ]

    prefix = [settings.sao_tenant] if settings.sao_tenant else []
    new_path = "/" + "/".join(prefix + tail)
    return urlunsplit((target.scheme, target.netloc, new_path, parts.query, parts.fragment))


def _sanitize_key(key: str) -> str:
    """Make an arbitrary metadata key safe to use as a Splunk field name."""
    cleaned = _UNSAFE_KEY_CHARS.sub("_", key).strip("_")
    return cleaned or "unnamed"


def parse_timestamp(value: Any) -> float | None:
    """Parse an ISO-8601 timestamp (with optional trailing Z) to epoch seconds."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        logger.warning("Unparseable timestamp %r; falling back to receipt time", value)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def severity_for(status: Any) -> str:
    if not isinstance(status, str):
        return DEFAULT_SEVERITY
    return SEVERITY_BY_STATUS.get(status.strip().lower(), DEFAULT_SEVERITY)


def flatten(payload: dict[str, Any], settings: "Settings | None" = None) -> dict[str, Any]:
    """Produce the flat event body, with the raw payload kept under `original`.

    Best-effort: a payload that fails model validation is still flattened from
    the raw dict, and flagged with parse_ok=false.

    When `settings` carries a SAO console URL, the top-level `deep_link` is
    rewritten to point at that console and the link SAO sent is kept alongside
    as `deep_link_source`. `original` is never modified.
    """
    parse_ok = True
    try:
        SAOWebhookPayload.model_validate(payload)
    except ValidationError as exc:
        parse_ok = False
        logger.warning("Payload did not match the known SAO schema: %s", exc)

    alert = payload.get("alert") or {}
    scope = payload.get("scope") or {}
    conditions = payload.get("conditions") or []
    metadata = payload.get("metadata") or {}

    if not isinstance(alert, dict):
        alert = {}
    if not isinstance(scope, dict):
        scope = {}
    if not isinstance(conditions, list):
        conditions = []
    if not isinstance(metadata, dict):
        metadata = {}

    flat: dict[str, Any] = {
        "parse_ok": parse_ok,
        # --- envelope -------------------------------------------------------
        "version": payload.get("version"),
        "event_type": payload.get("event"),
        "event_id": payload.get("event_id"),
        "timestamp": payload.get("timestamp"),
        "dedup_key": payload.get("dedup_key"),
        "deep_link": payload.get("deep_link"),
        # --- alert ----------------------------------------------------------
        "alert_id": alert.get("id"),
        "alert_name": alert.get("name"),
        "alert_status": alert.get("status"),
        "alert_previous_status": alert.get("previous_status"),
        "severity": severity_for(alert.get("status")),
        # --- scope ----------------------------------------------------------
        "org_id": scope.get("org_id"),
        "project_id": scope.get("project_id"),
        "project_name": scope.get("project_name"),
        # SAO renamed these from agent_stream_* to log_stream_*; accept either
        # and promote both spellings so existing searches keep working.
        "agent_stream_id": scope.get("agent_stream_id") or scope.get("log_stream_id"),
        "agent_stream_name": scope.get("agent_stream_name") or scope.get("log_stream_name"),
        "log_stream_id": scope.get("log_stream_id") or scope.get("agent_stream_id"),
        "log_stream_name": scope.get("log_stream_name") or scope.get("agent_stream_name"),
        # --- conditions -----------------------------------------------------
        "condition_count": len(conditions),
    }

    # Promote the first condition to top level; the full list stays in
    # `original`, so one alert remains one HEC event.
    first = conditions[0] if conditions and isinstance(conditions[0], dict) else {}
    flat.update(
        {
            "metric": first.get("metric"),
            "aggregation": first.get("aggregation"),
            "operator": first.get("operator"),
            "threshold": first.get("threshold"),
            "observed_value": first.get("observed_value"),
        }
    )

    # Metadata: flat metadata_<key> fields for easy SPL, plus the intact object.
    for key, value in metadata.items():
        flat[f"metadata_{_sanitize_key(str(key))}"] = value
    if metadata:
        flat["metadata"] = metadata

    # Drop keys we have nothing for, so Splunk isn't littered with nulls.
    flat = {k: v for k, v in flat.items() if v is not None}

    # Rewrite last, so the link SAO sent survives in both `original` and
    # `deep_link_source` and only the field searches use is retargeted.
    original_link = flat.get("deep_link")
    if original_link:
        rewritten = rewrite_deep_link(original_link, settings)
        if rewritten != original_link:
            flat["deep_link"] = rewritten
            flat["deep_link_source"] = original_link

    flat["original"] = payload
    return flat


def to_hec_envelope(
    flat: dict[str, Any],
    settings: Settings,
    received_at: float,
) -> dict[str, Any]:
    """Wrap the flat event in the Splunk HEC JSON envelope."""
    event_time = parse_timestamp(flat.get("timestamp"))
    return {
        "time": event_time if event_time is not None else received_at,
        "host": settings.hec_host,
        "source": settings.hec_source,
        "sourcetype": settings.hec_sourcetype,
        "index": settings.hec_index,
        "event": flat,
    }
