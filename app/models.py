"""Lenient models for the Splunk Agent Observability (SAO) webhook payload.

Every field is optional and every model allows extra keys. The SAO docs define
the `alert.triggered` shape but NOT the clear-event shape, and the "Send test
event" payload may be thinner still. A payload we don't recognise must still be
accepted and forwarded -- never rejected back at SAO with a 422.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="allow")


class Alert(_Lenient):
    id: str | None = None
    name: str | None = None
    status: str | None = None
    previous_status: str | None = None


class Scope(_Lenient):
    org_id: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    agent_stream_id: str | None = None
    agent_stream_name: str | None = None


class Condition(_Lenient):
    metric: str | None = None
    aggregation: str | None = None
    operator: str | None = None
    threshold: float | None = None
    observed_value: float | None = None


class SAOWebhookPayload(_Lenient):
    version: str | None = None
    event: str | None = None
    event_id: str | None = None
    timestamp: str | None = None
    alert: Alert | None = None
    scope: Scope | None = None
    conditions: list[Condition] | None = None
    dedup_key: str | None = None
    deep_link: str | None = None
    metadata: dict[str, Any] | None = None
