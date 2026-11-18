"""Payload reshaping: flat fields for SPL, original preserved."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from app.transform import flatten, parse_timestamp, severity_for, to_hec_envelope


def test_documented_payload_flattens_to_expected_fields(triggered_payload):
    flat = flatten(triggered_payload)

    assert flat["parse_ok"] is True
    assert flat["event_type"] == "alert.triggered"
    assert flat["event_id"] == "a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
    assert flat["alert_id"] == "alert-7f3c2b91"
    assert flat["alert_name"] == "High hallucination rate"
    assert flat["alert_status"] == "triggered"
    assert flat["alert_previous_status"] == "healthy"
    assert flat["severity"] == "high"
    assert flat["org_id"] == "org-acme-001"
    assert flat["project_name"] == "My Project"
    assert flat["agent_stream_name"] == "production"
    assert flat["metric"] == "metrics/context_adherence"
    assert flat["aggregation"] == "Average"
    assert flat["operator"] == "less than"
    assert flat["threshold"] == 0.5
    assert flat["observed_value"] == 0.34
    assert flat["condition_count"] == 1
    assert flat["dedup_key"] == "alert-7f3c2b91:proj-llm-gateway:stream-prod-01"
    assert flat["deep_link"].startswith("https://")


def test_metadata_is_flattened_and_preserved(triggered_payload):
    flat = flatten(triggered_payload)

    assert flat["metadata_team"] == "platform"
    assert flat["metadata_env"] == "production"
    assert flat["metadata_service"] == "my-llm-app"
    assert flat["metadata"] == triggered_payload["metadata"]


def test_metadata_keys_with_unsafe_characters_are_sanitized():
    flat = flatten({"metadata": {"cost center": "x", "team.name": "y", "": "z"}})

    assert flat["metadata_cost_center"] == "x"
    assert flat["metadata_team_name"] == "y"
    assert flat["metadata_unnamed"] == "z"


def test_original_payload_is_preserved_unchanged(triggered_payload):
    pristine = copy.deepcopy(triggered_payload)

    flat = flatten(triggered_payload)

    assert flat["original"] == pristine


def test_cleared_event_shares_dedup_key_and_is_informational(
    triggered_payload, cleared_payload
):
    triggered = flatten(triggered_payload)
    cleared = flatten(cleared_payload)

    assert cleared["dedup_key"] == triggered["dedup_key"]
    assert cleared["event_type"] == "alert.cleared"
    assert cleared["severity"] == "informational"


def test_minimal_payload_without_scope_conditions_or_metadata(minimal_payload):
    flat = flatten(minimal_payload)

    assert flat["parse_ok"] is True
    assert flat["alert_name"] == "Test event"
    assert flat["condition_count"] == 0
    # Absent fields are dropped rather than written to Splunk as nulls.
    assert "metric" not in flat
    assert "project_name" not in flat
    assert "metadata" not in flat


def test_unknown_shapes_are_tolerated_not_rejected():
    # Wrong types everywhere; must not raise.
    flat = flatten({"alert": "not-an-object", "conditions": "nope", "metadata": 5})

    assert flat["condition_count"] == 0
    assert flat["severity"] == "unknown"
    assert flat["original"]["alert"] == "not-an-object"


def test_extra_unknown_fields_survive_in_original():
    payload = {"event": "alert.triggered", "brand_new_field": {"nested": 1}}

    flat = flatten(payload)

    assert flat["parse_ok"] is True  # extra keys are allowed, not an error
    assert flat["original"]["brand_new_field"] == {"nested": 1}


def test_parse_ok_false_when_payload_violates_known_schema():
    # `conditions` must be a list of objects; a list of scalars is a real mismatch.
    flat = flatten({"conditions": [123]})

    assert flat["parse_ok"] is False
    assert flat["original"]["conditions"] == [123]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("triggered", "high"),
        ("TRIGGERED", "high"),
        ("healthy", "informational"),
        ("cleared", "informational"),
        ("resolved", "informational"),
        ("something-else", "unknown"),
        (None, "unknown"),
        (42, "unknown"),
    ],
)
def test_severity_mapping(status, expected):
    assert severity_for(status) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2024-01-15T10:30:00Z", datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc).timestamp()),
        ("2024-01-15T10:30:00+00:00", datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc).timestamp()),
        # Naive timestamps are read as UTC rather than local time.
        ("2024-01-15T10:30:00", datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc).timestamp()),
    ],
)
def test_parse_timestamp_variants(value, expected):
    assert parse_timestamp(value) == expected


@pytest.mark.parametrize("value", ["", "not-a-date", None, 12345, "   "])
def test_parse_timestamp_rejects_junk(value):
    assert parse_timestamp(value) is None


def test_envelope_uses_payload_timestamp_as_event_time(triggered_payload, settings):
    envelope = to_hec_envelope(flatten(triggered_payload), settings, received_at=999.0)

    assert envelope["time"] == datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc).timestamp()
    assert envelope["index"] == "sao_alerts"
    assert envelope["sourcetype"] == "splunk:sao:alert"
    assert envelope["source"] == "sao:webhook"
    assert envelope["host"] == "test-host"
    assert envelope["event"]["alert_name"] == "High hallucination rate"


def test_envelope_falls_back_to_receipt_time(settings):
    envelope = to_hec_envelope(flatten({"timestamp": "garbage"}), settings, received_at=1234.5)

    assert envelope["time"] == 1234.5


# --- SAO console deep-link rewriting -----------------------------------------


class _Console:
    """Minimal stand-in for Settings; only the fields the rewrite reads."""

    def __init__(self, url="https://console.multitenant.sao.splunkcloud.com",
                 tenant="your-tenant", stream_segment="agent-streams"):
        self.sao_console_url = url
        self.sao_tenant = tenant
        self.sao_stream_segment = stream_segment


# A deep_link exactly as SAO stamps it: no tenant segment, "log-streams" path.
SAO_LINK = (
    "https://console.multitenant.sao.splunkcloud.com"
    "/project/33333333-3333-4333-8333-333333333333"
    "/log-streams/44444444-4444-4444-8444-444444444444"
    "?timeRange=%7B%22type%22%3A%20%22custom%22%7D&tableLevel=traces"
)

# The same link from a console on a different origin, so the host-retargeting
# half of the rewrite stays covered.
OTHER_ORIGIN_LINK = SAO_LINK.replace(
    "https://console.multitenant.sao.splunkcloud.com", "https://console.example.com"
)


def test_rewrite_inserts_tenant_and_retargets_stream_segment():
    from app.transform import rewrite_deep_link

    got = rewrite_deep_link(SAO_LINK, _Console())

    assert got == (
        "https://console.multitenant.sao.splunkcloud.com/your-tenant"
        "/project/33333333-3333-4333-8333-333333333333"
        "/agent-streams/44444444-4444-4444-8444-444444444444"
        "?timeRange=%7B%22type%22%3A%20%22custom%22%7D&tableLevel=traces"
    )


def test_rewrite_retargets_a_console_on_another_origin():
    from app.transform import rewrite_deep_link

    got = rewrite_deep_link(OTHER_ORIGIN_LINK, _Console())

    assert got == (
        "https://console.multitenant.sao.splunkcloud.com/your-tenant"
        "/project/33333333-3333-4333-8333-333333333333"
        "/agent-streams/44444444-4444-4444-8444-444444444444"
        "?timeRange=%7B%22type%22%3A%20%22custom%22%7D&tableLevel=traces"
    )


def test_rewrite_preserves_query_string_byte_for_byte():
    from app.transform import rewrite_deep_link

    got = rewrite_deep_link(SAO_LINK, _Console())

    assert got.split("?", 1)[1] == SAO_LINK.split("?", 1)[1]


def test_rewrite_is_a_no_op_without_a_console_url():
    from app.transform import rewrite_deep_link

    assert rewrite_deep_link(SAO_LINK, _Console(url="")) == SAO_LINK
    assert rewrite_deep_link(SAO_LINK, None) == SAO_LINK


def test_rewrite_leaves_unrecognised_links_alone():
    from app.transform import rewrite_deep_link

    for odd in [
        "https://example.com/nothing/useful/here",  # no /project segment
        "not-a-url",                                # unparseable as absolute
        "",
        None,
        12345,
    ]:
        assert rewrite_deep_link(odd, _Console()) == odd


def test_rewrite_without_tenant_omits_the_prefix():
    from app.transform import rewrite_deep_link

    got = rewrite_deep_link(SAO_LINK, _Console(tenant=""))

    assert got.startswith(
        "https://console.multitenant.sao.splunkcloud.com/project/"
    )


def test_flatten_rewrites_deep_link_and_keeps_the_original(triggered_payload):
    payload = copy.deepcopy(triggered_payload)
    payload["deep_link"] = SAO_LINK

    flat = flatten(payload, _Console())

    assert flat["deep_link"].startswith(
        "https://console.multitenant.sao.splunkcloud.com/your-tenant/project/"
    )
    assert flat["deep_link_source"] == SAO_LINK
    # The untouched payload must still carry what SAO actually sent.
    assert flat["original"]["deep_link"] == SAO_LINK


def test_flatten_without_settings_leaves_deep_link_untouched(triggered_payload):
    payload = copy.deepcopy(triggered_payload)
    payload["deep_link"] = SAO_LINK

    flat = flatten(payload)

    assert flat["deep_link"] == SAO_LINK
    assert "deep_link_source" not in flat
