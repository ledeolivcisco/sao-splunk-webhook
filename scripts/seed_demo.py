#!/usr/bin/env python3
"""Seed a believable SAO alert history for a demo.

Generates SAO-shaped webhook payloads spread over the last N hours and POSTs
them at the bridge, so the whole path (webhook -> transform -> HEC -> index)
is exercised exactly as it will be during the live portion of the demo.

    ./scripts/seed_demo.py                  # 48h of history at the bridge
    ./scripts/seed_demo.py --hours 24
    ./scripts/seed_demo.py --dry-run        # print payloads, send nothing
    ./scripts/seed_demo.py --live           # one fresh "now" alert, the hero
    TARGET=https://host/webhook/sao ./scripts/seed_demo.py

Field shape follows what SAO actually sends today (scope.log_stream_*,
string-valued thresholds), not the older agent_stream_* samples.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import sys
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Placeholder org id. Replace with your own to make seeded events line up with
# what the SAO console shows for your tenant.
ORG_ID = "11111111-1111-4111-8111-111111111111"
CONSOLE = "https://console.multitenant.sao.splunkcloud.com"

# Metric-column filter id stamped into the deep link's query string. A filter id
# the console cannot resolve still produces a valid link, it just lands on the
# stream's front page instead of the offending traces. Paste the id from a
# genuine SAO alert to make the filter meaningful.
FILTER_ID = "22222222-2222-4222-8222-222222222222"

# All ids below are placeholders, so every deep link 404s until you replace them.
# Paste a real project_id / log_stream_id from your tenant into one of these and
# flip its "real" flag to True; --real-only then seeds only that project, and
# seeded history lines up with anything fired live during the demo.
PROJECTS = [
    {
        "project_id": "33333333-3333-4333-8333-333333333333",
        "project_name": "demo-project",
        "log_stream_id": "44444444-4444-4444-8444-444444444444",
        "log_stream_name": "demo-stream",
        "metadata": {"team": "customer-experience", "env": "production", "service": "support-agent"},
        # Paste real ids above and flip this to True - see note on PROJECTS.
        "real": False,
    },
    {
        "project_id": "3b1f90ae-7c42-4a1d-9f88-2d6e5c0b7a31",
        "project_name": "atlas-copilot",
        "log_stream_id": "c4d2e118-33b9-4f07-8a56-91ec7b240d6f",
        "log_stream_name": "atlas-prod",
        "metadata": {"team": "platform", "env": "production", "service": "atlas-copilot"},
        # Invented identifiers: deep links for this project will 404 in the SAO
        # console. Paste real project/log-stream ids here to make them resolve.
        "real": False,
    },
    {
        "project_id": "9e77c41b-05da-4ec6-b2f3-8a1047dd6c92",
        "project_name": "ledger-assist",
        "log_stream_id": "6f0b3a27-18c5-4d93-ae41-72b9f5e8c103",
        "log_stream_name": "ledger-staging",
        "metadata": {"team": "fintech", "env": "staging", "service": "ledger-assist"},
        # Invented identifiers - see note above.
        "real": False,
    },
]

# Guardrail metrics SAO evaluates, with the condition shape each one produces.
SCENARIOS = [
    {"name": "Prompt Injection", "metric": "Prompt Injection", "aggregation": "Count_true",
     "operator": "greater than or equals", "threshold": "1", "hot": ("2.0", "7.0"), "weight": 4},
    {"name": "PII Detected", "metric": "PII", "aggregation": "Count_true",
     "operator": "greater than or equals", "threshold": "1", "hot": ("1.0", "4.0"), "weight": 3},
    {"name": "Toxicity", "metric": "Toxicity", "aggregation": "Count_true",
     "operator": "greater than or equals", "threshold": "1", "hot": ("1.0", "3.0"), "weight": 2},
    {"name": "Low Context Adherence", "metric": "metrics/context_adherence", "aggregation": "Average",
     "operator": "less than", "threshold": "0.5", "hot": ("0.18", "0.47"), "weight": 3},
    {"name": "Unsafe Tool Call", "metric": "Tool Error Rate", "aggregation": "Average",
     "operator": "greater than", "threshold": "0.2", "hot": ("0.31", "0.78"), "weight": 2},
    {"name": "Action Advancement Drop", "metric": "metrics/action_advancement", "aggregation": "Average",
     "operator": "less than", "threshold": "0.6", "hot": ("0.22", "0.55"), "weight": 1},
]


def _deep_link(project_id: str, stream_id: str, fired: datetime) -> str:
    end_ms = int(fired.timestamp() * 1000)
    start_ms = end_ms - 15 * 60 * 1000
    time_range = json.dumps({"type": "custom", "startTime": start_ms, "endTime": end_ms})
    filters = json.dumps([{"id": FILTER_ID, "operator": "eq", "value": "true"}])
    query = urllib.parse.urlencode(
        {"timeRange": time_range, "filters": filters, "tableLevel": "traces"},
        quote_via=urllib.parse.quote,
    )
    return f"{CONSOLE}/project/{project_id}/log-streams/{stream_id}?{query}"


def _payload(scenario, project, fired, *, cleared=False, alert_id=None, link=None, observed=None):
    alert_id = alert_id or str(uuid.uuid4())
    link = link or _deep_link(project["project_id"], project["log_stream_id"], fired)
    if cleared:
        status, previous = "healthy", "triggered"
    else:
        status, previous = "triggered", "healthy"
    if observed is None:
        lo, hi = (float(x) for x in scenario["hot"])
        # Count_true is a count of flagged traces: whole numbers only.
        observed = f"{round(random.uniform(lo, hi)):.1f}" if scenario["aggregation"] == "Count_true" \
            else f"{random.uniform(lo, hi):.2f}"
    return {
        "version": "1.0",
        "event": "alert.cleared" if cleared else "alert.triggered",
        "event_id": str(uuid.uuid4()),
        "timestamp": fired.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "alert": {"id": alert_id, "name": scenario["name"], "status": status, "previous_status": previous},
        "scope": {
            "org_id": ORG_ID,
            "project_id": project["project_id"],
            "project_name": project["project_name"],
            "log_stream_id": project["log_stream_id"],
            "log_stream_name": project["log_stream_name"],
        },
        "conditions": [{
            "metric": scenario["metric"],
            "aggregation": scenario["aggregation"],
            "operator": scenario["operator"],
            "threshold": scenario["threshold"],
            "observed_value": observed,
        }],
        "dedup_key": f"{alert_id}:{project['project_id']}:{project['log_stream_id']}",
        "deep_link": link,
        "metadata": project["metadata"],
    }


def build_history(hours: int, count: int, seed: int, only: str | None = None,
                  real_only: bool = False) -> list[dict]:
    rng = random.Random(seed)
    random.seed(seed)
    now = datetime.now(timezone.utc)
    pool = [s for s in SCENARIOS for _ in range(s["weight"])]
    pool_projects = [p for p in PROJECTS if p["real"]] if real_only else PROJECTS
    if not pool_projects:
        raise SystemExit("--real-only: no project is marked real. Paste real "
                         "project/log-stream ids into PROJECTS and set \"real\": True.")
    picks = [p for p in pool_projects if p["project_name"] == only] if only else None
    if only and not picks:
        raise SystemExit(f"no such project: {only} (have: {', '.join(p['project_name'] for p in PROJECTS)})")
    events: list[dict] = []
    for _ in range(count):
        scenario = rng.choice(pool)
        if picks:
            project = picks[0]
        else:
            # Weight the hero project so the demo story has a clear subject.
            project = pool_projects[0] if rng.random() < 0.5 else rng.choice(pool_projects)
        # Keep history out of the last 30 minutes; that window is for the live fire.
        fired = now - timedelta(minutes=rng.randint(31, hours * 60))
        alert_id = str(uuid.uuid4())
        link = _deep_link(project["project_id"], project["log_stream_id"], fired)
        events.append(_payload(scenario, project, fired, alert_id=alert_id, link=link))
        # Most alerts recover; a few stay open so Incident Review has live work.
        if rng.random() < 0.65:
            recovered = fired + timedelta(minutes=rng.randint(6, 90))
            if recovered < now - timedelta(minutes=30):
                ok = "0.0" if scenario["aggregation"] == "Count_true" else f"{float(scenario['threshold']) + 0.2:.2f}"
                events.append(_payload(scenario, project, recovered, cleared=True,
                                       alert_id=alert_id, link=link, observed=ok))
    return sorted(events, key=lambda e: e["timestamp"])


def build_live() -> list[dict]:
    """One unmistakable hero alert, stamped now, on the hero project."""
    scenario = SCENARIOS[0]  # Prompt Injection
    return [_payload(scenario, PROJECTS[0], datetime.now(timezone.utc), observed="9.0")]


def webhook_token() -> str | None:
    token = os.environ.get("WEBHOOK_TOKEN")
    if token:
        return token
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("WEBHOOK_TOKEN="):
                return line.split("=", 1)[1].strip() or None
    return None


def post(target: str, payload: dict, token: str | None) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(target, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:200]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=int, default=48, help="how far back history spreads (default 48)")
    ap.add_argument("--count", type=int, default=14, help="number of triggered alerts (default 14)")
    ap.add_argument("--seed", type=int, default=20261117, help="RNG seed, for repeatable demos")
    ap.add_argument("--project", help="restrict history to one project by name")
    ap.add_argument("--real-only", action="store_true",
                    help="only use projects whose ids are real, so every deep link resolves")
    ap.add_argument("--live", action="store_true", help="send one hero alert stamped now instead of history")
    ap.add_argument("--dry-run", action="store_true", help="print payloads, send nothing")
    ap.add_argument("--target", default=os.environ.get("TARGET", "http://localhost:8088/webhook/sao"))
    args = ap.parse_args()

    events = build_live() if args.live else build_history(
        args.hours, args.count, args.seed, args.project, args.real_only)

    if args.dry_run:
        for e in events:
            print(json.dumps(e))
        print(f"\n{len(events)} payloads (dry run, nothing sent)", file=sys.stderr)
        return 0

    fake = sorted({e["scope"]["project_name"] for e in events
                   if not next(p for p in PROJECTS
                               if p["project_name"] == e["scope"]["project_name"])["real"]})
    if fake:
        print(f"WARNING: {', '.join(fake)} use placeholder project/log-stream ids. "
              f"Their deep links will 404 in the SAO console.\n"
              f"         Paste real ids into PROJECTS and set \"real\": True, "
              f"then use --real-only.", file=sys.stderr)

    token = webhook_token()
    ok = 0
    for e in events:
        status, body = post(args.target, e, token)
        mark = "ok " if status == 200 else "ERR"
        ok += status == 200
        print(f"{mark} {status} {e['timestamp']}  {e['alert']['name']:<26} "
              f"{e['scope']['project_name']:<14} {e['event'].split('.')[-1]:<9} {body if status != 200 else ''}")
    print(f"\n{ok}/{len(events)} accepted by {args.target}", file=sys.stderr)
    return 0 if ok == len(events) else 1


if __name__ == "__main__":
    raise SystemExit(main())
