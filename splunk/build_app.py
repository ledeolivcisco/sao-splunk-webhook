#!/usr/bin/env python3
"""Build the `sao_es_demo` Splunk app from the canonical SPL and dashboard XML.

One source of truth: splunk/notable_macro.spl and splunk/sao_incident_review.xml
feed both the REST installer (splunk/install.py, for fast iteration against a
lab instance) and this packager (for shipping to any other environment).

    ./splunk/build_app.py              # writes splunk/dist/sao_es_demo{,.tar.gz}
    ./splunk/build_app.py --version 1.1.0
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import tarfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent
APP = "sao_es_demo"
CORR = "SAO - Guardrail Breach - Rule"


def conf_value(spl: str) -> str:
    """Render multi-line SPL as a .conf value using backslash continuations."""
    lines = [ln.rstrip() for ln in spl.strip().splitlines()]
    return " \\\n".join(lines)


def build(version: str) -> pathlib.Path:
    dist = ROOT / "dist"
    app = dist / APP
    if app.exists():
        shutil.rmtree(app)
    for d in ("default/data/ui/views", "default/data/ui/nav", "metadata", "optional"):
        (app / d).mkdir(parents=True, exist_ok=True)

    macro_spl = (ROOT / "notable_macro.spl").read_text()
    dash_xml = (ROOT / "sao_incident_review.xml").read_text()

    (app / "default/app.conf").write_text(f"""# {APP} - SAO AI guardrail alerts, triaged like ES notables.
[install]
is_configured = 1
state = enabled

[package]
id = {APP}

[ui]
is_visible = 1
label = SAO AI Guardrails

[launcher]
author = Splunk
description = Turns Splunk AI Observability guardrail alerts into ES-style notables, with one-click pivot back into SAO.
version = {version}
""")

    (app / "default/macros.conf").write_text(f"""# Base search. Override in local/macros.conf to point at a different index.
[sao_index]
definition = index=sao_alerts
iseval = 0
description = Where the SAO webhook bridge lands alerts.

# Reshapes raw SAO alerts into ES-style notables: urgency, status, owner, dwell.
# Invoke it bare - `sao_notables` - never as `search `sao_notables``: Splunk Web
# already prepends "search" to panel queries that do not start with a pipe.
[sao_notables]
definition = {conf_value(macro_spl)}
iseval = 0
description = SAO guardrail alerts as notables (urgency, status, owner, dwell_seconds).
""")

    corr_spl = ('`sao_notables` | search status="New" urgency IN ("critical","high") '
                '| table _time urgency title condition observed_value threshold '
                'project_name stream owner env deep_link deep_link_source')
    (app / "default/savedsearches.conf").write_text(f"""[{CORR}]
search = {corr_spl}
description = Correlation search: raises a notable for every high-or-critical AI guardrail breach \\
reported by Splunk AI Observability. Pivot via deep_link to the offending traces in SAO.
cron_schedule = */5 * * * *
enableSched = 1
dispatch.earliest_time = -15m
dispatch.latest_time = now
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.track = 1
alert.severity = 4
alert.suppress = 1
alert.suppress.fields = dedup_key
alert.suppress.period = 3600s
disabled = 0
""")

    (app / "default/workflow_actions.conf").write_text("""# Pivot from any raw SAO event straight to the traces in the SAO console.
[view_in_sao]
label = View in SAO
type = link
fields = deep_link
display_location = both
link.method = get
link.target = blank
link.uri = $deep_link$
""")

    (app / "default/props.conf").write_text("""# Events arrive from the HEC bridge as a JSON object; _time is set by the HEC
# envelope from the alert's own timestamp, so no timestamp extraction is needed.
[splunk:sao:alert]
KV_MODE = json
SHOULD_LINEMERGE = false
TRUNCATE = 50000
category = Application
description = SAO alert webhook, forwarded by the SAO -> HEC bridge
""")

    (app / "default/data/ui/views/sao_incident_review.xml").write_text(dash_xml)

    (app / "default/data/ui/nav/default.xml").write_text("""<nav search_view="search" color="#65A637">
  <view name="sao_incident_review" default="true"/>
  <view name="search"/>
  <saved name="SAO - Guardrail Breach - Rule"/>
</nav>
""")

    (app / "metadata/default.meta").write_text("""# Export everything system-wide so the macro and dashboard resolve from any app.
[]
access = read : [ * ], write : [ admin, power ]
export = system
""")

    (app / "optional/indexes.conf").write_text("""# Splunk Enterprise only. Copy to default/ (or an indexer app) to create the index.
# On Splunk Cloud, indexes.conf is not accepted in an app - create `sao_alerts`
# through Settings > Indexes or the ACS API instead.
[sao_alerts]
homePath   = $SPLUNK_DB/sao_alerts/db
coldPath   = $SPLUNK_DB/sao_alerts/colddb
thawedPath = $SPLUNK_DB/sao_alerts/thaweddb
frozenTimePeriodInSecs = 7776000
""")

    (app / "optional/inputs.conf.example").write_text("""# HEC input the bridge posts to. Tokens are per-instance secrets: generate one
# on the target instance and paste it here, or create the input via the UI.
[http://sao_bridge]
disabled = 0
index = sao_alerts
indexes = sao_alerts
sourcetype = splunk:sao:alert
token = REPLACE-WITH-A-REAL-HEC-TOKEN
""")

    (app / "README.md").write_text(f"""# {APP}

SAO AI guardrail alerts, triaged like Enterprise Security notables, with a one-click
pivot back into the SAO console.

Version {version}.

## Prerequisites

- Splunk Enterprise or Splunk Cloud, 9.0+. Tested on 10.6.1.
- An account with the `admin` role — the app exports its objects system-wide.
- **Enterprise Security is NOT required.** This app imitates the Incident Review
  workflow using core Splunk only; it does not read or write ES notables.
- The SAO -> HEC bridge, which feeds the index this app searches. Without it the
  app installs cleanly and every panel reads zero.

## Install

**Splunk Enterprise**

    tar -xzf {APP}.tar.gz -C $SPLUNK_HOME/etc/apps/
    $SPLUNK_HOME/bin/splunk restart

**Splunk Cloud, or Enterprise via the UI** — Apps > Manage Apps > Install app from
file > upload `{APP}.tar.gz` > Upload. Restart if prompted. On Cloud, private apps
may need self-service install or Support-assisted vetting.

A restart is needed for `macros.conf` and `props.conf` to take effect. Dashboards and
nav load without one.

Once installed it appears as **SAO AI Guardrails** in the app menu, and the dashboard
is at:

    /en-US/app/{APP}/sao_incident_review

## Set up the data path

**1. Create the index.** This app searches `sao_alerts`.

- Enterprise: copy `optional/indexes.conf` into `default/` and restart, or create it
  in Settings > Indexes > New Index.
- Cloud: Settings > Indexes > New Index, or the ACS API. `indexes.conf` inside an app
  is not accepted on Cloud.
- Using a different name? Override one line in `local/macros.conf` and nothing else
  changes:

      [sao_index]
      definition = index=my_other_index

**2. Enable HEC and mint a token.**

- Settings > Data inputs > HTTP Event Collector > New Token.
- Name it, set **Source type** to `splunk:sao:alert` and **Index** to `sao_alerts`.
- Then Global Settings > **All Tokens: Enabled**. HEC is off by default and this is
  the step most often missed.
- Note the endpoint: Enterprise is `https://<host>:8088`, Cloud is
  `https://http-inputs-<stack>.splunkcloud.com:443`.
- `optional/inputs.conf.example` shows the same thing as config, if you deploy inputs
  that way instead.

**3. Point the bridge at it.** In the bridge's `.env`:

      HEC_URL=https://<host>:8088
      HEC_TOKEN=<the token from step 2>
      HEC_INDEX=sao_alerts

**4. Retarget the deep links** — see the next section. Skip it and the drilldown 404s.

**5. Register the webhook in SAO** so alerts reach the bridge, or generate data with
`./scripts/seed_demo.py` (history) and `--live` (one fresh alert) from the bridge repo.

## Verify the install

Run these in Search, in this app's context. Each one isolates a different link in the
chain, so the first that fails tells you where the problem is.

    | rest /services/apps/local/{APP} | table label version
    --> one row. The app is installed.

    `sao_index` | stats count
    --> non-zero. The index exists, HEC works, the bridge is delivering.
        Zero means the data path is broken, not the app.

    `sao_notables` | stats count by urgency
    --> rows by urgency. The macro resolves and notables are being built.

    `sao_notables` | table title deep_link deep_link_source
    --> deep_link should point at YOUR console host. If it points somewhere else,
        the bridge rewrite is not configured (see below).

Then open the dashboard. Panels populate and clicking a notable row opens that alert's
traces in the SAO console, in a new tab.

## Uninstall

Apps > Manage Apps > Actions > Delete, or remove `$SPLUNK_HOME/etc/apps/{APP}` and
restart. Indexed data is untouched; delete the `sao_alerts` index separately if you
want it gone.

## Deep links: the drilldown depends on the bridge

Clicking a notable opens that alert's `deep_link`. SAO stamps that field with **its own**
console host and path layout, which may not match the console a tenant actually uses:

    SAO sends   https://console.multitenant.sao.splunkcloud.com/project/{{p}}/log-streams/{{s}}?...
    tenant uses https://console.multitenant.sao.splunkcloud.com/your-tenant/project/{{p}}/agent-streams/{{s}}?...

This app does not rewrite anything — **the bridge does**, before indexing. Set in its `.env`:

    SAO_CONSOLE_URL=https://console.multitenant.sao.splunkcloud.com
    SAO_TENANT=your-tenant
    SAO_STREAM_SEGMENT=agent-streams

Events indexed before those were set keep the original host and will still 404. The
pre-rewrite URL is preserved on every event as `deep_link_source`, so you can always
see what SAO actually sent:

    `sao_notables` | table _time title deep_link deep_link_source

## What is in it

| Object | Name |
|---|---|
| Macro | `sao_index`, `sao_notables` |
| Saved search | {CORR} |
| Workflow action | View in SAO |
| Dashboard | Incident Review — SAO AI Guardrails |
| Sourcetype | `splunk:sao:alert` |

Everything is exported system-wide, so `sao_notables` resolves from any app.

The dashboard also carries a **hardcoded button** to one SAO agent stream, above the KPI
tiles. It is a demo convenience, not driven by data — edit the `<a href>` in
`default/data/ui/views/sao_incident_review.xml` to repoint it, or delete that `<row>`.

## Troubleshooting

**Drilldown goes to a Splunk page-not-found.** The token must carry the no-escape
filter: `$row.deep_link|n$`. Without `|n`, Splunk URL-encodes the value, `https://`
becomes `https%3A%2F%2F`, and the result is treated as a path relative to Splunk.

**Drilldown opens the SAO console but 404s there.** The link points at a console host
or path that does not exist for this tenant — configure the bridge rewrite above.
Compare `deep_link` against `deep_link_source` to see which is being used.

**Panels are empty but the SPL works when you paste it in.** Do not prefix the macro
with `search` in a panel. Splunk Web already prepends `search` to any panel query that
does not start with `|`, so ``search `sao_notables` `` becomes `search search index=...`
and silently returns nothing. Panels must invoke the macro bare.

**You edited a shared object and nothing changed.** A user-private copy is shadowing
the app's. Check `servicesNS/-/-/configs/conf-macros` for duplicates and delete the
private one.

## Local overrides

Never edit `default/`. Put changes in `local/` — they survive upgrades:

    local/macros.conf          # different index
    local/savedsearches.conf   # different schedule or thresholds
""")

    tgz = dist / f"{APP}.tar.gz"
    if tgz.exists():
        tgz.unlink()
    with tarfile.open(tgz, "w:gz") as tar:
        tar.add(app, arcname=APP)
    return tgz


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.1.0")
    a = ap.parse_args()
    tgz = build(a.version)

    # Fail loudly rather than shipping a broken package.
    ET.parse(ROOT / "dist" / APP / "default/data/ui/views/sao_incident_review.xml")
    ET.parse(ROOT / "dist" / APP / "default/data/ui/nav/default.xml")
    files = sorted(p.relative_to(ROOT / "dist") for p in (ROOT / "dist" / APP).rglob("*") if p.is_file())
    for f in files:
        print(f"  {f}")
    print(f"\n{tgz}  ({tgz.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
