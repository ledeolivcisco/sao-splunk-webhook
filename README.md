# SAO → Splunk HEC webhook bridge

Receives alert webhooks from **Splunk Agent Observability (SAO)** and forwards them to
**Splunk HTTP Event Collector (HEC)**, so SAO alerts land in a Splunk index and are available to
Enterprise Security content.

SAO's generic webhook can POST to any URL, but it speaks its own JSON envelope and HEC expects its
own. This service is the hop in between: it authenticates SAO, reshapes the payload into
search-friendly fields, and ships it to HEC with retries.

```
SAO alert  ──POST /webhook/sao──▶  bridge  ──POST /services/collector/event──▶  Splunk
           Authorization: Bearer            Authorization: Splunk <hec-token>
```

## What it does

- **Authenticates** SAO with a bearer token (constant-time compare).
- **Flattens** the nested SAO payload into top-level fields — `alert_name`, `alert_status`,
  `metric`, `observed_value`, `threshold`, `dedup_key`, `metadata_*` — so SPL needs no `spath`.
- **Keeps the original** payload intact under `original`, so nothing SAO sends is ever lost,
  including fields added after this was written.
- **Sets event time** from the payload's `timestamp`, so `_time` in Splunk is when the alert fired,
  not when it was indexed.
- **Acks immediately** and forwards in the background with bounded exponential backoff.

## Quick start

```bash
cp .env.example .env
# edit .env: WEBHOOK_TOKEN, HEC_URL, HEC_TOKEN, HEC_INDEX

docker compose up --build
curl localhost:8088/healthz        # {"status":"ok","version":"1.0.0"}

./scripts/send_sample.sh           # replay samples/alert_triggered.json
```

Without Docker:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e ".[dev]"
./.venv/bin/python -m uvicorn app.main:app --port 8088
```

## Demo assets

Everything needed to show SAO alerts arriving in a Splunk ES-style Incident Review and pivoting
back into SAO.

### Seeding alert history

`scripts/seed_demo.py` generates SAO-shaped payloads and POSTs them at the bridge, so the full path
(webhook -> transform -> HEC -> index) is exercised exactly as it is in production.

```bash
./scripts/seed_demo.py                          # ~25 events over the last 48h, 3 projects
./scripts/seed_demo.py --project atlas-copilot --count 4
./scripts/seed_demo.py --live                   # one hero alert stamped "now"
./scripts/seed_demo.py --dry-run                # print payloads, send nothing
```

History is kept out of the last 30 minutes so a live fire during the demo stands alone at the top
of the list. `--seed` makes a run repeatable.

### Splunk content

The Splunk side ships as a self-contained app, `sao_es_demo`, so it reproduces on any instance.
`splunk/notable_macro.spl` and `splunk/sao_incident_review.xml` are the single source of truth —
both the package and the REST installer are generated from them, so they cannot drift.

```bash
./splunk/build_app.py                     # -> splunk/dist/sao_es_demo.tar.gz (v1.1.0)
```

Install the tarball on the target: Apps > Manage Apps > Install app from file, or on Enterprise
untar into `$SPLUNK_HOME/etc/apps/` and restart. `splunk/dist/sao_es_demo/README.md` covers the
index, the HEC input, and overriding things per environment.

| Object | Name | Purpose |
|---|---|---|
| Macro | `sao_index` | The base search, `index=sao_alerts`. Override in `local/macros.conf` to relocate the whole app to another index. |
| Macro | `sao_notables` | Reshapes raw SAO alerts into ES-style notables: `urgency`, `status`, `owner`, `dwell_seconds`. Pairs each `alert.triggered` with a later `alert.cleared` to decide New vs Closed. |
| Saved search | `SAO - Guardrail Breach - Rule` | The correlation search. Every 5 min over `-15m`, raises high/critical breaches. Tracked under Activity > Triggered Alerts, suppressed 1h on `dedup_key`. |
| Workflow action | `View in SAO` | On any raw event carrying `deep_link`, opens the SAO console at the offending traces. |
| Dashboard | `sao_incident_review` | Incident Review lookalike. Clicking a notable row opens its SAO evidence in a new tab (drilldown uses `$row.deep_link|n$` — the `|n` is required, see below). Carries a static button to one SAO agent stream above the KPI tiles; its URL is a placeholder, replace it with a link from your own console. |
| Sourcetype | `splunk:sao:alert` | `KV_MODE = json`, so the flattened fields extract without `spath`. |

Only the index and the HEC token are environment-specific. Nothing else needs editing.

### Iterating against a lab instance

`splunk/install.py` pushes the same objects straight into an already-installed `sao_es_demo` over
the Splunk Web REST proxy — seconds instead of a rebuild-and-upload cycle. It is a development
convenience, not the deployment path.

```bash
curl -sk -c cj.txt -L -o /dev/null \
  "$SPLUNK_WEB/en-US/account/insecurelogin?return_to=app/launcher&loginType=splunk&username=$U&password=$P"
COOKIES=cj.txt SPLUNK_WEB=https://your-sh.example.com python3 splunk/install.py
```

Two gotchas worth knowing, both learned the hard way:

**Do not prefix the macro with `search` in the dashboard.** Splunk Web already prepends `search` to
any panel query that does not start with `|`, so ``search `sao_notables` `` becomes
`search search index=sao_alerts ...` and quietly returns nothing. Panels invoke the macro bare. The
REST search endpoint does *not* auto-prepend, so a panel query tested over REST must have `search `
added by hand — otherwise the test does not reproduce what the browser runs.

**Objects are created with `owner=nobody`, inside the app.** Creating them as a user and then
promoting the ACL to global leaves the original behind on the next run, and a user-private copy
silently shadows the shared one — so you edit the shared object and see no change.

## Configuration

All settings come from environment variables (or `.env`). See [.env.example](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_TOKEN` | *(required)* | Bearer token SAO must present. Startup fails if unset. |
| `ALLOW_INSECURE` | `false` | Permit an empty `WEBHOOK_TOKEN`. **Local testing only.** |
| `HEC_URL` | *(required)* | Base URL. The app appends `/services/collector/event`. |
| `HEC_TOKEN` | *(required)* | Splunk HEC token. |
| `HEC_INDEX` | `sao_alerts` | Target index. Must be in the HEC token's allowed indexes. |
| `HEC_SOURCETYPE` | `splunk:sao:alert` | |
| `HEC_SOURCE` | `sao:webhook` | |
| `HEC_HOST` | container hostname | Value of `host` on the indexed event. |
| `HEC_VERIFY_TLS` | `true` | Set `false` only for a lab Splunk with a self-signed cert. |
| `HEC_TIMEOUT_SECONDS` | `10` | Per-attempt timeout. |
| `RETRY_MAX_ATTEMPTS` | `5` | |
| `RETRY_BASE_DELAY` / `RETRY_MAX_DELAY` | `0.5` / `30` | Exponential backoff with full jitter. |
| `LOG_LEVEL` | `INFO` | |

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/webhook/sao` | The URL to register in SAO. |
| `GET` | `/healthz` | Liveness, backs the container healthcheck. |

Responses from `/webhook/sao`:

| Code | Meaning |
|---|---|
| `200` | Accepted and queued for HEC: `{"status":"accepted","event_id":…,"dedup_key":…}` |
| `400` | Body was not a JSON object |
| `401` | Missing or wrong bearer token |

## Splunk setup

1. **Create the index** (`sao_alerts`, or whatever you set in `HEC_INDEX`).
2. **Create a HEC token** — Settings → Data inputs → HTTP Event Collector → New Token.
   Set the allowed indexes to include your index. Leave *Enable indexer acknowledgement* **off**
   (this service posts to `/services/collector/event` without channel IDs).
3. Note the HEC URL: `https://<splunk>:8088` for Splunk Enterprise, or
   `https://http-inputs-<stack>.splunkcloud.com:443` for Splunk Cloud.

## SAO setup

In the Agent Stream's **Alerts** tab, under **Webhook (Generic)**:

- **URL:** `https://<your-host>/webhook/sao`
- **Auth type:** `Header token` — paste the same value as `WEBHOOK_TOKEN`.
  SAO sends it as `Authorization: Bearer <token>`.
- **Metadata:** any key/value pairs you add are echoed back in the payload and arrive in Splunk as
  both `metadata_<key>` fields and an intact `metadata` object. Useful for `team`, `env`, `service`.
- Click **Send test event** — the badge should flip to **Active**.

> **SAO must be able to reach this service.** It is an outbound call from Splunk's cloud, so the
> bridge needs a publicly resolvable URL (or a tunnel for lab work). This service does not solve
> ingress for you; put it behind a reverse proxy that terminates TLS.

## Checking it in Splunk

```spl
index=sao_alerts sourcetype=splunk:sao:alert
| table _time alert_name alert_status severity metric observed_value threshold dedup_key
| sort - _time
```

> **Set the time picker to All time when testing.** `_time` comes from the alert's own
> `timestamp` field, not from ingest time — see [Troubleshooting](#troubleshooting-the-script-returns-200-but-nothing-is-in-splunk).

Match a trigger with its clear:

```spl
index=sao_alerts sourcetype=splunk:sao:alert
| stats earliest(_time) as fired latest(_time) as cleared values(alert_name) as alert_name
        by dedup_key
| eval duration_mins = round((cleared - fired)/60, 1)
```

Fields are indexed as JSON, so `alert_name` and friends are available directly, while the full
original payload remains under `original.*`.

## Troubleshooting: "the script returns 200 but nothing is in Splunk"

**A `200` from the script does not mean Splunk got it.** This service acks SAO before the HEC
write completes (see *Ack-fast* below), so the HEC result only ever appears in the **app log**:

```
INFO  app.hec: Forwarded to HEC [event_id=... dedup_key=...] (attempt 1)   <- delivered
ERROR app.hec: HEC rejected the event [...], not retrying: HTTP 400: {"text":"Incorrect index"...}
ERROR app.hec: Giving up on HEC after 5 attempts [...]
```

Every accepted request is also logged with the **full payload SAO sent**, as one line, so you can
see exactly what arrived before any transformation:

```
INFO  sao_hec_bridge: Accepted alert.triggered alert='High hallucination rate' status='triggered' (event_id=... dedup_key=...)
INFO  sao_hec_bridge: SAO payload (event_id=... dedup_key=...): {"version":"1.0","event":"alert.triggered",...}
```

If the log says **Forwarded**, Splunk has the event and the problem is in your search. Work down
this list:

**1. Check the time range first.** The bridge sets `_time` from the payload's `timestamp` field,
not from ingest time, so an alert is filed at the moment it fired. The bundled samples are dated
`2024-01-15`, so replaying one verbatim files it in January 2024 and a *Last 24 hours* search
finds nothing. Search **All time** to confirm:

```spl
index=sao_alerts sourcetype=splunk:sao:alert | head 20
```

`scripts/send_sample.sh` rewrites the timestamp to now by default for exactly this reason; pass
`--as-is` to send a sample unmodified.

**2. Verify HEC independently of this service:**

```bash
source .env
curl -sS "$HEC_URL/services/collector/health"          # {"text":"HEC is healthy","code":17}
curl -sS -H "Authorization: Splunk $HEC_TOKEN" \
  -H 'Content-Type: application/json' \
  "$HEC_URL/services/collector/event" \
  -d "{\"index\":\"$HEC_INDEX\",\"event\":{\"probe\":\"direct\"}}"   # {"text":"Success","code":0}
```

A `200 Success` here with nothing searchable points at the index or your role's permissions, not
at this service. Common causes and what HEC returns:

| Symptom | Cause |
|---|---|
| `{"text":"Incorrect index","code":7}` | Index missing, or not in the HEC token's allowed-index list |
| `{"text":"Invalid token","code":4}` | Wrong `HEC_TOKEN` |
| `{"text":"Token disabled","code":1}` | Token exists but is disabled |
| Connection refused / TLS error | Wrong scheme. HEC with SSL off needs `http://`, not `https://` |
| **200 Success, still not searchable** | **The target index does not exist on the indexer.** See below — this is the most common cause and the hardest to spot. |
| 200 Success, not searchable, index does exist | Searching the wrong index or time range, or your role can't see it |

**3. Make sure the target index exists.** This is the trap: if `HEC_INDEX` names an index that
does not exist on the indexer, HEC still answers **`{"text":"Success","code":0}`** and the
indexing pipeline then discards the event silently. Nothing is logged by this service, because
from its point of view the write succeeded.

HEC only rejects an index (`{"text":"Incorrect index","code":7}`) when the token has an explicit
allowed-index list and your index is not on it. A token with no restriction accepts any index
name, real or not.

Diagnose it in two posts — one naming the index, one letting the token use its default:

```bash
source .env
curl -sS -H "Authorization: Splunk $HEC_TOKEN" "$HEC_URL/services/collector/event" \
  -d "{\"index\":\"$HEC_INDEX\",\"event\":{\"probe\":\"with-index\"}}"
curl -sS -H "Authorization: Splunk $HEC_TOKEN" "$HEC_URL/services/collector/event" \
  -d '{"event":{"probe":"default-index"}}'
```

Then search `index=* probe=*` over All time. If only `default-index` appears, your `HEC_INDEX`
does not exist. Fix it by creating the index **on the indexer** (Settings → Indexes → New Index,
or `splunk add index sao_alerts`) and adding it to the HEC token's allowed indexes — or point
`HEC_INDEX` at an index that already exists.

**4. Confirm the index actually received data**, independent of time range:

```spl
| eventcount summarize=false index=sao_alerts
| tstats count where index=sao_alerts by _time span=1d
```

The second search shows *which days* hold events — the quickest way to spot the 2024 case.

## Design notes

**Ack-fast.** The service returns `200` to SAO *before* the HEC round trip completes, then forwards
in a background task. This keeps SAO's webhook badge **Active** through Splunk restarts and
blips — SAO's own retry behaviour is undocumented, so a 5xx from us may well mean the alert is
simply lost. The trade-off: events in flight are lost if the container is killed mid-retry.
Failures are logged with `event_id` and `dedup_key` so they can be traced. If you need delivery
guarantees, add a durable queue in front of `HECClient.send`.

**Retry policy.** Connection errors, timeouts, `429` and `5xx` are retried with full-jitter
exponential backoff. Other `4xx` responses are **not** retried — a `400`/`403` from HEC means a bad
token, an index the token can't write to, or a malformed envelope, and retrying only delays the
error showing up in the log. Splunk's response body (e.g. `{"text":"Incorrect index","code":7}`)
is logged verbatim.

**Schema tolerance.** SAO documents the `alert.triggered` payload but not the clear-event shape,
and the test event may be thinner. Every model field is optional and extra keys are allowed. A
payload that doesn't match is still flattened on a best-effort basis, flagged with
`parse_ok=false`, and forwarded — never rejected back at SAO with a validation error. Only a body
that isn't a JSON object is refused.

**Severity.** Derived from `alert.status`: `triggered`/`firing`/`alerting` → `high`;
`cleared`/`resolved`/`healthy`/`ok` → `informational`; anything else → `unknown`. The map lives in
one place, `SEVERITY_BY_STATUS` in [app/transform.py](app/transform.py).

## Tests

```bash
./.venv/bin/python -m pytest
```

55 tests covering auth (valid/missing/wrong/wrong-scheme, insecure mode, startup validation),
transformation (flattening, metadata sanitising, timestamps, severity, schema tolerance), and
forwarding (envelope shape, retry on transient errors, no retry on 4xx, SAO still gets 200 when
Splunk is down). HEC is mocked throughout — no Splunk needed.

## Not included

CIM data-model mapping, a Splunk TA with `props.conf`/`transforms.conf`, ES correlation searches or
notable-event generation, a `/metrics` endpoint, durable queueing, and HTTP Basic inbound auth.
The flat field names were chosen so that adding a CIM-mapping TA later is additive configuration,
not a rewrite.
