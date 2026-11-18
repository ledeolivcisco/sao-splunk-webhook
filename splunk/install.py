#!/usr/bin/env python3
"""Push the SAO demo content into a live instance over the web REST proxy.

This is the fast-iteration path: it edits the objects of an ALREADY INSTALLED
`sao_es_demo` app in place, so you can tweak the SPL or dashboard and re-check
in seconds. To install somewhere new, build and upload the app package instead:

    ./splunk/build_app.py        ->  splunk/dist/sao_es_demo.tar.gz

Updates (idempotently) in the `sao_es_demo` app, shared globally:
  * macro          sao_index             - the base index, override to relocate
  * macro          sao_notables          - turns raw SAO alerts into notables
  * saved search   SAO - Guardrail Breach - Rule   (the "correlation search")
  * workflow action View in SAO          - pivot from any raw event
  * dashboard      sao_incident_review   - ES-style Incident Review

Usage: COOKIES=/path/to/cj.txt ./splunk/install.py
"""
from __future__ import annotations
import os, pathlib, sys, urllib.parse, urllib.request, http.cookiejar, json, ssl

BASE = os.environ.get("SPLUNK_WEB", "https://leandrof-sh.west.buttercup.cloud")
APP, OWNER = "sao_es_demo", "nobody"
ROOT = pathlib.Path(__file__).resolve().parent
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE


def load_cookies(path):
    jar, csrf = {}, None
    for line in pathlib.Path(path).read_text().splitlines():
        # curl writes HttpOnly cookies as "#HttpOnly_<domain>" - keep those,
        # they carry the splunkd session; skip only real comments.
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#") or not line.strip():
            continue
        f = line.split("\t")
        if len(f) >= 7:
            jar[f[5]] = f[6]
            if f[5] == "splunkweb_csrf_token_8000":
                csrf = f[6]
    return "; ".join(f"{k}={v}" for k, v in jar.items()), csrf


COOKIE, CSRF = load_cookies(os.environ.get("COOKIES", "cj.txt"))


def call(path, data=None, method=None):
    url = f"{BASE}/en-US/splunkd/__raw{path}"
    body = urllib.parse.urlencode(data, doseq=True).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method or ("POST" if data else "GET"))
    req.add_header("Cookie", COOKIE)
    req.add_header("X-Splunk-Form-Key", CSRF or "")
    req.add_header("X-Requested-With", "XMLHttpRequest")
    try:
        with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def upsert(collection, name, params, label):
    """POST to create; on 409 (exists) POST to the entity to update."""
    status, body = call(collection, {"name": name, **params})
    if status in (200, 201):
        print(f"  created  {label}")
    elif status == 409:
        status, body = call(f"{collection}/{urllib.parse.quote(name, safe='')}", params)
        print(f"  updated  {label}" if status in (200, 201) else f"  FAILED   {label}: {status} {body[:300]}")
    else:
        print(f"  FAILED   {label}: {status} {body[:300]}")
        return False
    return True


def share(collection, name, label):
    path = f"{collection}/{urllib.parse.quote(name, safe='')}/acl"
    status, body = call(path, {"sharing": "global", "owner": "nobody",
                               "perms.read": "*", "perms.write": "admin"})
    if status in (200, 201):
        print(f"  shared   {label}")
    elif status == 409:
        print(f"  shared   {label} (already global)")
    else:
        print(f"  share failed {label}: {status} {body[:200]}")


ns = f"/servicesNS/{OWNER}/{APP}"
macro_body = (ROOT / "notable_macro.spl").read_text().strip()
dash_xml = (ROOT / "sao_incident_review.xml").read_text()

print("macros")
upsert(f"{ns}/configs/conf-macros", "sao_index",
       {"definition": "index=sao_alerts",
        "description": "Where the SAO webhook bridge lands alerts."},
       "`sao_index`") and share(f"{ns}/configs/conf-macros", "sao_index", "`sao_index`")
if upsert(f"{ns}/configs/conf-macros", "sao_notables",
          {"definition": macro_body,
           "description": "SAO guardrail alerts reshaped as ES-style notables (urgency, status, owner, dwell)."},
          "`sao_notables`"):
    share(f"{ns}/configs/conf-macros", "sao_notables", "`sao_notables`")

print("correlation search")
corr = {
    "search": ("`sao_notables` | search status=\"New\" urgency IN (\"critical\",\"high\") "
               "| table _time urgency title condition observed_value threshold project_name stream owner env deep_link"),
    "description": ("Correlation search: raises a notable for every high-or-critical AI guardrail "
                    "breach reported by Splunk AI Observability. Drill down via deep_link to the traces in SAO."),
    "dispatch.earliest_time": "-15m",
    "dispatch.latest_time": "now",
    "cron_schedule": "*/5 * * * *",
    "is_scheduled": "1",
    "alert_type": "number of events",
    "alert_comparator": "greater than",
    "alert_threshold": "0",
    "alert.track": "1",
    "alert.severity": "4",
    "alert.suppress": "1",
    "alert.suppress.fields": "dedup_key",
    "alert.suppress.period": "3600s",
    "disabled": "0",
}
NAME = "SAO - Guardrail Breach - Rule"
if upsert(f"{ns}/saved/searches", NAME, corr, NAME):
    share(f"{ns}/saved/searches", NAME, NAME)

print("workflow action")
wf = {
    "label": "View in SAO",
    "link.uri": "$deep_link$",
    "link.target": "blank",
    "link.method": "get",
    "type": "link",
    "fields": "deep_link",
    "display_location": "both",
}
if upsert(f"{ns}/data/ui/workflow-actions", "view_in_sao", wf, "View in SAO"):
    share(f"{ns}/data/ui/workflow-actions", "view_in_sao", "View in SAO")

print("dashboard")
if upsert(f"{ns}/data/ui/views", "sao_incident_review", {"eai:data": dash_xml},
          "Incident Review — SAO AI Guardrails"):
    share(f"{ns}/data/ui/views", "sao_incident_review", "dashboard")

print(f"\nDashboard: {BASE}/en-US/app/{APP}/sao_incident_review")
