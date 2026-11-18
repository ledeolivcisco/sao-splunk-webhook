#!/usr/bin/env bash
# Replay a sample SAO payload against the local receiver.
#
#   ./scripts/send_sample.sh                             # alert_triggered.json, stamped "now"
#   ./scripts/send_sample.sh samples/alert_cleared.json
#   ./scripts/send_sample.sh --as-is samples/alert_triggered.json
#   TARGET=https://my-host/webhook/sao ./scripts/send_sample.sh
#
# By default the payload's `timestamp` is rewritten to the current time. The
# bridge uses that field as the Splunk `_time`, so replaying a sample verbatim
# would file it under the sample's own date (2024-01-15) where a recent-time
# search will never find it. Pass --as-is to send the file untouched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${TARGET:-http://localhost:8088/webhook/sao}"
STAMP_NOW=1

ARGS=()
for arg in "$@"; do
  case "$arg" in
    --as-is)  STAMP_NOW=0 ;;
    --now)    STAMP_NOW=1 ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)        ARGS+=("$arg") ;;
  esac
done

PAYLOAD="${ARGS[0]:-$ROOT/samples/alert_triggered.json}"

if [[ ! -f "$PAYLOAD" ]]; then
  echo "No such payload file: $PAYLOAD" >&2
  exit 1
fi

# Pull WEBHOOK_TOKEN from .env unless it is already exported.
if [[ -z "${WEBHOOK_TOKEN:-}" && -f "$ROOT/.env" ]]; then
  WEBHOOK_TOKEN="$(grep -E '^WEBHOOK_TOKEN=' "$ROOT/.env" | tail -n1 | cut -d= -f2- || true)"
fi

BODY="$(cat "$PAYLOAD")"
if [[ "$STAMP_NOW" == "1" ]]; then
  BODY="$(
    STAMP_NOW=1 python3 - "$PAYLOAD" <<'PY'
import json, sys, datetime
payload = json.load(open(sys.argv[1]))
payload["timestamp"] = (
    datetime.datetime.now(datetime.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z")
)
print(json.dumps(payload))
PY
  )"
  EVENT_TIME="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["timestamp"])')"
  echo "timestamp rewritten to now: $EVENT_TIME   (use --as-is to keep the file's own)"
else
  EVENT_TIME="$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("timestamp","<none>"))')"
  echo "sending as-is, payload timestamp: $EVENT_TIME"
  echo "  -> this becomes _time in Splunk; search that period, not 'Last 24 hours'"
fi

echo "POST $TARGET  <-  $(basename "$PAYLOAD")"
curl -sS -w '\nHTTP %{http_code}\n' \
  -X POST "$TARGET" \
  -H 'Content-Type: application/json' \
  ${WEBHOOK_TOKEN:+-H "Authorization: Bearer ${WEBHOOK_TOKEN}"} \
  --data-binary "$BODY"
