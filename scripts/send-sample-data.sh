#!/usr/bin/env bash
# Stream the bundled example payloads into Logstash so you can verify
# the pipelines and see immediate data in Kibana.

set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${LS_HOST:-127.0.0.1}"

log() { printf '\033[36m[send]\033[0m %s\n' "$*"; }

send() {
  local file="$1" port="$2" name="$3"
  if [ ! -f "$file" ]; then
    echo "missing: $file" >&2; return 1
  fi
  log "→ $name (port $port): $file"
  # nc on most distros: -q1 lingers 1s after EOF so Logstash flushes.
  # macOS netcat doesn't have -q; use -w1 instead.
  if nc -h 2>&1 | grep -q -- '-q'; then
    nc -q1 "$HOST" "$port" < "$file"
  else
    nc -w1 "$HOST" "$port" < "$file"
  fi
}

send examples/loghound-report.json     5001 loghound
send examples/netsentinel-events.jsonl 5002 netsentinel
send examples/honeynet-events.jsonl    5003 honeynet
send examples/threatpulse-lookups.jsonl 5004 threatpulse

log "done. Give Logstash a few seconds, then check Kibana → Discover."
