#!/usr/bin/env bash
# BlueStack first-time setup
#   1. Brings up the docker-compose stack
#   2. Waits for Elasticsearch + Kibana to become available
#   3. Installs index templates so dashboards have correct field types
#   4. Imports Kibana data views and saved objects
#
# Idempotent — safe to re-run.

set -euo pipefail

cd "$(dirname "$0")/.."

ES_URL="${ES_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

log() { printf '\033[36m[setup]\033[0m %s\n' "$*"; }
err() { printf '\033[31m[setup]\033[0m %s\n' "$*" >&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { err "required command not found: $1"; exit 1; }
}

require docker
require curl

# --- 1. compose up ---
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  err "docker compose not available"; exit 1
fi

log "starting stack via: $COMPOSE up -d"
$COMPOSE up -d

# --- 2. wait for elasticsearch ---
log "waiting for Elasticsearch at $ES_URL ..."
for i in $(seq 1 60); do
  if curl -fsS "$ES_URL/_cluster/health" 2>/dev/null \
       | grep -qE '"status":"(green|yellow)"'; then
    log "Elasticsearch is ready"
    break
  fi
  sleep 2
  if [ "$i" = "60" ]; then err "Elasticsearch did not become ready in time"; exit 1; fi
done

# --- 3. install index templates ---
log "installing index template: bluestack-events"
curl -fsS -X PUT "$ES_URL/_index_template/bluestack-events" \
  -H 'Content-Type: application/json' \
  --data-binary @scripts/index-template.json >/dev/null
log "index template installed"

# --- 4. wait for kibana ---
log "waiting for Kibana at $KIBANA_URL ..."
for i in $(seq 1 60); do
  if curl -fsS "$KIBANA_URL/api/status" 2>/dev/null \
       | grep -q '"level":"available"'; then
    log "Kibana is ready"
    break
  fi
  sleep 2
  if [ "$i" = "60" ]; then err "Kibana did not become ready in time"; exit 1; fi
done

# --- 5. create Kibana data views (one per source tool, plus a unified one) ---
create_data_view() {
  local id="$1" title="$2"
  local payload
  payload=$(cat <<JSON
{
  "data_view": {
    "id": "$id",
    "title": "$title",
    "name": "$id",
    "timeFieldName": "@timestamp"
  },
  "override": true
}
JSON
)
  curl -fsS -X POST "$KIBANA_URL/api/data_views/data_view" \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    --data "$payload" >/dev/null
  log "data view: $id  →  $title"
}

log "creating Kibana data views"
create_data_view "bluestack"             "bluestack-*"
create_data_view "bluestack-loghound"    "bluestack-loghound-*"
create_data_view "bluestack-netsentinel" "bluestack-netsentinel-*"
create_data_view "bluestack-honeynet"    "bluestack-honeynet-*"
create_data_view "bluestack-threatpulse" "bluestack-threatpulse-*"

# --- 6. import any user-exported dashboards/saved-searches ---
SAVED_OBJECTS="kibana/dashboards/bluestack-saved-objects.ndjson"
if [ -f "$SAVED_OBJECTS" ]; then
  log "importing Kibana saved objects from $SAVED_OBJECTS"
  curl -fsS -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
    -H 'kbn-xsrf: true' \
    --form file=@"$SAVED_OBJECTS" >/dev/null
  log "saved objects imported"
fi

cat <<EOF

------------------------------------------------------------
BlueStack is up.
  Kibana:        $KIBANA_URL
  Elasticsearch: $ES_URL

Send sample data with:
  ./scripts/send-sample-data.sh

Tail Logstash for parse errors:
  docker logs -f bluestack-logstash
------------------------------------------------------------
EOF
