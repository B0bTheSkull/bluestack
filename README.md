# BlueStack — SIEM-in-a-Box

A pre-wired ELK stack (Elasticsearch + Logstash + Kibana) that ingests JSON output from the rest of the [B0bTheSkull](https://github.com/B0bTheSkull) blue-team toolkit and turns it into searchable, dashboarded detections — in one `docker compose up`.

```
                  ┌─────────────┐   JSON        ┌──────────────┐
LogHound      ──→ │  Logstash   │   over TCP    │ Elasticsearch│
NetSentinel   ──→ │  pipelines  │ ────────────→ │   (single    │
HoneyNet      ──→ │  (one per   │               │    node)     │
ThreatPulse   ──→ │   source)   │               └──────┬───────┘
                  └─────────────┘                      │
                                                       ▼
                                                  ┌──────────┐
                                                  │  Kibana  │  ← you
                                                  └──────────┘
```

**What you get:**
- A single-node Elasticsearch cluster sized for a laptop (1 GB heap by default)
- Four Logstash pipelines, one per source tool, with grok/JSON parsing, severity normalization, and **MITRE ATT&CK tagging baked in**
- A shared index template so cross-source dashboards have correct field types (IPs as `ip`, timestamps as `date`, severities as `keyword`)
- Kibana data views auto-created so you can open Discover and immediately query
- Sample data files so you can verify the whole thing in <60 seconds
- Loopback-only port bindings — nothing on this stack is exposed to your LAN by default

**What it's not:**
- This is a lab/portfolio kit, not a hardened production SIEM. Authentication is disabled, TLS is off. See [`docs/HARDENING.md`](docs/HARDENING.md) before exposing it to anything you care about.

---

## Quick start

```bash
git clone https://github.com/B0bTheSkull/bluestack
cd bluestack
cp .env.example .env          # tune ports/heap if you need to
./scripts/setup.sh             # bring stack up + install templates + create data views
./scripts/send-sample-data.sh  # ship the bundled sample payloads through Logstash
open http://localhost:5601     # Kibana → Discover → bluestack-*
```

You should see ~16 events across 4 indices (`bluestack-loghound-*`, `bluestack-netsentinel-*`, `bluestack-honeynet-*`, `bluestack-threatpulse-*`).

---

## Ingestion ports

Each source tool gets its own dedicated Logstash pipeline and TCP port so a parse error in one stream doesn't block the others.

| Source tool | Port | Format | Index pattern |
|---|---|---|---|
| LogHound      | 5001 | wrapped JSON report | `bluestack-loghound-*` |
| NetSentinel   | 5002 | newline-delimited JSON | `bluestack-netsentinel-*` |
| HoneyNet      | 5003 | newline-delimited JSON | `bluestack-honeynet-*` |
| ThreatPulse   | 5004 | newline-delimited JSON | `bluestack-threatpulse-*` |

### Wiring up real tool output

```bash
# LogHound — single wrapped report
loghound auth /var/log/auth.log --output /tmp/loghound.json
nc -q1 localhost 5001 < /tmp/loghound.json

# NetSentinel — tail the live log
tail -F /var/log/netsentinel.json | nc -q1 localhost 5002

# HoneyNet — tail the live log
tail -F logs/honeynet.json | nc -q1 localhost 5003

# ThreatPulse — pipe a batch of lookups
threatpulse-bulk --iocs ioc-list.txt --json | nc -q1 localhost 5004
```

For production-ish use, drop a Filebeat sidecar in front of the JSON files instead of `tail | nc`. A Filebeat `inputs.d` example is in [`filebeat/`](filebeat/).

---

## What the pipelines do

Each pipeline does more than blind JSON forwarding — they enrich each event so dashboards can pivot across sources:

- **Severity normalization** — every source emits `severity`; pipelines uppercase it and standardize on `CRITICAL/HIGH/MEDIUM/LOW/INFO`.
- **`source_tool` tagging** — every document carries `source_tool: loghound | netsentinel | honeynet | threatpulse` so a single Kibana view can split or filter by origin.
- **MITRE ATT&CK enrichment** — known event types are mapped to technique IDs:
  - NetSentinel `port_scan` → `T1046`
  - NetSentinel `arp_spoof` → `T1557.002`
  - NetSentinel `dns_tunnel` → `T1041`
  - HoneyNet `credential_attempt` → `T1110`
  - HoneyNet `command_executed` → `T1059`
  - LogHound passes its own `mitre_technique` straight through.
- **ECS-aligned aliases** — `source.ip`, `destination.address`, `mitre.technique_id`, `mitre.tactic` so cross-source dashboards work.
- **LogHound flattening** — LogHound emits a wrapped report with a `findings[]` array; the pipeline splits it so each finding is its own document.

Full ATT&CK coverage table is in [`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md).

---

## Repo layout

```
bluestack/
├── docker-compose.yml             # ES + Kibana + Logstash, single network
├── .env.example                   # ports + heap sizing
├── elasticsearch/config/          # single-node lab config
├── kibana/config/                 # publicBaseUrl, telemetry off
├── kibana/dashboards/             # exported saved objects (your handcrafted dashboards go here)
├── logstash/
│   ├── config/                    # logstash.yml + pipelines.yml (one pipeline per source)
│   └── pipeline/                  # the four source pipelines
├── filebeat/                      # optional sidecar for tail-style ingestion
├── scripts/
│   ├── setup.sh                   # idempotent stand-up: compose up, install templates, create data views
│   ├── send-sample-data.sh        # smoke-test the pipelines
│   └── index-template.json        # field-type mappings for bluestack-*
├── examples/                      # one sample payload per source tool
└── docs/
    ├── ATTACK-COVERAGE.md
    └── HARDENING.md
```

---

## Building dashboards

The setup script creates Kibana data views (`bluestack`, `bluestack-loghound`, etc.) but does *not* ship pre-made dashboards. Build your own in Kibana, then export them:

```bash
# In Kibana: Stack Management → Saved Objects → select dashboards → Export.
# Save the resulting ndjson here:
mv ~/Downloads/export.ndjson kibana/dashboards/bluestack-saved-objects.ndjson
```

Re-running `./scripts/setup.sh` will pick the file up and re-import it on every fresh stand-up.

Suggested dashboards (what I built first):
- **Overview** — event count by `source_tool`, severity distribution, top source IPs.
- **MITRE ATT&CK heatmap** — `mitre.tactic` × `mitre.technique_id`, count per cell.
- **HoneyNet attacker timeline** — per-IP timeline with credential attempts, commands, coordinated-scan markers.
- **NetSentinel network anomalies** — split by `event_type`, with source/destination IP fields.
- **LogHound auth findings** — focused on `severity:CRITICAL OR HIGH`, sorted by `count` for brute-force escalation.

---

## Tearing down

```bash
docker compose down            # keep data
docker compose down -v         # nuke the Elasticsearch volume too
```

---

## Roadmap

- Pre-built Kibana dashboards exported as version-stable saved objects
- Filebeat sidecar with shipped `inputs.d` for the four tools
- Wazuh-flavored variant (compose profile) for users who want HIDS + agent-based collection alongside the JSON pipelines
- Detection rule pack — Elastic detection-engine rules (`siem.rules`) that cover the high-signal cases (multi-failed-SSH-then-success, DNS tunnel, ARP cache poison)
- Alert sink — Slack/email outputs from Logstash for `severity:CRITICAL`

---

## License

MIT — see [LICENSE](LICENSE).
