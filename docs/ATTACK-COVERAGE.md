# MITRE ATT&CK Coverage

BlueStack's pipelines tag every parseable event with `mitre.technique_id` and `mitre.tactic` where the source tool's event type maps cleanly to a known technique. Source tools that already emit ATT&CK fields (LogHound) have those fields passed through verbatim.

Use this table to build the ATT&CK heatmap dashboard, or to cross-reference what a given detection in your SOC actually corresponds to.

## NetSentinel pipeline tagging

| Event type     | Technique  | Tactic              | Notes |
|----------------|------------|---------------------|-------|
| `arp_spoof`    | T1557.002  | credential-access   | ARP cache poisoning — adversary-in-the-middle |
| `port_scan`    | T1046      | discovery           | TCP/UDP port enumeration |
| `icmp_flood`   | T1499.003  | impact              | Network DoS via ICMP |
| `dns_hijack`   | T1071.004  | command-and-control | DNS response tampering |
| `dns_tunnel`   | T1041      | exfiltration        | Data over DNS query labels |

## HoneyNet pipeline tagging

| Event type           | Technique | Tactic             | Notes |
|----------------------|-----------|--------------------|-------|
| `credential_attempt` | T1110     | credential-access  | Brute force — sub-techniques inferable from cadence |
| `command_executed`   | T1059     | execution          | Command and scripting interpreter |
| `file_upload_attempt`| T1105     | command-and-control| Ingress tool transfer |
| `coordinated_scan`   | T1595.001 | reconnaissance     | Active scanning — IP block |

## LogHound

LogHound's detectors emit `mitre_technique` and `mitre_tactic` directly on each finding, so the BlueStack pipeline preserves them as-is. Expected values:

| Detector finding                       | Technique  | Tactic               |
|----------------------------------------|------------|----------------------|
| `ssh_brute_force`                      | T1110.001  | credential-access    |
| `credential_stuffing`                  | T1110.004  | credential-access    |
| `successful_login_after_brute_force`   | T1110.001  | credential-access    |
| `sudo_privilege_escalation`            | T1548.003  | privilege-escalation |
| `scanner_user_agent`                   | T1595.002  | reconnaissance       |
| `sensitive_path_probe`                 | T1083      | discovery            |

## ThreatPulse

ThreatPulse documents are intel/enrichment, not detections — they don't carry technique IDs. Use them as a join target when an alert from one of the other pipelines mentions an IOC.

## Building the ATT&CK heatmap

In Kibana:
1. Open Lens against the `bluestack` data view.
2. Set X-axis = `mitre.technique_id`, breakdown = `mitre.tactic`.
3. Metric = `count of records`.
4. Save as **MITRE ATT&CK Heatmap**.

Extending coverage: when a source tool gains new event types, add a corresponding `if [event_type] == "..."` branch to that tool's pipeline (`logstash/pipeline/<tool>.conf`) and update this table.
