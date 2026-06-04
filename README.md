# PulseWatch

A production-grade log analysis and incident detection tool built in Python. Parses microservice logs, fingerprints error patterns, detects anomalies, and dispatches alerts to Slack and PagerDuty.

---

## Features

- **Log parsing** — JSON structured logs and Nginx combined-log format
- **Error fingerprinting** — normalises dynamic tokens (UUIDs, IPs, numbers) so similar errors collapse into one group
- **Root cause hints** — heuristic rules map error patterns to probable causes and runbook links
- **Anomaly detection** — Z-score on rolling per-minute error counts, no ML dependencies
- **Alert dispatch** — severity-based alerts to Slack webhook and PagerDuty Events API v2
- **Terminal dashboard** — rich UI with error timeline, service bar charts, and alert panels
- **JSON report export** — machine-readable output for ELK / Grafana integration

---

## Architecture

```
Log Sources (microservices)
        │
        ▼
  Ingestion Layer
  (file / stdin / stream)
        │
        ▼
    parser.py
  JSON + Nginx → LogEntry
        │
        ├──────────────────────┐
        ▼                      ▼
  analyzer.py            anomaly.py
  • Fingerprinting       • Z-score rolling
  • Error grouping         window detection
  • Root cause hints
  • Timeline buckets
        │                      │
        └──────────┬───────────┘
                   ▼
              alerts.py
         Slack + PagerDuty
                   │
                   ▼
             reporter.py
        Terminal dashboard
          + JSON export
```

---

## Project Structure

```
PulseWatch/
├── main.py                  # CLI entry point (analyse | stream)
├── config.yaml              # Thresholds, webhook URLs, service list
├── requirements.txt
├── logs/                    # Drop real log files here (git-ignored)
└── pulsewatch/
    ├── simulator.py         # Microservice log generator
    ├── parser.py            # JSON + Nginx parsers → LogEntry dataclass
    ├── analyzer.py          # Fingerprinting, error grouping, root cause hints
    ├── anomaly.py           # Z-score anomaly detector
    ├── alerts.py            # Alert objects + Slack/PagerDuty dispatch
    └── reporter.py          # Rich terminal dashboard + JSON export
```

---

## Setup

```bash
# Clone and enter the project
git clone <repo-url>
cd PulseWatch

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Analyse simulated microservice logs
python main.py analyse --lines 1000

# Export a JSON report
python main.py analyse --lines 1000 --export report.json

# Analyse a real log file (JSON or Nginx format)
python main.py analyse --file logs/service.log

# Pipe logs from stdin
cat logs/service.log | python main.py analyse --stdin

# Pipe from kubectl
kubectl logs -l app=payment-service --since=1h | python main.py analyse --stdin

# Live stream mode (real-time, 120 seconds)
python main.py stream --duration 120 --export incident.json
```

---

## Sample Output

```
──────── PulseWatch — Log Analysis & Incident Detection ────────

Error Groups Detected:  19       Top Failing Services
Total Error Events:     56       user-service       16  ████████████████████
Timeline Windows:        5       api-gateway        14  █████████████████░░░
                                 inventory-service  12  ███████████████░░░░░

Incident Timeline
17:40   167 logs    0 errors    0%   ▓░░░░░░░░░░░░░░░░░░░
17:42   220 logs   12 errors    5%   ▓▓▓▓▓▓▓▓▓░░░░░░░░░░░
17:43    26 logs   26 errors  100%   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  🔥

Anomaly Detection
HIGH  17:43 — 26 errors (z=3.89, baseline 4.0±5.7)
```

---

## Configuration

Edit `config.yaml` to adjust thresholds and alert destinations:

```yaml
analysis:
  min_group_size: 2          # minimum occurrences to report a group
  anomaly_z_threshold: 2.5   # z-score threshold for anomaly alerts
  error_rate_critical: 30    # errors/min to trigger CRITICAL alert

alerts:
  slack_webhook_url: ""      # or set SLACK_WEBHOOK_URL env var
  pagerduty_routing_key: ""  # or set PAGERDUTY_ROUTING_KEY env var
  min_severity: "HIGH"       # INFO | WARNING | HIGH | CRITICAL
```

---

## ELK Stack Integration

PulseWatch can consume logs from Elasticsearch and write processed results back as a separate index for Kibana visualisation.

```
Fluentd / Filebeat  →  Logstash  →  Elasticsearch
                                          │
                              PulseWatch reads via scroll API
                                          │
                              Writes to pulsewatch-{date} index
                                          │
                                       Kibana
                              (alerts + anomaly dashboards)
```

To connect, replace `generate_batch()` in `main.py` with an Elasticsearch scroll query and set your `ELASTIC_API_KEY` environment variable.

---

## How Anomaly Detection Works

Uses a rolling Z-score on per-minute error counts:

```
z = (current_error_count - rolling_mean) / rolling_std
```

If `z >= 2.5` (configurable), the window is flagged as anomalous and an alert is fired. No external ML dependencies — pure Python math.

---

## Supported Log Formats

| Format | Example |
|---|---|
| JSON structured | `{"level": "ERROR", "service": "auth", "message": "..."}` |
| Nginx combined | `203.0.113.1 - - [04/Jun/2026] "GET /api 500 2326"` |

More formats (syslog, logfmt) can be added in `parser.py`.

---

## Root Cause Categories

| Category | Triggered by |
|---|---|
| DATABASE | Connection refused, deadlock, max_connections |
| LATENCY | Context deadline exceeded, upstream timeout |
| AUTH | JWT invalid, token expired, rate limit |
| MEMORY | OOMKilled, OutOfMemoryError |
| DISK | No space left on device |
| NETWORK | Connection refused, TLS errors, EOF |
