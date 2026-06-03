"""
Alert engine.

Produces structured Alert objects and optionally fires them to:
  - Slack   (incoming webhook)
  - PagerDuty Events API v2

In production you'd add a retry/back-off wrapper and a de-duplication store
(Redis SETNX with a TTL keyed on alert fingerprint) to avoid alert storms.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from .analyzer import ErrorGroup
from .anomaly import AnomalyEvent


class Severity(IntEnum):
    INFO     = 0
    WARNING  = 1
    HIGH     = 2
    CRITICAL = 3

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


@dataclass
class Alert:
    alert_id:    str
    severity:    Severity
    title:       str
    description: str
    service:     str
    fired_at:    datetime        = field(default_factory=lambda: datetime.now(timezone.utc))
    runbook:     str             = ""
    tags:        dict            = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id":    self.alert_id,
            "severity":    self.severity.name,
            "title":       self.title,
            "description": self.description,
            "service":     self.service,
            "fired_at":    self.fired_at.isoformat(),
            "runbook":     self.runbook,
            "tags":        self.tags,
        }


# ─── Alert builder ────────────────────────────────────────────────────────────

def alert_from_error_group(group: ErrorGroup, error_rate_per_min: float) -> Alert:
    if error_rate_per_min >= 30:
        sev = Severity.CRITICAL
    elif error_rate_per_min >= 10:
        sev = Severity.HIGH
    elif group.count >= 5:
        sev = Severity.WARNING
    else:
        sev = Severity.INFO

    rc = group.root_cause
    return Alert(
        alert_id=f"err-{group.service}-{hash(group.fingerprint) & 0xFFFFFF:06x}",
        severity=sev,
        title=f"[{group.service.upper()}] Repeated error: {group.sample[:80]}",
        description=(
            f"Error occurred {group.count}× in "
            f"{group.duration_seconds:.0f}s across {len(group.hosts)} host(s).\n"
            f"Root cause hint: {rc.description if rc else 'Unknown'}"
        ),
        service=group.service,
        runbook=rc.runbook if rc else "",
        tags={"category": rc.category if rc else "UNKNOWN", "count": str(group.count)},
    )


def alert_from_anomaly(event: AnomalyEvent) -> Alert:
    sev = Severity.from_str(event.severity)
    return Alert(
        alert_id=f"anomaly-{event.window_start.strftime('%H%M')}",
        severity=sev,
        title=f"Anomalous error spike at {event.window_start.strftime('%H:%M')}",
        description=(
            f"Error count jumped to {event.error_count} "
            f"(z={event.z_score}, baseline mean={event.baseline_mean:.1f}±{event.baseline_std:.1f})."
        ),
        service="*",
        tags={"z_score": str(event.z_score)},
    )


# ─── Dispatcher ───────────────────────────────────────────────────────────────

class AlertDispatcher:
    def __init__(
        self,
        slack_webhook_url: str = "",
        pagerduty_routing_key: str = "",
        min_severity: str = "HIGH",
        dry_run: bool = False,
    ):
        self.slack_url     = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        self.pd_key        = pagerduty_routing_key or os.getenv("PAGERDUTY_ROUTING_KEY", "")
        self.min_severity  = Severity.from_str(min_severity)
        self.dry_run       = dry_run
        self.fired: list[Alert] = []

    def fire(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        self.fired.append(alert)
        if not self.dry_run:
            self._send_slack(alert)
            self._send_pagerduty(alert)

    def _send_slack(self, alert: Alert) -> None:
        if not self.slack_url or not _HAS_REQUESTS:
            return
        color = {"INFO": "#36a64f", "WARNING": "#ffa500",
                 "HIGH": "#ff0000", "CRITICAL": "#7b0000"}.get(alert.severity.name, "#888")
        payload = {
            "attachments": [{
                "color":  color,
                "title":  alert.title,
                "text":   alert.description,
                "fields": [
                    {"title": "Severity", "value": alert.severity.name, "short": True},
                    {"title": "Service",  "value": alert.service,       "short": True},
                    {"title": "Runbook",  "value": alert.runbook or "—","short": False},
                ],
                "footer": f"PulseWatch • {alert.fired_at.strftime('%H:%M:%S UTC')}",
            }]
        }
        try:
            _requests.post(self.slack_url, json=payload, timeout=5)
        except Exception:
            pass  # fire-and-forget — log to stderr in production

    def _send_pagerduty(self, alert: Alert) -> None:
        if not self.pd_key or alert.severity < Severity.HIGH or not _HAS_REQUESTS:
            return
        payload = {
            "routing_key": self.pd_key,
            "event_action": "trigger",
            "dedup_key": alert.alert_id,
            "payload": {
                "summary":   alert.title,
                "severity":  "critical" if alert.severity == Severity.CRITICAL else "error",
                "source":    alert.service,
                "component": "pulsewatch",
                "custom_details": alert.tags,
            },
        }
        try:
            _requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload, timeout=5,
            )
        except Exception:
            pass
