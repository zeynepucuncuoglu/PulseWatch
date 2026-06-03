"""
Core analysis engine.

  1. Error fingerprinting  — normalise dynamic tokens out of messages so
     "user 42 not found" and "user 99 not found" collapse to one group.
  2. Error grouping        — cluster entries by fingerprint + service.
  3. Root cause hints      — heuristic rules that map error patterns to
     probable causes and suggested runbooks.
  4. Incident timeline     — bucket events into 1-minute windows.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .parser import LogEntry

# ─── Fingerprinting ───────────────────────────────────────────────────────────

# Tokens that vary per-request but carry no grouping signal
_DYNAMIC_PATTERNS = [
    (re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I), '<uuid>'),
    (re.compile(r'\b[0-9a-f]{12,}\b', re.I),  '<hex>'),
    (re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b'),                             '<ip>'),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*'), '<timestamp>'),
    (re.compile(r'\b\d+ms\b'),                                          '<Nms>'),
    (re.compile(r'\b\d+\b'),                                            '<N>'),
    (re.compile(r"client_id=\S+"),                                      'client_id=<id>'),
    (re.compile(r"ip=\S+"),                                             'ip=<ip>'),
    (re.compile(r"host=\S+"),                                           'host=<host>'),
]

def fingerprint(message: str) -> str:
    """Return a normalised message suitable for grouping similar errors."""
    s = message
    for pattern, replacement in _DYNAMIC_PATTERNS:
        s = pattern.sub(replacement, s)
    # collapse repeated whitespace
    return re.sub(r'\s+', ' ', s).strip().lower()


# ─── Root-cause heuristics ────────────────────────────────────────────────────

@dataclass
class RootCauseHint:
    category:    str
    description: str
    runbook:     str
    confidence:  str   # HIGH | MEDIUM | LOW

_HEURISTICS: list[tuple[re.Pattern, RootCauseHint]] = [
    (re.compile(r'connection refused.*postgres|postgres.*connection refused', re.I),
     RootCauseHint("DATABASE", "PostgreSQL primary is unreachable — pod or TCP listener is down.",
                   "runbook/db-connection-refused.md", "HIGH")),

    (re.compile(r'max_connections|too many connections', re.I),
     RootCauseHint("DATABASE", "Connection pool exhausted — services are leaking connections or pool is undersized.",
                   "runbook/db-connection-pool.md", "HIGH")),

    (re.compile(r'deadlock', re.I),
     RootCauseHint("DATABASE", "Transaction deadlock — review query order and add retry logic.",
                   "runbook/db-deadlock.md", "MEDIUM")),

    (re.compile(r'context deadline exceeded|timed out after \d+', re.I),
     RootCauseHint("LATENCY", "Downstream service is responding too slowly — check CPU/memory, or circuit-break.",
                   "runbook/latency-spike.md", "HIGH")),

    (re.compile(r'upstream timed out', re.I),
     RootCauseHint("LATENCY", "Nginx upstream timeout — upstream pod may be overloaded or crashing.",
                   "runbook/nginx-upstream-timeout.md", "HIGH")),

    (re.compile(r'ReadTimeoutError.*redis|redis.*timeout', re.I),
     RootCauseHint("CACHE", "Redis cluster is slow or unreachable — check cluster health and eviction policy.",
                   "runbook/redis-timeout.md", "MEDIUM")),

    (re.compile(r'jwt.*invalid|token.*expired|signature.*invalid', re.I),
     RootCauseHint("AUTH", "JWT tokens are invalid/expired — possible clock skew, key rotation, or replay attack.",
                   "runbook/jwt-invalid.md", "HIGH")),

    (re.compile(r'rate limit exceeded', re.I),
     RootCauseHint("THROTTLE", "Client is being throttled — check for traffic spike or misconfigured retry loop.",
                   "runbook/rate-limiting.md", "MEDIUM")),

    (re.compile(r'OutOfMemoryError|OOMKilled|cannot allocate memory', re.I),
     RootCauseHint("MEMORY", "Container OOM — increase memory limits or investigate heap leak.",
                   "runbook/oom.md", "HIGH")),

    (re.compile(r'no space left|disk.*(full|100%)|partition at 100%', re.I),
     RootCauseHint("DISK", "Disk full — rotate/archive logs or expand volume immediately.",
                   "runbook/disk-full.md", "CRITICAL")),

    (re.compile(r'connection refused|EOF reading|tls.*bad certificate', re.I),
     RootCauseHint("NETWORK", "Network connectivity issue — check service mesh, DNS, and TLS certificates.",
                   "runbook/network-connectivity.md", "MEDIUM")),
]

def get_root_cause_hint(message: str) -> Optional[RootCauseHint]:
    for pattern, hint in _HEURISTICS:
        if pattern.search(message):
            return hint
    return None


# ─── Error group ──────────────────────────────────────────────────────────────

@dataclass
class ErrorGroup:
    fingerprint:  str
    service:      str
    sample:       str           # representative raw message
    count:        int           = 0
    first_seen:   Optional[datetime] = None
    last_seen:    Optional[datetime] = None
    hosts:        set           = field(default_factory=set)
    trace_ids:    list          = field(default_factory=list)
    root_cause:   Optional[RootCauseHint] = None

    def add(self, entry: LogEntry) -> None:
        self.count += 1
        if self.first_seen is None or entry.timestamp < self.first_seen:
            self.first_seen = entry.timestamp
        if self.last_seen is None or entry.timestamp > self.last_seen:
            self.last_seen = entry.timestamp
        self.hosts.add(entry.host)
        if entry.trace_id:
            self.trace_ids.append(entry.trace_id)
        if self.root_cause is None:
            self.root_cause = get_root_cause_hint(entry.message)

    @property
    def duration_seconds(self) -> float:
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds()
        return 0.0


# ─── Incident timeline ────────────────────────────────────────────────────────

@dataclass
class TimelineWindow:
    window_start: datetime
    total_logs:   int = 0
    error_count:  int = 0
    services:     dict = field(default_factory=lambda: defaultdict(int))

    @property
    def error_rate(self) -> float:
        return self.error_count / max(self.total_logs, 1)


# ─── Analyser ─────────────────────────────────────────────────────────────────

class LogAnalyzer:
    def __init__(self, min_group_size: int = 2):
        self.min_group_size = min_group_size
        self._groups: dict[tuple[str, str], ErrorGroup] = {}   # (fp, service) → group
        self._timeline: dict[str, TimelineWindow] = {}          # "YYYY-MM-DDTHH:MM" → window

    # ── ingest ────────────────────────────────────────────────────────────────

    def ingest(self, entries: list[LogEntry]) -> None:
        for entry in entries:
            self._update_timeline(entry)
            if entry.is_error:
                self._update_group(entry)

    def _update_timeline(self, entry: LogEntry) -> None:
        bucket = entry.timestamp.strftime("%Y-%m-%dT%H:%M")
        if bucket not in self._timeline:
            self._timeline[bucket] = TimelineWindow(
                window_start=entry.timestamp.replace(second=0, microsecond=0)
            )
        w = self._timeline[bucket]
        w.total_logs += 1
        w.services[entry.service] += 1
        if entry.is_error:
            w.error_count += 1

    def _update_group(self, entry: LogEntry) -> None:
        fp  = fingerprint(entry.message)
        key = (fp, entry.service)
        if key not in self._groups:
            self._groups[key] = ErrorGroup(
                fingerprint=fp, service=entry.service, sample=entry.message
            )
        self._groups[key].add(entry)

    # ── results ───────────────────────────────────────────────────────────────

    def error_groups(self, min_count: Optional[int] = None) -> list[ErrorGroup]:
        """Return error groups sorted by count descending."""
        threshold = min_count if min_count is not None else self.min_group_size
        groups = [g for g in self._groups.values() if g.count >= threshold]
        return sorted(groups, key=lambda g: g.count, reverse=True)

    def top_failing_services(self, top_n: int = 5) -> list[tuple[str, int]]:
        """Return (service, error_count) pairs, highest first."""
        service_counts: dict[str, int] = defaultdict(int)
        for g in self._groups.values():
            service_counts[g.service] += g.count
        return sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def timeline(self) -> list[TimelineWindow]:
        """Return timeline windows sorted chronologically."""
        return sorted(self._timeline.values(), key=lambda w: w.window_start)

    def summary(self) -> dict:
        groups = self.error_groups()
        return {
            "total_error_groups":    len(groups),
            "total_error_events":    sum(g.count for g in groups),
            "top_failing_services":  self.top_failing_services(),
            "top_error_groups":      groups[:10],
            "timeline_windows":      len(self._timeline),
        }
