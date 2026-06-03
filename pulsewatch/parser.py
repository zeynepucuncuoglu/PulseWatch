"""
Log parser — handles JSON structured logs and Nginx/Apache combined-log format.

In production you'd add more format handlers here (syslog, logfmt, etc.) and
wire them up via the config.yaml format list.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ─── Data model ───────────────────────────────────────────────────────────────

LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL", "FATAL"}
LEVEL_SEVERITY = {
    "DEBUG": 0, "INFO": 1, "WARNING": 2, "WARN": 2,
    "ERROR": 3, "CRITICAL": 4, "FATAL": 4,
}

@dataclass
class LogEntry:
    raw:        str
    timestamp:  datetime
    level:      str
    service:    str
    message:    str
    host:       str          = ""
    trace_id:   str          = ""
    status_code: Optional[int] = None
    latency_ms:  Optional[int] = None
    endpoint:   str          = ""
    error_category: str      = ""
    extra:      dict         = field(default_factory=dict)

    @property
    def severity(self) -> int:
        return LEVEL_SEVERITY.get(self.level.upper(), 0)

    @property
    def is_error(self) -> bool:
        return self.severity >= LEVEL_SEVERITY["ERROR"]


# ─── Nginx combined-log pattern ───────────────────────────────────────────────
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
_NGINX_RE = re.compile(
    r'(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
_NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx(line: str) -> Optional[LogEntry]:
    m = _NGINX_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    level  = "ERROR" if status >= 500 else ("WARNING" if status >= 400 else "INFO")
    try:
        ts = datetime.strptime(m.group("time"), _NGINX_TIME_FMT)
    except ValueError:
        ts = datetime.now(timezone.utc)
    return LogEntry(
        raw=line, timestamp=ts, level=level, service="nginx",
        message=f'{m.group("method")} {m.group("path")} {status}',
        status_code=status, endpoint=m.group("path"),
    )


# ─── JSON parser ──────────────────────────────────────────────────────────────

_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
]

def _parse_timestamp(raw: str) -> datetime:
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _parse_json(line: str) -> Optional[LogEntry]:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None

    level = str(d.get("level", d.get("severity", "INFO"))).upper()
    if level not in LOG_LEVELS:
        level = "INFO"

    raw_ts = d.get("timestamp", d.get("time", d.get("@timestamp", "")))
    ts     = _parse_timestamp(raw_ts) if raw_ts else datetime.now(timezone.utc)

    known = {"timestamp", "time", "@timestamp", "level", "severity",
             "service", "message", "msg", "host", "trace_id",
             "status_code", "latency_ms", "endpoint", "error_category"}
    extra = {k: v for k, v in d.items() if k not in known}

    return LogEntry(
        raw=line,
        timestamp=ts,
        level=level,
        service=str(d.get("service", d.get("logger", "unknown"))),
        message=str(d.get("message", d.get("msg", ""))),
        host=str(d.get("host", "")),
        trace_id=str(d.get("trace_id", "")),
        status_code=d.get("status_code"),
        latency_ms=d.get("latency_ms"),
        endpoint=str(d.get("endpoint", "")),
        error_category=str(d.get("error_category", "")),
        extra=extra,
    )


# ─── Dispatcher ───────────────────────────────────────────────────────────────

def parse_line(line: str) -> Optional[LogEntry]:
    """Try JSON first, fall back to Nginx combined format."""
    line = line.strip()
    if not line:
        return None
    entry = _parse_json(line)
    if entry is None:
        entry = _parse_nginx(line)
    return entry


def parse_lines(lines: list[str]) -> list[LogEntry]:
    """Parse a list of raw log lines, silently dropping unparseable ones."""
    entries = []
    for line in lines:
        e = parse_line(line)
        if e:
            entries.append(e)
    return entries


def parse_log_dicts(log_dicts: list[dict]) -> list[LogEntry]:
    """Accept pre-parsed dicts (e.g. from the simulator) directly."""
    return parse_lines([json.dumps(d) for d in log_dicts])
