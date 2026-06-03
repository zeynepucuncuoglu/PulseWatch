"""
Generates realistic microservice log streams with injected failure scenarios.

Produces JSON-structured logs that mirror what you'd see in a Kubernetes
cluster running multiple services behind an API gateway.
"""

import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Generator

SERVICES = [
    "api-gateway",
    "auth-service",
    "payment-service",
    "inventory-service",
    "notification-service",
    "user-service",
]

ENDPOINTS = {
    "api-gateway":        ["/api/v1/users", "/api/v1/products", "/api/v1/orders", "/health"],
    "auth-service":       ["/auth/login", "/auth/logout", "/auth/refresh", "/auth/validate"],
    "payment-service":    ["/payments/charge", "/payments/refund", "/payments/status"],
    "inventory-service":  ["/inventory/check", "/inventory/reserve", "/inventory/release"],
    "notification-service": ["/notify/email", "/notify/sms", "/notify/push"],
    "user-service":       ["/users/profile", "/users/update", "/users/delete"],
}

ERROR_TEMPLATES = {
    "database": [
        "could not connect to server: Connection refused (host=postgres-primary port=5432)",
        "deadlock detected on table 'orders' — transaction rolled back",
        "ERROR: relation 'sessions' does not exist",
        "too many connections — max_connections=100 reached",
        "SSL connection has been closed unexpectedly by postgres-replica",
    ],
    "timeout": [
        "upstream timed out (110: Connection timed out) while reading response header from upstream",
        "context deadline exceeded after 30s waiting for downstream service",
        "ReadTimeoutError: HTTPConnectionPool host=redis-cluster port=6379 timed out",
        "request to auth-service timed out after 5000ms",
    ],
    "auth": [
        "JWT validation failed: token signature is invalid",
        "OAuth2 token expired — issued_at=2026-06-02T18:00:00Z",
        "API key revoked for client_id=svc-payment-prod",
        "rate limit exceeded for ip=203.0.113.42: 1000 req/min",
    ],
    "memory": [
        "java.lang.OutOfMemoryError: GC overhead limit exceeded",
        "OOMKilled: container exceeded memory limit of 512Mi",
        "Cannot allocate memory: fork failed",
    ],
    "disk": [
        "No space left on device — /var/log partition at 100%",
        "write /tmp/upload-buffer: no space left on device",
    ],
    "network": [
        "dial tcp 10.0.1.45:8080: connect: connection refused",
        "EOF reading from socket — peer closed connection",
        "TLS handshake error from 10.0.0.23:51234: remote error: tls: bad certificate",
    ],
}

INCIDENT_SCENARIOS = [
    # (weight, category, services affected)
    (0.30, "database",  ["payment-service", "user-service", "inventory-service"]),
    (0.20, "timeout",   ["api-gateway", "auth-service"]),
    (0.15, "auth",      ["auth-service", "api-gateway"]),
    (0.10, "memory",    ["payment-service"]),
    (0.10, "disk",      ["notification-service"]),
    (0.15, "network",   ["inventory-service", "notification-service", "api-gateway"]),
]


def _now_iso(offset_seconds: float = 0.0) -> str:
    ts = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _make_log(
    service: str,
    level: str,
    message: str,
    offset_seconds: float = 0.0,
    extra: dict | None = None,
) -> dict:
    log = {
        "timestamp": _now_iso(offset_seconds),
        "level":     level,
        "service":   service,
        "host":      f"{service}-{random.randint(1, 3):02d}",
        "trace_id":  uuid.uuid4().hex[:16],
        "message":   message,
    }
    if extra:
        log.update(extra)
    return log


def generate_normal_traffic(
    service: str,
    count: int = 5,
    base_offset: float = 0.0,
) -> list[dict]:
    """Happy-path INFO logs — simulates healthy request throughput."""
    logs = []
    endpoint = random.choice(ENDPOINTS[service])
    latency   = random.randint(5, 350)
    status    = random.choices([200, 201, 204, 400, 404], weights=[75, 5, 5, 8, 7])[0]
    level     = "INFO" if status < 400 else "WARNING"
    for i in range(count):
        logs.append(_make_log(
            service, level,
            f"{random.choice(['GET','POST','PUT','DELETE'])} {endpoint} {status} {latency}ms",
            offset_seconds=base_offset + i * 0.1,
            extra={"endpoint": endpoint, "status_code": status, "latency_ms": latency},
        ))
    return logs


def generate_incident(
    category: str,
    services: list[str],
    burst_count: int = 15,
    base_offset: float = 0.0,
) -> list[dict]:
    """Burst of ERROR logs for an active incident."""
    templates = ERROR_TEMPLATES[category]
    logs = []
    for i in range(burst_count):
        svc = random.choice(services)
        logs.append(_make_log(
            svc, "ERROR",
            random.choice(templates),
            offset_seconds=base_offset + i * 0.3,
            extra={"error_category": category, "incident": True},
        ))
    return logs


def stream_logs(
    duration_seconds: int = 120,
    incident_probability: float = 0.15,
) -> Generator[dict, None, None]:
    """
    Yields log dicts in real-time at ~10 logs/sec.
    Randomly injects incident bursts to simulate production chaos.
    """
    start = time.time()
    while time.time() - start < duration_seconds:
        elapsed = time.time() - start

        # Normal traffic from a random service
        svc = random.choice(SERVICES)
        for log in generate_normal_traffic(svc, count=random.randint(1, 3)):
            yield log

        # Randomly trigger an incident burst
        if random.random() < incident_probability:
            weights, categories, affected_services_list = zip(
                *[(w, c, s) for w, c, s in INCIDENT_SCENARIOS]
            )
            cat = random.choices(categories, weights=weights)[0]
            svcs = next(s for w, c, s in INCIDENT_SCENARIOS if c == cat)
            for log in generate_incident(cat, svcs, burst_count=random.randint(8, 20),
                                         base_offset=elapsed):
                yield log

        time.sleep(0.1)


def generate_batch(total_logs: int = 500) -> list[dict]:
    """
    Returns a static batch of logs (no real-time delay).
    Useful for unit tests and dashboard demos.
    """
    logs: list[dict] = []
    base = 0.0

    # Seed ~60% normal traffic
    for _ in range(int(total_logs * 0.6)):
        svc = random.choice(SERVICES)
        logs.extend(generate_normal_traffic(svc, count=1, base_offset=base))
        base += random.uniform(0.05, 0.5)

    # Inject 3-5 distinct incident windows
    for _ in range(random.randint(3, 5)):
        weights, categories, _ = zip(*[(w, c, s) for w, c, s in INCIDENT_SCENARIOS])
        cat = random.choices(categories, weights=weights)[0]
        svcs = next(s for w, c, s in INCIDENT_SCENARIOS if c == cat)
        burst = random.randint(10, 25)
        logs.extend(generate_incident(cat, svcs, burst_count=burst, base_offset=base))
        base += random.uniform(10, 60)

    # Sort by timestamp so timeline analysis is correct
    logs.sort(key=lambda l: l["timestamp"])
    return logs[:total_logs]
