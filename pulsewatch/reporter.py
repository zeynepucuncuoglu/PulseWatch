"""
Terminal dashboard renderer using the `rich` library.

Produces four panels:
  1. Error Summary      — top-level numbers
  2. Top Failing Svcs   — bar-chart style table
  3. Incident Timeline  — sparkline of error rate per minute
  4. Error Groups       — fingerprinted clusters with root-cause hints
  5. Active Alerts      — severity-coloured alert list
"""

import json
from datetime import datetime

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import LogAnalyzer, ErrorGroup
from .anomaly import AnomalyDetector, AnomalyEvent
from .alerts import AlertDispatcher, Alert, Severity

_SEVERITY_COLOR = {
    "INFO":     "green",
    "WARNING":  "yellow",
    "HIGH":     "bold red",
    "CRITICAL": "bold white on red",
}

_CONFIDENCE_COLOR = {
    "HIGH":     "bright_red",
    "MEDIUM":   "yellow",
    "LOW":      "dim",
    "CRITICAL": "bold white on red",
}

console = Console()


# ─── Individual panels ────────────────────────────────────────────────────────

def _summary_panel(analyzer: LogAnalyzer) -> Panel:
    s = analyzer.summary()
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(style="bold white")
    t.add_row("Error Groups Detected:", str(s["total_error_groups"]))
    t.add_row("Total Error Events:",    str(s["total_error_events"]))
    t.add_row("Timeline Windows:",      str(s["timeline_windows"]))
    return Panel(t, title="[bold]Error Summary[/bold]", border_style="cyan", padding=(1, 2))


def _services_panel(analyzer: LogAnalyzer) -> Panel:
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
    t.add_column("Service",      style="cyan",  no_wrap=True)
    t.add_column("Errors",       justify="right")
    t.add_column("Rate Bar",     no_wrap=True)

    rows = analyzer.top_failing_services(top_n=8)
    if not rows:
        return Panel("[dim]No errors detected.[/dim]", title="[bold]Top Failing Services[/bold]",
                     border_style="magenta")
    max_count = rows[0][1] if rows else 1
    for svc, count in rows:
        bar_len = int((count / max_count) * 20)
        bar = Text("█" * bar_len + "░" * (20 - bar_len))
        bar.stylize("bright_red", 0, bar_len)
        bar.stylize("dim", bar_len)
        t.add_row(svc, str(count), bar)
    return Panel(t, title="[bold]Top Failing Services[/bold]", border_style="magenta")


def _timeline_panel(analyzer: LogAnalyzer, anomalies: list[AnomalyEvent]) -> Panel:
    windows  = analyzer.timeline()
    anomaly_times = {a.window_start.strftime("%H:%M") for a in anomalies}

    t = Table(box=box.MINIMAL, show_header=True, header_style="bold blue")
    t.add_column("Time",    style="dim",   no_wrap=True, width=6)
    t.add_column("Total",   justify="right", width=6)
    t.add_column("Errors",  justify="right", width=6)
    t.add_column("Rate",    justify="right", width=6)
    t.add_column("Trend",   no_wrap=True, width=24)
    t.add_column("",        width=3)

    max_err = max((w.error_count for w in windows), default=1) or 1
    for w in windows[-20:]:   # last 20 minutes
        label    = w.window_start.strftime("%H:%M")
        bar_len  = max(1, int((w.error_count / max_err) * 20))
        bar_txt  = Text("▓" * bar_len + "░" * (20 - bar_len))
        rate_pct = f"{w.error_rate * 100:.0f}%"
        flag     = "🔥" if label in anomaly_times else ""

        if w.error_count == 0:
            bar_txt.stylize("green")
        elif label in anomaly_times:
            bar_txt.stylize("bold red", 0, bar_len)
        else:
            bar_txt.stylize("yellow", 0, bar_len)
        bar_txt.stylize("dim", bar_len)

        t.add_row(label, str(w.total_logs), str(w.error_count), rate_pct, bar_txt, flag)

    return Panel(t, title="[bold]Incident Timeline (last 20 min)[/bold]", border_style="blue")


def _groups_panel(groups: list[ErrorGroup]) -> Panel:
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow", expand=True)
    t.add_column("#",         width=4,  justify="right")
    t.add_column("Service",   width=18, no_wrap=True)
    t.add_column("Count",     width=6,  justify="right")
    t.add_column("Duration",  width=9)
    t.add_column("Hosts",     width=6,  justify="right")
    t.add_column("Root Cause",width=12)
    t.add_column("Sample Message", ratio=1)

    for i, g in enumerate(groups[:15], 1):
        rc    = g.root_cause
        cat   = rc.category   if rc else "—"
        conf  = rc.confidence if rc else "LOW"
        color = _CONFIDENCE_COLOR.get(conf, "dim")
        dur   = f"{g.duration_seconds:.0f}s" if g.duration_seconds else "—"
        t.add_row(
            str(i),
            g.service,
            str(g.count),
            dur,
            str(len(g.hosts)),
            Text(cat, style=color),
            Text(g.sample[:80], style="dim"),
        )
    return Panel(t, title="[bold]Error Groups (by fingerprint)[/bold]", border_style="yellow")


def _alerts_panel(alerts: list[Alert]) -> Panel:
    if not alerts:
        return Panel("[dim green]No alerts fired.[/dim green]",
                     title="[bold]Active Alerts[/bold]", border_style="green")

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
    t.add_column("ID",        width=28, no_wrap=True)
    t.add_column("Severity",  width=10)
    t.add_column("Service",   width=22)
    t.add_column("Title",     ratio=1)
    t.add_column("Runbook",   width=30)

    for a in sorted(alerts, key=lambda x: x.severity, reverse=True):
        color = _SEVERITY_COLOR.get(a.severity.name, "white")
        t.add_row(
            a.alert_id,
            Text(a.severity.name, style=color),
            a.service,
            a.title[:80],
            a.runbook or "—",
        )
    return Panel(t, title="[bold]Active Alerts[/bold]", border_style="red")


# ─── Full dashboard ───────────────────────────────────────────────────────────

def render_dashboard(
    analyzer:   LogAnalyzer,
    detector:   AnomalyDetector,
    dispatcher: AlertDispatcher,
) -> None:
    anomalies = detector.detect(analyzer.timeline())
    groups    = analyzer.error_groups()

    console.rule("[bold cyan]PulseWatch — Log Analysis & Incident Detection[/bold cyan]")
    console.print()

    # Row 1: summary + services side by side
    console.print(Columns([
        _summary_panel(analyzer),
        _services_panel(analyzer),
    ]))

    # Row 2: timeline (full width)
    console.print(_timeline_panel(analyzer, anomalies))

    # Row 3: error groups (full width)
    console.print(_groups_panel(groups))

    # Row 4: alerts
    console.print(_alerts_panel(dispatcher.fired))

    # Anomaly callouts
    if anomalies:
        console.print()
        console.rule("[bold red]Anomaly Detection Findings[/bold red]")
        for a in anomalies:
            color = _SEVERITY_COLOR.get(a.severity, "red")
            console.print(
                f"  [{color}]{a.severity}[/{color}] "
                f"{a.window_start.strftime('%H:%M')} — "
                f"{a.error_count} errors (z={a.z_score}, "
                f"baseline {a.baseline_mean:.1f}±{a.baseline_std:.1f})"
            )


def export_json_report(
    analyzer:   LogAnalyzer,
    detector:   AnomalyDetector,
    dispatcher: AlertDispatcher,
    path: str,
) -> None:
    anomalies = detector.detect(analyzer.timeline())
    groups    = analyzer.error_groups()

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_error_groups": len(groups),
            "total_error_events": sum(g.count for g in groups),
            "top_failing_services": [
                {"service": s, "error_count": c}
                for s, c in analyzer.top_failing_services()
            ],
        },
        "error_groups": [
            {
                "fingerprint":      g.fingerprint,
                "service":          g.service,
                "count":            g.count,
                "first_seen":       g.first_seen.isoformat() if g.first_seen else None,
                "last_seen":        g.last_seen.isoformat()  if g.last_seen  else None,
                "duration_seconds": g.duration_seconds,
                "affected_hosts":   list(g.hosts),
                "sample_message":   g.sample,
                "root_cause": {
                    "category":    g.root_cause.category,
                    "description": g.root_cause.description,
                    "runbook":     g.root_cause.runbook,
                    "confidence":  g.root_cause.confidence,
                } if g.root_cause else None,
            }
            for g in groups
        ],
        "anomalies": [
            {
                "window_start":   a.window_start.isoformat(),
                "error_count":    a.error_count,
                "z_score":        a.z_score,
                "baseline_mean":  a.baseline_mean,
                "baseline_std":   a.baseline_std,
                "severity":       a.severity,
            }
            for a in anomalies
        ],
        "alerts": [a.to_dict() for a in dispatcher.fired],
        "timeline": [
            {
                "window": w.window_start.isoformat(),
                "total":  w.total_logs,
                "errors": w.error_count,
            }
            for w in analyzer.timeline()
        ],
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"[green]JSON report written → {path}[/green]")
