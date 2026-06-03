#!/usr/bin/env python3
"""
PulseWatch CLI — Log Analysis and Incident Detection Tool

Usage examples:

  # Analyse simulated microservice logs (default 500 log lines)
  python main.py analyse

  # Analyse a real log file (JSON or Nginx combined format)
  python main.py analyse --file /var/log/app/service.log

  # Pipe logs from stdin
  cat service.log | python main.py analyse --stdin

  # Export a JSON report
  python main.py analyse --export report.json

  # Stream live logs (real-time mode)
  python main.py stream --duration 120
"""

import sys
import json
import click
import yaml

from pulsewatch.simulator  import generate_batch, stream_logs
from pulsewatch.parser     import parse_log_dicts, parse_lines
from pulsewatch.analyzer   import LogAnalyzer
from pulsewatch.anomaly    import AnomalyDetector
from pulsewatch.alerts     import AlertDispatcher, alert_from_error_group, alert_from_anomaly
from pulsewatch.reporter   import render_dashboard, export_json_report, console


def _load_config(config_path: str) -> dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _run_analysis(entries, cfg: dict, export_path: str | None) -> None:
    analysis_cfg = cfg.get("analysis", {})
    alert_cfg    = cfg.get("alerts",   {})

    analyzer = LogAnalyzer(min_group_size=analysis_cfg.get("min_group_size", 2))
    analyzer.ingest(entries)

    detector = AnomalyDetector(
        z_threshold=analysis_cfg.get("anomaly_z_threshold", 2.5),
        rolling_window=10,
    )

    dispatcher = AlertDispatcher(
        slack_webhook_url=alert_cfg.get("slack_webhook_url", ""),
        pagerduty_routing_key=alert_cfg.get("pagerduty_routing_key", ""),
        min_severity=alert_cfg.get("min_severity", "HIGH"),
        dry_run=True,   # flip to False to send real alerts
    )

    # Fire alerts for error groups
    timeline = analyzer.timeline()
    total_minutes = max(len(timeline), 1)
    for group in analyzer.error_groups():
        rate = group.count / total_minutes
        alert = alert_from_error_group(group, rate)
        dispatcher.fire(alert)

    # Fire alerts for anomalies
    for anomaly in detector.detect(timeline):
        dispatcher.fire(alert_from_anomaly(anomaly))

    render_dashboard(analyzer, detector, dispatcher)

    if export_path:
        export_json_report(analyzer, detector, dispatcher, export_path)


@click.group()
def cli():
    """PulseWatch — production log analysis and incident detection."""


@cli.command()
@click.option("--file",     "-f", default=None,    help="Path to a log file (JSON or Nginx format).")
@click.option("--stdin",    "-s", is_flag=True,    help="Read logs from stdin.")
@click.option("--lines",    "-n", default=500,     help="Number of simulated log lines (default 500).")
@click.option("--export",   "-e", default=None,    help="Export JSON report to this path.")
@click.option("--config",   "-c", default="config.yaml", help="Config file path.")
def analyse(file, stdin, lines, export, config):
    """Analyse a batch of logs and display the dashboard."""
    cfg = _load_config(config)

    if stdin:
        raw_lines = sys.stdin.read().splitlines()
        entries   = parse_lines(raw_lines)
        console.print(f"[cyan]Parsed {len(entries)} entries from stdin.[/cyan]")
    elif file:
        with open(file) as f:
            raw_lines = f.read().splitlines()
        entries = parse_lines(raw_lines)
        console.print(f"[cyan]Parsed {len(entries)} entries from {file}.[/cyan]")
    else:
        console.print(f"[cyan]Generating {lines} simulated microservice log lines…[/cyan]")
        log_dicts = generate_batch(total_logs=lines)
        entries   = parse_log_dicts(log_dicts)
        console.print(f"[cyan]Parsed {len(entries)} entries.[/cyan]\n")

    _run_analysis(entries, cfg, export)


@cli.command()
@click.option("--duration", "-d", default=60,  help="Stream duration in seconds (default 60).")
@click.option("--export",   "-e", default=None, help="Export JSON report when stream ends.")
@click.option("--config",   "-c", default="config.yaml", help="Config file path.")
def stream(duration, export, config):
    """Stream live (simulated) logs and refresh analysis in real-time."""
    cfg = _load_config(config)
    console.print(f"[cyan]Streaming logs for {duration}s — press Ctrl+C to stop early…[/cyan]\n")

    log_dicts = []
    try:
        for log in stream_logs(duration_seconds=duration, incident_probability=0.15):
            log_dicts.append(log)
            # Print each log line as it arrives
            level = log.get("level", "INFO")
            color = {"ERROR": "red", "WARNING": "yellow", "INFO": "green",
                     "DEBUG": "dim"}.get(level, "white")
            console.print(
                f"[dim]{log['timestamp']}[/dim] "
                f"[{color}]{level:8}[/{color}] "
                f"[cyan]{log['service']:22}[/cyan] "
                f"{log['message'][:90]}"
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Stream interrupted.[/yellow]")

    console.print(f"\n[cyan]Collected {len(log_dicts)} log entries. Analysing…[/cyan]\n")
    entries = parse_log_dicts(log_dicts)
    _run_analysis(entries, cfg, export)


if __name__ == "__main__":
    cli()
