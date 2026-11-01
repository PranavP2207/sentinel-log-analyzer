"""Human-readable reports and a versioned JSON report contract."""

import json
import unicodedata
from dataclasses import asdict
from datetime import datetime

from .models import AnalysisReport


def safe_text(value: str) -> str:
    """Escape terminal controls and bidi overrides from untrusted log content."""
    return "".join(
        (f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char)
        for char in value
    )


def timestamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def report_dict(report: AnalysisReport) -> dict:
    alerts = []
    for alert in report.alerts:
        data = asdict(alert)
        data["first_seen"], data["last_seen"] = timestamp(alert.first_seen), timestamp(alert.last_seen)
        for evidence, event in zip(data["evidence"], alert.evidence):
            evidence["timestamp"] = timestamp(event.timestamp)
        alerts.append(data)
    return {
        "schema_version": 1,
        "status": report.status,
        "sources": list(report.sources),
        "summary": {
            **asdict(report.stats),
            "failed_events": report.failed_events,
            "accepted_events": report.accepted_events,
            "first_event": timestamp(report.first_event),
            "last_event": timestamp(report.last_event),
            "alert_count": len(report.alerts),
        },
        "configuration": {
            **asdict(report.config), "syslog_start_year": report.year,
            "syslog_utc_offset": report.utc_offset,
        },
        "alerts": alerts,
    }


def render_json(report: AnalysisReport) -> str:
    return json.dumps(report_dict(report), indent=2, ensure_ascii=True) + "\n"


def render_text(report: AnalysisReport) -> str:
    stats = report.stats
    lines = [
        "SENTINEL | SSH authentication log analysis",
        "=" * 56,
        f"Inputs: {', '.join(safe_text(source) for source in report.sources)}",
        f"Records: {stats.total_lines} lines | {stats.parsed_events} SSH authentication events",
        f"Outcomes: {report.failed_events} failed | {report.accepted_events} accepted",
        f"Skipped: {stats.ignored_lines} unrelated/unsupported | {stats.malformed_lines} malformed | {stats.blank_lines} blank",
        f"Rules: {report.config.threshold} failures / {report.config.window_seconds}s; "
        f"{report.config.spray_threshold} distinct usernames / {report.config.window_seconds}s",
        f"Timestamp default: UTC{report.utc_offset} for records without a timezone",
    ]
    if stats.yearless_events:
        lines.append(
            f"Syslog assumptions: starting year {report.year}; "
            "Dec-to-Jan rollover inferred per file"
        )
    if report.first_event is not None:
        lines.append(f"Event range (UTC): {timestamp(report.first_event)} to {timestamp(report.last_event)}")
    lines.append("")
    if report.status == "no_supported_events":
        lines.append("NO ASSESSMENT: No supported SSH authentication events were found.")
    elif report.status == "partial":
        lines.append("PARTIAL ANALYSIS: Malformed records were skipped; review the diagnostics below.")
    if report.alerts:
        lines.append(f"{len(report.alerts)} alert(s) to review. Patterns are indicators, not proof of compromise.")
        for number, alert in enumerate(report.alerts, 1):
            lines.extend([
                "", f"{number}. [{alert.severity.upper()}] {alert.title} ({alert.rule})",
                f"   Host: {safe_text(alert.host)} | Source IP: {alert.source_ip}",
                f"   Usernames: {', '.join(safe_text(user) for user in alert.users)}",
                f"   Window (UTC): {timestamp(alert.first_seen)} to {timestamp(alert.last_seen)}",
                f"   Failed attempts: {alert.failed_attempts} | Relevant events: {alert.evidence_total}",
                "   Evidence:",
            ])
            for event in alert.evidence:
                # JSON retains full records; bound text lines for readable terminal output.
                excerpt = event.raw if len(event.raw) <= 400 else event.raw[:397] + "..."
                lines.append(f"     {safe_text(event.source)}:{event.line_number} | {safe_text(excerpt)}")
            omitted = alert.evidence_total - len(alert.evidence)
            if omitted:
                lines.append(f"     ... {omitted} additional event(s) omitted from evidence samples")
            lines.append(f"   Review: {alert.recommendation}")
    elif report.stats.parsed_events:
        lines.append("No suspicious patterns matched the configured rules in the parsed SSH events.")
    if stats.diagnostics:
        lines.extend(["", "Malformed record diagnostics (up to 5):"])
        lines.extend(f"  {safe_text(diagnostic)}" for diagnostic in stats.diagnostics)
    return "\n".join(lines) + "\n"
