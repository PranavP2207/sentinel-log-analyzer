"""Shared records for parsing, detection, and reporting."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    source_ip: str
    username: str
    outcome: str
    method: str
    invalid_user: bool
    source: str
    line_number: int
    raw: str


@dataclass(frozen=True)
class DetectionConfig:
    threshold: int = 5
    window_seconds: int = 300
    spray_threshold: int = 3

    def __post_init__(self) -> None:
        if self.threshold < 2 or self.spray_threshold < 2:
            raise ValueError("failure and username thresholds must be at least 2")
        if self.window_seconds < 1:
            raise ValueError("window must be at least 1 second")


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    title: str
    host: str
    source_ip: str
    users: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    failed_attempts: int
    evidence_total: int
    evidence: tuple[AuthEvent, ...]
    recommendation: str


@dataclass
class InputStats:
    total_lines: int = 0
    blank_lines: int = 0
    ignored_lines: int = 0
    malformed_lines: int = 0
    parsed_events: int = 0
    yearless_events: int = 0
    diagnostics: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AnalysisReport:
    sources: tuple[str, ...]
    stats: InputStats
    config: DetectionConfig
    year: int
    utc_offset: str
    failed_events: int
    accepted_events: int
    first_event: datetime | None
    last_event: datetime | None
    alerts: tuple[Alert, ...]

    @property
    def status(self) -> str:
        if self.stats.parsed_events == 0:
            return "no_supported_events"
        return "partial" if self.stats.malformed_lines else "ok"
