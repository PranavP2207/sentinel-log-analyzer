"""Read inputs and build a report without changing the source logs."""

import gzip
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .detector import detect
from .models import AnalysisReport, AuthEvent, DetectionConfig, InputStats
from .parser import LogParser


def analyze(
    sources: list[str], config: DetectionConfig | None = None, *,
    year: int | None = None, utc_offset: str = "+00:00", stdin: TextIO | None = None,
) -> AnalysisReport:
    if not sources:
        raise ValueError("at least one input file or '-' for stdin is required")
    if sources.count("-") > 1:
        raise ValueError("stdin can only be read once")
    effective_year = datetime.now(timezone.utc).year if year is None else year
    config = config or DetectionConfig()
    # Validate assumptions before opening any input, including empty files.
    LogParser(effective_year, utc_offset)
    stats = InputStats()
    events: list[AuthEvent] = []
    for source in sources:
        parser = LogParser(effective_year, utc_offset)
        if source == "-":
            if stdin is None:
                raise ValueError("stdin was requested but no input stream was supplied")
            stream_context = nullcontext(stdin)
        else:
            opener = gzip.open if Path(source).suffix.lower() == ".gz" else open
            stream_context = opener(source, "rt", encoding="utf-8", errors="replace")
        with stream_context as stream:
            for number, line in enumerate(stream, 1):
                stats.total_lines += 1
                result = parser.parse_line(line, source, number)
                if result.status == "parsed":
                    assert result.event is not None
                    events.append(result.event)
                    stats.parsed_events += 1
                    stats.yearless_events += int(result.yearless)
                elif result.status == "blank":
                    stats.blank_lines += 1
                elif result.status == "malformed":
                    stats.malformed_lines += 1
                    if len(stats.diagnostics) < 5:
                        stats.diagnostics.append(f"{source}:{number}: {result.reason}")
                else:
                    stats.ignored_lines += 1
    ordered = sorted(events, key=lambda event: event.timestamp)
    return AnalysisReport(
        sources=tuple(sources), stats=stats, config=config, year=effective_year, utc_offset=utc_offset,
        failed_events=sum(event.outcome == "failed" for event in ordered),
        accepted_events=sum(event.outcome == "accepted" for event in ordered),
        first_event=ordered[0].timestamp if ordered else None,
        last_event=ordered[-1].timestamp if ordered else None,
        alerts=detect(ordered, config),
    )
