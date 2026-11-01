"""Deterministic sliding-window rules, scoped to destination host and source IP."""

from collections import Counter, defaultdict, deque
from datetime import timedelta
from typing import Callable, Iterable

from .models import Alert, AuthEvent, DetectionConfig

MAX_EVIDENCE = 10
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


def _alert(rule: str, events: list[AuthEvent]) -> Alert:
    failed = sum(event.outcome == "failed" for event in events)
    users = tuple(sorted({event.username for event in events}))
    details = {
        "repeated_failures": (
            "high", "Repeated SSH authentication failures",
            "Review the source, accounts, and SSH access policy; check whether these attempts are expected.",
        ),
        "multiple_usernames": (
            "medium", "SSH failures across multiple usernames",
            "Review the targeted accounts and source; this pattern can indicate account guessing or password spraying.",
        ),
        "success_after_failures": (
            "critical", "Successful SSH login after repeated failures",
            "Verify this login with the account owner and investigate subsequent activity if it was unexpected.",
        ),
    }
    severity, title, recommendation = details[rule]
    # Preserve both the first event and the last (including a successful login).
    evidence = events if len(events) <= MAX_EVIDENCE else events[:MAX_EVIDENCE - 1] + events[-1:]
    return Alert(
        rule=rule, severity=severity, title=title, host=events[-1].host,
        source_ip=events[-1].source_ip, users=users,
        first_seen=events[0].timestamp, last_seen=events[-1].timestamp,
        failed_attempts=failed, evidence_total=len(events), evidence=tuple(evidence),
        recommendation=recommendation,
    )


def _failure_windows(
    failures: list[AuthEvent], config: DetectionConfig, rule: str,
    qualifies: Callable[[deque[AuthEvent], Counter[str]], bool],
    score: Callable[[deque[AuthEvent], Counter[str]], tuple[int, ...]],
) -> list[Alert]:
    """Merge overlapping qualifying windows and retain the strongest window."""
    window: deque[AuthEvent] = deque()
    users: Counter[str] = Counter()
    candidates: list[tuple[int, int]] = []
    active_index: int | None = None
    active_end = None
    best_score: tuple[int, ...] = ()
    duration = timedelta(seconds=config.window_seconds)
    left = 0
    for right, event in enumerate(failures):
        while window and event.timestamp - window[0].timestamp > duration:
            expired = window.popleft()
            left += 1
            users[expired.username] -= 1
            if users[expired.username] == 0:
                del users[expired.username]
        window.append(event)
        users[event.username] += 1
        if not qualifies(window, users):
            continue
        current_score = score(window, users)
        if active_index is None or window[0].timestamp > active_end:
            candidates.append((left, right + 1))
            active_index = len(candidates) - 1
            best_score = current_score
        elif current_score > best_score:
            candidates[active_index] = (left, right + 1)
            best_score = current_score
        active_end = event.timestamp
    return [_alert(rule, failures[start:stop]) for start, stop in candidates]


def detect(events: Iterable[AuthEvent], config: DetectionConfig) -> tuple[Alert, ...]:
    ordered = sorted(events, key=lambda event: (event.timestamp, event.outcome == "accepted"))
    groups: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for event in ordered:
        groups[(event.host, event.source_ip)].append(event)
    alerts: list[Alert] = []
    for group in groups.values():
        failures = [event for event in group if event.outcome == "failed"]
        alerts.extend(_failure_windows(
            failures, config, "repeated_failures",
            lambda window, users: len(window) >= config.threshold,
            lambda window, users: (len(window),),
        ))
        alerts.extend(_failure_windows(
            failures, config, "multiple_usernames",
            lambda window, users: len(users) >= config.spray_threshold,
            lambda window, users: (len(users), len(window)),
        ))
        # A successful login only correlates with failures for the same account.
        # Consuming those failures avoids flagging every later legitimate login.
        pending: dict[str, deque[AuthEvent]] = defaultdict(deque)
        duration = timedelta(seconds=config.window_seconds)
        for event in group:
            window = pending[event.username]
            while window and event.timestamp - window[0].timestamp > duration:
                window.popleft()
            if event.outcome == "failed":
                window.append(event)
            else:
                # Same-second records have no reliable sub-second ordering.
                preceding = [failure for failure in window if failure.timestamp < event.timestamp]
                if len(preceding) >= config.threshold:
                    alerts.append(_alert("success_after_failures", preceding + [event]))
                window.clear()
    return tuple(sorted(alerts, key=lambda alert: (
        SEVERITY_ORDER[alert.severity], alert.first_seen, alert.host, alert.source_ip, alert.rule
    )))
