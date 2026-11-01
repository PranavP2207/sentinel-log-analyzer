"""Parse OpenSSH authentication records from syslog and journal JSON lines."""

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import AuthEvent

MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}
SYSLOG = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w/-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
ISO_SYSLOG = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w/-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
AUTH_MESSAGE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\S+) for "
    r"(?P<invalid>invalid user )?(?P<user>.+?) from (?P<ip>\S+) "
    r"port (?P<port>\d+) ssh2(?:$|[ :].*)"
)
SSH_PROGRAMS = {"sshd", "sshd-session", "sshd-auth"}
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ParseResult:
    status: str
    event: AuthEvent | None = None
    reason: str | None = None
    yearless: bool = False


def parse_utc_offset(value: str) -> timezone:
    """Accept explicit fixed offsets; don't depend on the host's timezone."""
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", value)
    if not match:
        raise ValueError("UTC offset must use +HH:MM or -HH:MM")
    hours, minutes = int(match[2]), int(match[3])
    if hours > 23 or minutes > 59:
        raise ValueError("UTC offset must be less than 24 hours")
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(-delta if match[1] == "-" else delta)


class LogParser:
    """A parser per input file, with Dec-to-Jan year inference for BSD syslog."""

    def __init__(self, year: int, utc_offset: str = "+00:00") -> None:
        if not 1 <= year <= 9999:
            raise ValueError("year must be between 1 and 9999")
        self.year = year
        self.tz = parse_utc_offset(utc_offset)
        self.previous_month: int | None = None

    def parse_line(self, line: str, source: str, line_number: int) -> ParseResult:
        raw = line.rstrip("\r\n")
        if not raw.strip():
            return ParseResult("blank")
        if "\ufffd" in raw:
            return ParseResult("malformed", reason="UTF-8 replacement character found; check the log encoding")
        # A BOM can occur in the first line of an exported text file.
        content = raw.removeprefix("\ufeff") if line_number == 1 else raw
        try:
            if content.lstrip().startswith("{"):
                return self._journal(content, raw, source, line_number)
            match = SYSLOG.match(content) or ISO_SYSLOG.match(content)
            if not match:
                return ParseResult("ignored")
            fields = match.groupdict()
            stamp, yearless = self._syslog_timestamp(fields["stamp"])
            return self._auth(
                stamp, fields["host"], fields["program"], fields["message"],
                raw, source, line_number, yearless,
            )
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            # Bad input must not abort the rest of a usable export.
            return ParseResult("malformed", reason=str(exc) or "invalid record")

    def _syslog_timestamp(self, value: str) -> tuple[datetime, bool]:
        if value[0].isdigit():
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=self.tz)
            return timestamp.astimezone(timezone.utc), False
        month_name, day, clock = value.split()
        month = MONTHS.get(month_name)
        if month is None:
            raise ValueError(f"unknown syslog month: {month_name}")
        year = self.year + int(self.previous_month == 12 and month == 1)
        hour, minute, second = map(int, clock.split(":"))
        timestamp = datetime(year, month, int(day), hour, minute, second, tzinfo=self.tz)
        self.year, self.previous_month = year, month
        return timestamp.astimezone(timezone.utc), True

    def _journal(self, content: str, raw: str, source: str, line_number: int) -> ParseResult:
        record = json.loads(content)
        if not isinstance(record, dict):
            raise ValueError("journal record must be a JSON object")
        program = record.get("SYSLOG_IDENTIFIER") or record.get("_COMM", "")
        if not isinstance(program, str):
            raise ValueError("journal identifier must be a string")
        if program not in SSH_PROGRAMS:
            return ParseResult("ignored")
        message = record.get("MESSAGE")
        if not isinstance(message, str):
            raise ValueError("SSH journal MESSAGE must be a text string")
        micros = record.get("__REALTIME_TIMESTAMP")
        if not isinstance(micros, str) or not re.fullmatch(r"[0-9]{1,18}", micros):
            raise ValueError("journal __REALTIME_TIMESTAMP must be microseconds since epoch")
        timestamp = EPOCH + timedelta(microseconds=int(micros))
        host = record.get("_HOSTNAME", f"unknown-host@{source}")
        if not isinstance(host, str) or not host:
            raise ValueError("journal _HOSTNAME must be a nonempty string")
        return self._auth(timestamp, host, program, message, raw, source, line_number, False)

    @staticmethod
    def _auth(
        timestamp: datetime, host: str, program: str, message: str,
        raw: str, source: str, line_number: int, yearless: bool,
    ) -> ParseResult:
        if program not in SSH_PROGRAMS:
            return ParseResult("ignored")
        match = AUTH_MESSAGE.fullmatch(message)
        if not match:
            if message.startswith(("Failed ", "Accepted ")):
                raise ValueError("unrecognized SSH authentication message")
            return ParseResult("ignored")
        ip = ipaddress.ip_address(match["ip"])
        if not 1 <= int(match["port"]) <= 65535:
            raise ValueError("SSH source port must be between 1 and 65535")
        event = AuthEvent(
            timestamp=timestamp, host=host, source_ip=str(ip), username=match["user"],
            outcome="failed" if match["result"] == "Failed" else "accepted",
            method=match["method"], invalid_user=bool(match["invalid"]),
            source=source, line_number=line_number, raw=raw,
        )
        return ParseResult("parsed", event=event, yearless=yearless)
