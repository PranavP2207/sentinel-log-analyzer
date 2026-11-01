import json
import unittest
from datetime import datetime, timezone

from sentinel.parser import LogParser, parse_utc_offset


class ParserTests(unittest.TestCase):
    def test_bsd_syslog_fields_and_fixed_timezone(self):
        result = LogParser(2026, "+05:30").parse_line(
            "Nov  1 09:00:00 bastion sshd[42]: Failed password for invalid user deploy from 203.0.113.7 port 42000 ssh2",
            "auth.log", 17,
        )
        self.assertEqual(result.status, "parsed")
        event = result.event
        self.assertEqual(event.timestamp, datetime(2026, 11, 1, 3, 30, tzinfo=timezone.utc))
        self.assertEqual((event.host, event.source_ip, event.username), ("bastion", "203.0.113.7", "deploy"))
        self.assertEqual((event.outcome, event.method, event.invalid_user), ("failed", "password", True))
        self.assertEqual((event.source, event.line_number), ("auth.log", 17))
        self.assertTrue(result.yearless)

    def test_iso_syslog_microseconds_ipv6_and_method(self):
        result = LogParser(2020).parse_line(
            "2026-11-01T09:00:00.123456-04:00 web sshd-session[12]: Accepted publickey for alice from 2001:0db8:0:0::7 port 2222 ssh2: ED25519 SHA256:sample",
            "secure", 2,
        )
        self.assertEqual(result.status, "parsed")
        self.assertEqual(result.event.timestamp, datetime(2026, 11, 1, 13, 0, 0, 123456, tzinfo=timezone.utc))
        self.assertEqual(result.event.source_ip, "2001:db8::7")
        self.assertEqual((result.event.outcome, result.event.method), ("accepted", "publickey"))
        self.assertFalse(result.yearless)

    def test_iso_without_timezone_uses_explicit_offset(self):
        result = LogParser(2026, "-04:00").parse_line(
            "2026-11-01T09:00:00 web sshd-auth[12]: Failed keyboard-interactive/pam for bob from ::1 port 42 ssh2",
            "secure", 1,
        )
        self.assertEqual(result.status, "parsed")
        self.assertEqual(result.event.timestamp.hour, 13)
        self.assertEqual(result.event.method, "keyboard-interactive/pam")

    def test_year_rollover_is_inferred_from_all_syslog_records(self):
        parser = LogParser(2025)
        parser.parse_line("Dec 31 23:59:58 web CRON[1]: job", "auth.log", 1)
        result = parser.parse_line(
            "Jan  1 00:00:02 web sshd[2]: Failed password for bob from ::1 port 42 ssh2", "auth.log", 2,
        )
        self.assertEqual(result.event.timestamp, datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc))

    def test_ordinary_out_of_order_month_does_not_increment_year(self):
        parser = LogParser(2026)
        parser.parse_line("Nov  1 09:00:00 web CRON[1]: job", "auth.log", 1)
        result = parser.parse_line(
            "Oct 31 09:00:00 web sshd[2]: Failed password for bob from ::1 port 42 ssh2", "auth.log", 2,
        )
        self.assertEqual(result.event.timestamp.year, 2026)

    def test_journal_timestamp_uses_exact_microseconds_and_comm_fallback(self):
        record = {
            "__REALTIME_TIMESTAMP": "1793523600123456", "_HOSTNAME": "web",
            "_COMM": "sshd-auth", "MESSAGE": "Failed password for alice from ::1 port 42 ssh2",
        }
        result = LogParser(2020, "+05:30").parse_line(json.dumps(record), "journal.jsonl", 3)
        self.assertEqual(result.status, "parsed")
        self.assertEqual(result.event.timestamp, datetime(2026, 11, 1, 9, 0, 0, 123456, tzinfo=timezone.utc))
        self.assertEqual((result.event.host, result.event.username), ("web", "alice"))

    def test_missing_journal_hostname_is_scoped_to_source(self):
        record = {
            "__REALTIME_TIMESTAMP": "1793523600000000", "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for alice from ::1 port 42 ssh2",
        }
        result = LogParser(2026).parse_line(json.dumps(record), "one.jsonl", 1)
        self.assertEqual(result.event.host, "unknown-host@one.jsonl")

    def test_pam_and_non_ssh_auth_messages_are_ignored(self):
        for line in (
            "Nov  1 09:00:00 web sshd[42]: pam_unix(sshd:auth): authentication failure; rhost=::1 user=bob",
            "Nov  1 09:00:00 web sshd[42]: Invalid user bob from ::1 port 42",
            "Nov  1 09:00:00 web sudo[42]: Failed password for bob from ::1 port 42 ssh2",
        ):
            with self.subTest(line=line):
                self.assertEqual(LogParser(2026).parse_line(line, "auth.log", 1).status, "ignored")

    def test_invalid_ssh_records_are_malformed_not_events(self):
        for line in (
            "Nov 32 09:00:00 web sshd[42]: Failed password for bob from ::1 port 42 ssh2",
            "Nov  1 09:00:00 web sshd[42]: Failed password for bob from 999.1.1.1 port 42 ssh2",
            "Nov  1 09:00:00 web sshd[42]: Failed password for bob from ::1 port 70000 ssh2",
            "Nov  1 09:00:00 web sshd[42]: Accepted password for bob (truncated)",
            '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":null}',
            '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"x","__REALTIME_TIMESTAMP":"nan"}',
            '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"x","__REALTIME_TIMESTAMP":"999999999999999999"}',
            '{"broken":',
        ):
            with self.subTest(line=line):
                result = LogParser(2026).parse_line(line, "auth.log", 1)
                self.assertEqual(result.status, "malformed")
                self.assertIsNone(result.event)
                self.assertIsInstance(result.reason, str)

    def test_blank_unrecognized_and_bom_input(self):
        parser = LogParser(2026)
        self.assertEqual(parser.parse_line("\n", "auth.log", 1).status, "blank")
        self.assertEqual(parser.parse_line("not a log", "auth.log", 1).status, "ignored")
        self.assertEqual(parser.parse_line(
            "\ufeffNov  1 09:00:00 web sshd[42]: Failed password for bob from ::1 port 42 ssh2\n", "auth.log", 1,
        ).status, "parsed")

    def test_utc_offset_validation(self):
        for offset in ("local", "+24:00", "05:30", "+01:60"):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                parse_utc_offset(offset)


if __name__ == "__main__":
    unittest.main()
