import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "examples" / "auth.log"
CLEAN = ROOT / "examples" / "clean.log"


def run_cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *map(str, args)],
        input=stdin, capture_output=True, text=True, encoding="utf-8", cwd=ROOT,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"}, timeout=15,
    )


class CLITests(unittest.TestCase):
    def test_demo_json_has_expected_rules_counts_and_source_evidence(self):
        result = run_cli("analyze", AUTH, "--year", "2026", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["schema_version"], report["status"]), (1, "ok"))
        self.assertEqual(report["summary"]["total_lines"], 16)
        self.assertEqual(report["summary"]["parsed_events"], 13)
        self.assertEqual(report["summary"]["failed_events"], 10)
        self.assertEqual(report["summary"]["accepted_events"], 3)
        self.assertEqual(report["summary"]["ignored_lines"], 3)
        self.assertEqual(report["summary"]["malformed_lines"], 0)
        self.assertEqual([alert["rule"] for alert in report["alerts"]], [
            "success_after_failures", "repeated_failures", "multiple_usernames",
        ])
        success = report["alerts"][0]
        self.assertEqual((success["source_ip"], success["failed_attempts"], success["evidence_total"]), ("203.0.113.24", 6, 7))
        self.assertEqual([item["line_number"] for item in success["evidence"]], [1, 3, 4, 5, 6, 7, 8])
        self.assertEqual(success["evidence"][-1]["source"], str(AUTH))
        self.assertEqual(success["evidence"][-1]["outcome"], "accepted")
        self.assertEqual(success["first_seen"], "2026-11-01T09:00:00Z")
        self.assertEqual(report["alerts"][2]["users"], ["deploy", "root", "test"])

    def test_clean_input_and_alert_exit_codes(self):
        clean = run_cli("analyze", CLEAN, "--fail-on-alert", "--format", "json")
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(json.loads(clean.stdout)["alerts"], [])
        suspicious = run_cli("analyze", AUTH, "--fail-on-alert", "--year", "2026")
        self.assertEqual(suspicious.returncode, 1)
        self.assertIn("[CRITICAL] Successful SSH login", suspicious.stdout)
        self.assertIn("[HIGH] Repeated SSH", suspicious.stdout)
        self.assertIn("[MEDIUM] SSH failures across", suspicious.stdout)

    def test_stdin_with_custom_threshold_and_window(self):
        data = (
            "Nov  1 09:00:00 web sshd[1]: Failed password for bob from ::1 port 42 ssh2\n"
            "Nov  1 09:00:30 web sshd[2]: Failed password for bob from ::1 port 43 ssh2\n"
        )
        result = run_cli("analyze", "-", "--threshold", "2", "--window", "30s", "--year", "2026", "--utc-offset=-04:00", "--format", "json", stdin=data)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["configuration"]["window_seconds"], 30)
        self.assertEqual(report["alerts"][0]["first_seen"], "2026-11-01T13:00:00Z")
        self.assertEqual([item["source"] for item in report["alerts"][0]["evidence"]], ["-", "-"])

    def test_plain_and_gzip_files_correlate_across_inputs_and_write_output(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "old.log.gz"
            second = Path(directory) / "new.log"
            output = Path(directory) / "report.json"
            attempts = [
                f"2026-11-01T09:00:0{n}Z web sshd[{n + 1}]: Failed password for bob from ::1 port {42 + n} ssh2\n"
                for n in range(5)
            ]
            with gzip.open(first, "wt", encoding="utf-8") as stream:
                stream.writelines(attempts[:3])
            second.write_text("".join(attempts[3:]), encoding="utf-8")
            result = run_cli("analyze", second, first, "--format", "json", "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["alerts"][0]["failed_attempts"], 5)
            self.assertEqual([item["source"] for item in report["alerts"][0]["evidence"]], [str(first)] * 3 + [str(second)] * 2)

    def test_journal_fixture(self):
        result = run_cli("analyze", ROOT / "examples" / "journal.jsonl", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([alert["rule"] for alert in report["alerts"]], ["success_after_failures", "repeated_failures"])
        self.assertEqual(report["summary"]["first_event"], "2026-11-01T09:00:00Z")
        self.assertEqual(report["summary"]["yearless_events"], 0)

    def test_malformed_records_produce_partial_report_and_exit_two(self):
        data = AUTH.read_text(encoding="utf-8") + "\n".join(['{"bad":'] * 7) + "\n"
        result = run_cli("analyze", "-", "--format", "json", "--fail-on-alert", stdin=data)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["parsed_events"], 13)
        self.assertEqual(report["summary"]["alert_count"], 3)
        self.assertEqual(report["summary"]["malformed_lines"], 7)
        self.assertEqual(len(report["summary"]["diagnostics"]), 5)
        self.assertIn("partial", result.stderr)

    def test_empty_and_unsupported_inputs_do_not_return_a_clean_assessment(self):
        for data in ("", "\n\n", "not a supported log\n"):
            with self.subTest(data=data):
                result = run_cli("analyze", "-", "--format", "json", stdin=data)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "no_supported_events")

    def test_terminal_control_sequences_are_escaped_in_text_and_json(self):
        data = (
            "Nov  1 09:00:00 web sshd[1]: Failed password for \x1b[31mbob from ::1 port 42 ssh2\n"
            "Nov  1 09:00:01 web sshd[2]: Failed password for \x1b[31mbob from ::1 port 43 ssh2\n"
        )
        for format_name in ("text", "json"):
            with self.subTest(format=format_name):
                result = run_cli("analyze", "-", "--threshold", "2", "--format", format_name, stdin=data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("\x1b", result.stdout)
                self.assertIn("\\u001b", result.stdout)
                if format_name == "json":
                    self.assertEqual(json.loads(result.stdout)["alerts"][0]["users"], ["\x1b[31mbob"])

    def test_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            source.write_text(CLEAN.read_text(encoding="utf-8"), encoding="utf-8")
            original = source.read_bytes()
            result = run_cli("analyze", source, "--output", source)
            self.assertEqual(result.returncode, 2)
            self.assertIn("must not overwrite", result.stderr)
            self.assertEqual(source.read_bytes(), original)

    def test_output_cannot_overwrite_input_via_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.log"
            alias = Path(directory) / "alias.log"
            source.write_text(CLEAN.read_text(encoding="utf-8"), encoding="utf-8")
            original = source.read_bytes()
            try:
                os.link(source, alias)
            except OSError as exc:
                self.skipTest(f"hard-link creation unavailable: {exc.strerror}")
            result = run_cli("analyze", source, "--output", alias)
            self.assertEqual(result.returncode, 2)
            self.assertIn("must not overwrite", result.stderr)
            self.assertEqual(source.read_bytes(), original)

    def test_missing_and_corrupt_files_fail_without_tracebacks(self):
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / "corrupt.log.gz"
            corrupt.write_bytes(b"not a gzip archive")
            truncated = Path(directory) / "truncated.log.gz"
            truncated.write_bytes(gzip.compress(CLEAN.read_bytes())[:-8])
            for path in (Path(directory) / "missing.log", corrupt, truncated, Path(directory)):
                with self.subTest(path=path):
                    result = run_cli("analyze", path)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertIn("sentinel:", result.stderr)

    def test_bad_arguments_are_rejected(self):
        for args in (
            ("--threshold", "1"), ("--window", "0s"), ("--window", "1day"),
            ("--spray-threshold", "zero"), ("--year", "10000"), ("--utc-offset", "+24:00"),
        ):
            with self.subTest(args=args):
                result = run_cli("analyze", CLEAN, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)
        duplicate = run_cli("analyze", CLEAN, CLEAN)
        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("more than once", duplicate.stderr)

    def test_invalid_utf8_is_reported_instead_of_silently_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "encoding.log"
            source.write_bytes(CLEAN.read_bytes() + b"Nov  1 09:00:00 web sshd[1]: Failed password for \xffbob from ::1 port 42 ssh2\n")
            result = run_cli("analyze", source, "--format", "json")
            self.assertEqual(result.returncode, 2)
            report = json.loads(result.stdout)
            self.assertEqual(report["summary"]["parsed_events"], 3)
            self.assertEqual(report["summary"]["malformed_lines"], 1)
            self.assertIn("encoding", report["summary"]["diagnostics"][0])


if __name__ == "__main__":
    unittest.main()
