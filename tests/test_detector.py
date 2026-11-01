import unittest
from datetime import datetime, timedelta, timezone

from sentinel.detector import detect
from sentinel.models import AuthEvent, DetectionConfig

START = datetime(2026, 11, 1, 9, tzinfo=timezone.utc)


def event(seconds, *, username="alice", host="bastion", ip="203.0.113.24", outcome="failed", line=1):
    return AuthEvent(
        timestamp=START + timedelta(seconds=seconds), host=host, source_ip=ip,
        username=username, outcome=outcome, method="password", invalid_user=False,
        source="auth.log", line_number=line, raw=f"synthetic event {line}",
    )


def rule_alerts(events, rule, config=None):
    return [alert for alert in detect(events, config or DetectionConfig()) if alert.rule == rule]


class DetectionTests(unittest.TestCase):
    def test_threshold_requires_five_failures_and_preserves_evidence(self):
        attempts = [event(n * 10, line=n + 1) for n in range(5)]
        self.assertEqual(detect(attempts[:4], DetectionConfig()), ())
        alerts = detect(attempts, DetectionConfig())
        self.assertEqual([alert.rule for alert in alerts], ["repeated_failures"])
        alert = alerts[0]
        self.assertEqual((alert.severity, alert.failed_attempts, alert.users), ("high", 5, ("alice",)))
        self.assertEqual((alert.first_seen, alert.last_seen), (START, START + timedelta(seconds=40)))
        self.assertEqual([entry.line_number for entry in alert.evidence], [1, 2, 3, 4, 5])

    def test_window_boundary_is_inclusive_but_one_second_later_expires(self):
        inside = [event(second) for second in (0, 75, 150, 225, 300)]
        outside = [event(second) for second in (0, 75, 150, 225, 301)]
        self.assertEqual(len(rule_alerts(inside, "repeated_failures")), 1)
        self.assertEqual(rule_alerts(outside, "repeated_failures"), [])

    def test_sliding_window_crosses_clock_bucket_boundary(self):
        attempts = [event(second) for second in (298, 299, 300, 301, 302)]
        alerts = rule_alerts(attempts, "repeated_failures")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failed_attempts, 5)

    def test_sources_and_destination_hosts_are_isolated(self):
        for attempts in (
            [event(n, host="one" if n < 3 else "two") for n in range(5)],
            [event(n, ip="192.0.2.1" if n < 3 else "192.0.2.2") for n in range(5)],
        ):
            with self.subTest(attempts=attempts):
                self.assertEqual(detect(attempts, DetectionConfig()), ())

    def test_overlapping_windows_keep_peak_instead_of_repeating_alert(self):
        alerts = rule_alerts([event(n, line=n + 1) for n in range(12)], "repeated_failures")
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].failed_attempts, alerts[0].evidence_total), (12, 12))
        self.assertEqual(len(alerts[0].evidence), 10)
        self.assertEqual((alerts[0].evidence[0].line_number, alerts[0].evidence[-1].line_number), (1, 12))

    def test_separated_bursts_produce_two_alerts(self):
        alerts = rule_alerts([event(n) for n in (0, 1, 2, 3, 4, 601, 602, 603, 604, 605)], "repeated_failures")
        self.assertEqual([alert.failed_attempts for alert in alerts], [5, 5])
        self.assertEqual([alert.first_seen for alert in alerts], [START, START + timedelta(seconds=601)])

    def test_multiple_usernames_uses_distinct_names_in_current_window(self):
        duplicate = [event(0, username="bob"), event(1, username="bob"), event(2, username="alice")]
        self.assertEqual(detect(duplicate, DetectionConfig()), ())
        unique = duplicate + [event(3, username="carol")]
        alerts = detect(unique, DetectionConfig())
        self.assertEqual([alert.rule for alert in alerts], ["multiple_usernames"])
        self.assertEqual(alerts[0].users, ("alice", "bob", "carol"))
        expired = [event(0, username="bob"), event(301, username="alice"), event(302, username="carol")]
        self.assertEqual(detect(expired, DetectionConfig()), ())

    def test_success_after_failures_requires_same_user_host_ip_and_window(self):
        failures = [event(n) for n in (0, 10, 20, 30, 40)]
        for success in (
            event(50, outcome="accepted", username="bob"),
            event(50, outcome="accepted", host="elsewhere"),
            event(50, outcome="accepted", ip="192.0.2.9"),
            event(301, outcome="accepted"),
        ):
            with self.subTest(success=success):
                self.assertEqual(rule_alerts(failures + [success], "success_after_failures"), [])
        alerts = rule_alerts(failures + [event(50, outcome="accepted", line=6)], "success_after_failures")
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].severity, alerts[0].failed_attempts), ("critical", 5))
        self.assertEqual(alerts[0].evidence[-1].outcome, "accepted")
        self.assertEqual(alerts[0].evidence[-1].line_number, 6)

    def test_success_consumes_correlated_failures(self):
        attempts = [event(n) for n in (0, 1, 2, 3, 4)] + [event(5, outcome="accepted"), event(6, outcome="accepted")]
        self.assertEqual(len(rule_alerts(attempts, "success_after_failures")), 1)

    def test_success_correlation_ignores_equal_timestamp_failures_in_any_input_order(self):
        failures = [event(0) for _ in range(5)]
        accepted = event(0, outcome="accepted")
        later = event(1, outcome="accepted")
        for attempts in (failures + [accepted, later], [accepted] + failures + [later]):
            self.assertEqual(rule_alerts(attempts, "success_after_failures"), [])

    def test_out_of_order_dated_events_are_sorted_before_correlation(self):
        attempts = [event(50, outcome="accepted")] + [event(n) for n in (40, 0, 30, 10, 20)]
        alerts = detect(attempts, DetectionConfig())
        self.assertEqual([alert.rule for alert in alerts], ["success_after_failures", "repeated_failures"])
        self.assertEqual(alerts[0].first_seen, START)

    def test_custom_config_changes_detection(self):
        attempts = [event(0), event(20)]
        self.assertEqual(detect(attempts, DetectionConfig()), ())
        alerts = detect(attempts, DetectionConfig(threshold=2, window_seconds=20))
        self.assertEqual([alert.rule for alert in alerts], ["repeated_failures"])
        self.assertEqual(detect(attempts, DetectionConfig(threshold=2, window_seconds=19)), ())


if __name__ == "__main__":
    unittest.main()
