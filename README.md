# Sentinel

**Find suspicious SSH login activity in Linux logs, with evidence you can review.**

[![Tests](https://github.com/PranavP2207/sentinel-log-analyzer/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/PranavP2207/sentinel-log-analyzer/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/PranavP2207/sentinel-log-analyzer)](https://github.com/PranavP2207/sentinel-log-analyzer/releases/latest)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Sentinel is an offline Python command-line tool for analyzing SSH authentication logs. It detects repeated failures, attempts across multiple usernames, and successful logins following failures. Each alert includes the host, source IP, affected usernames, timestamps, and source file/line evidence.

It has **no runtime dependencies**, makes no network requests, and supports plain logs, gzip rotations, stdin, and `journalctl` JSON exports. It is an early release for log review and security learning; alerts are indicators to investigate, not proof of compromise.

[Quick start](#quick-start) · [Installation](#installation) · [Usage guide](docs/usage.md) · [Releases](#releases) · [Contributing](#contributing)

## Features

- Three configurable SSH detection rules using sliding time windows.
- IPv4 and IPv6 support, with correlations separated by host and source IP.
- Evidence samples for every alert, including a successful login when applicable.
- Readable terminal reports and versioned JSON output for scripts.
- Explicit year/timezone assumptions and malformed-input diagnostics.
- Batch analysis of multiple log files without modifying the source logs.

## Quick start

Requires Python 3.10 or newer and Git. No installation is needed to try the examples:

```sh
git clone https://github.com/PranavP2207/sentinel-log-analyzer.git
cd sentinel-log-analyzer
python3 -m sentinel analyze examples/auth.log --year 2026
```

On Windows, use `python` instead of `python3` if needed. The fabricated example produces:

```text
Records: 16 lines | 13 SSH authentication events
Outcomes: 10 failed | 3 accepted

[CRITICAL] Successful SSH login after repeated failures
  admin on bastion, from 203.0.113.24: 6 failures then an accepted login
[HIGH] Repeated SSH authentication failures
  admin on bastion, from 203.0.113.24: 6 failures in 50 seconds
[MEDIUM] SSH failures across multiple usernames
  deploy, root, test on bastion, from 198.51.100.40
```

This is an abbreviated view; the actual report includes source-line evidence and review guidance. Try `examples/clean.log` for input that matches no rules.

## Installation

From the cloned project on Linux or macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
sentinel --version
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install .
sentinel --version
```

You can also download the wheel from [GitHub Releases](https://github.com/PranavP2207/sentinel-log-analyzer/releases/latest) and install the downloaded file in a virtual environment:

```sh
python -m pip install sentinel_log_analyzer-0.1.0-py3-none-any.whl
```

Sentinel is not currently published to PyPI. The source archive is available with each release.

## Usage

```sh
# Analyze a Linux authentication log with an explicit year and offset.
sentinel analyze /var/log/auth.log --year 2026 --utc-offset=+05:30

# Tune the threshold and time window.
sentinel analyze /var/log/secure --threshold 8 --window 10m

# Analyze non-overlapping rotations whose year assumptions agree.
sentinel analyze auth.log.2.gz auth.log.1 auth.log --year 2026

# Read a journal export using your existing journal access permissions.
journalctl --since today -o json --no-pager | sentinel analyze -

# Save JSON and return exit code 1 if alerts are found.
sentinel analyze auth.log --format json --output report.json --fail-on-alert

sentinel analyze --help
```

Traditional syslog omits the year and timezone. `--year` defaults to the current UTC year for each input, and `--utc-offset` defaults to `+00:00`. December-to-January rollover is inferred within each input; keep yearless records in chronological order. Reports use UTC. See the [usage guide](docs/usage.md#formats-and-timestamps) for cross-year rotations and timezone limits.

## Detection rules

| Rule | Default condition within 5 minutes | Severity |
| --- | --- | --- |
| `repeated_failures` | At least 5 failures from one source IP to one host | High |
| `multiple_usernames` | Failures targeting at least 3 distinct usernames from one source IP to one host | Medium |
| `success_after_failures` | An accepted login after at least 5 failures for the same username, source IP, and host | Critical |

The window is inclusive. Success correlation requires failures with strictly earlier timestamps. Overlapping qualifying failure windows are merged, and the report shows the strongest window with up to 10 evidence records. Counts describe that selected window, not the whole episode. Full [rule semantics](docs/usage.md#detection-rules) are documented.

| Exit code | Meaning |
| --- | --- |
| `0` | Analysis completed; alerts may exist unless `--fail-on-alert` was used |
| `1` | Alerts found with `--fail-on-alert` |
| `2` | Invalid arguments, I/O failure, malformed records, or no supported events |
| `130` | Interrupted by the user |

Malformed input can produce a partial report and exit 2, even if alerts exist. An empty or unsupported-only file returns an explicit “no assessment” result. JSON reports use `schema_version: 1`; see [options and output](docs/usage.md#options-and-exit-status).

## Scope and limitations

Sentinel currently analyzes OpenSSH `Failed` and `Accepted` authentication messages in traditional syslog, ISO timestamp syslog, or journal JSON lines. Recognized program names are `sshd`, `sshd-session`, and `sshd-auth`. Separate PAM and disconnect records are ignored to avoid counting an attempt twice.

This version keeps parsed events in memory and sorts them before analysis. Use bounded exports for large logs. Overlapping exports are not deduplicated. General sudo/firewall/kernel logs, Windows Event Logs, full RFC 5424 envelopes, and binary journal files are outside the current scope. There is no live monitoring, persistent state, blocking, or notification service. See the [detailed guide](docs/usage.md#development-and-current-limits).

## Releases

Download versioned wheels, source distributions, and `SHA256SUMS` from [GitHub Releases](https://github.com/PranavP2207/sentinel-log-analyzer/releases). See [CHANGELOG.md](CHANGELOG.md) for notable changes and [release notes for v0.1.0](docs/releases/v0.1.0.md) for the initial release.

To check a downloaded wheel on Linux, place it next to `SHA256SUMS`:

```sh
sha256sum --ignore-missing --check SHA256SUMS
```

Checksums detect download corruption; they do not establish publisher identity. The [release guide](docs/RELEASING.md) describes how tags are tested, packaged, and published. There is no automatic PyPI publishing.

## Contributing

Bug reports, parser fixtures, clearer documentation, and detection improvements are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and use the [issue templates](https://github.com/PranavP2207/sentinel-log-analyzer/issues/new/choose) for bugs or feature requests. Use fabricated or redacted logs; never include credentials or private production logs.

To run the test suite:

```sh
python -m unittest discover -s tests -v
```

CI checks Python 3.10 and 3.13 on Ubuntu and Windows, including an installed-command smoke test. Development uses Python's standard `unittest` library; no test framework dependency is required. For version-specific results, check the [Actions runs](https://github.com/PranavP2207/sentinel-log-analyzer/actions/workflows/tests.yml) and release notes.

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Ordinary usage questions can be opened as [issues](https://github.com/PranavP2207/sentinel-log-analyzer/issues).

## License

Sentinel is available under the [MIT License](LICENSE).
