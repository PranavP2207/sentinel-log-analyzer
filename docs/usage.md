# Sentinel usage guide

An offline security log analyzer for Linux SSH authentication logs, built in Python. Sentinel highlights repeated failures, attempts across multiple usernames, and successful logins following failures. Every alert includes timestamps, the destination host, the source IP, targeted usernames, and source file/line evidence.

**Status:** Initial CLI release. Python 3.10+; no runtime dependencies. Runs on Linux and also analyzes exported logs on Windows or macOS. Local verification so far uses Python 3.11 on Windows; Linux execution has not yet been verified.

## Try it

From this project directory:

```sh
python -m sentinel analyze examples/auth.log --year 2026
```

Use `python3` if that is your Python command on Linux. The synthetic example produces three alerts:

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

Try a clean example and a journal JSON export:

```sh
python -m sentinel analyze examples/clean.log
python -m sentinel analyze examples/journal.jsonl --format json
```

These are fabricated logs using documentation IP addresses.

## Install

Running from the checkout requires no installation. To install the `sentinel` command in a virtual environment on Linux:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
sentinel --version
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. Build an installable wheel with `python -m pip wheel . --no-deps --wheel-dir dist`.

## Analyze Linux logs

For a readable authentication log:

```sh
sentinel analyze /var/log/auth.log --year 2026 --utc-offset=+05:30
sentinel analyze /var/log/secure --threshold 8 --window 10m
```

Read gzip rotations and current logs together when their year assumptions agree:

```sh
sentinel analyze auth.log.2.gz auth.log.1 auth.log --year 2026
```

Provide each record once. Overlapping exports are not deduplicated. The exact same input path is rejected when repeated.

To read the journal as JSON lines, pipe an export from the Linux host into Sentinel. Reading journal entries depends on your existing account permissions:

```sh
journalctl --since today -o json --no-pager | sentinel analyze -
```

For an explicit report file and a status usable in scripts:

```sh
sentinel analyze auth.log --format json --output report.json --fail-on-alert
```

Sentinel reads files or stdin and writes a report. It makes no network requests and does not modify input logs or perform remediation. The output path cannot be an input path or an existing hard link to an input. A report file at another explicitly supplied path is overwritten.

## Detection rules

| Rule | Default condition within 5 minutes | Severity |
| --- | --- | --- |
| `repeated_failures` | At least 5 failed SSH authentication records from one source IP to one host | High |
| `multiple_usernames` | Failures targeting at least 3 distinct usernames from one source IP to one host | Medium |
| `success_after_failures` | An accepted login preceded by at least 5 failures for the same username, source IP, and host | Critical |

These are review indicators. Legitimate mistakes, shared IPs, and automation can produce the same patterns; an alert does not establish compromise. The multiple-username rule identifies a pattern consistent with guessing or spraying, but logs do not reveal whether the same password was tried.

Rules use inclusive sliding windows: an event exactly 300 seconds before the current event is included with the default window. Inputs are sorted by timestamp before detection. Overlapping qualifying failure windows are merged into one alert showing the strongest window: most failures for `repeated_failures`, or most distinct usernames followed by most failures for `multiple_usernames`. Separate windows with no time overlap produce separate alerts. The displayed timestamps/counts describe that selected window, not a total for the entire merged episode.

Success correlation uses the window ending at the accepted login and requires failures with **strictly earlier timestamps**. Equal-timestamp failures cannot establish order and are excluded. Each accepted login clears the prior failures for that account/source/host, so later logins do not repeatedly reuse them.

Evidence contains up to 10 records per alert, retaining the first and last record, including the accepted login when applicable. The full matching event count is preserved; the text report shows how many evidence samples were omitted. JSON includes the full raw text of each sampled record; terminal excerpts are limited to 400 characters and escape control characters.

## Formats and timestamps

Accepted input formats are detected per line:

```text
Nov  1 09:00:00 bastion sshd[42]: Failed password for admin from 203.0.113.24 port 51000 ssh2
2026-11-01T09:00:00+05:30 bastion sshd-session[42]: Accepted publickey for admin from 203.0.113.24 port 51000 ssh2: ...
```

Journal input must contain one JSON object per line, as produced by `journalctl -o json`. Sentinel reads `MESSAGE`, `__REALTIME_TIMESTAMP`, `_HOSTNAME`, and `SYSLOG_IDENTIFIER` (falling back to `_COMM`). A missing journal hostname is scoped to its input source. Binary, null, or repeated-value SSH fields are treated as malformed rather than guessed. The microsecond epoch timestamp is converted exactly to UTC.

The recognized SSH program names are `sshd`, `sshd-session`, and `sshd-auth`. Messages must follow the OpenSSH `Failed METHOD for ... from IP port N ssh2` or `Accepted METHOD ...` shape. Password, public-key, and keyboard-interactive methods are recognized. Separate PAM failure, invalid-user, and disconnect messages are ignored so they do not double-count an OpenSSH authentication record.

Traditional syslog timestamps omit the year and timezone:

- `--year` sets the starting year **for each input**, defaulting to the current UTC year. December-to-January transitions increment the year within that input.
- `--utc-offset` assigns a fixed offset to timestamps lacking a timezone; the default is `+00:00`. Use `--utc-offset=-04:00` for a negative value.
- All report times are UTC. Explicit offsets and journal timestamps override these assumptions.

Keep yearless records in chronological order for year inference. Rotations starting in different years cannot share a single `--year` assumption; concatenate them oldest first into one input with the correct starting year, or use an export with explicit timestamps. DST changes and host-specific timezone differences require explicit timestamps or separate analyses. No locale or host timezone is used to guess missing information.

Format references: [OpenSSH authentication log construction](https://github.com/openssh/openssh-portable/blob/master/auth.c), [OpenSSH process-name changes](https://www.openssh.org/releasenotes.html), and [systemd Journal JSON Format](https://systemd.io/JOURNAL_EXPORT_FORMATS/#journal-json-format).

## Options and exit status

```sh
sentinel analyze --help
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--threshold N` | `5` | Minimum failures for repeated-failure and success-correlation rules; at least 2 |
| `--window DURATION` | `5m` | Positive integer seconds, or a duration such as `30s`, `5m`, `1h` |
| `--spray-threshold N` | `3` | Minimum distinct failed usernames; at least 2 |
| `--year YYYY` | Current UTC year | Starting year of each yearless input |
| `--utc-offset=+HH:MM` | `+00:00` | Fixed offset for timestamps with no timezone |
| `--format text\|json` | `text` | Report format |
| `--output PATH` | stdout | Write report as UTF-8 |
| `--fail-on-alert` | Off | Exit 1 when the report contains alerts |

| Exit code | Meaning |
| --- | --- |
| `0` | Analysis completed; alerts may exist unless `--fail-on-alert` was used |
| `1` | Alerts found with `--fail-on-alert` |
| `2` | Invalid arguments, input/output error, no supported events, or skipped malformed records |
| `130` | Interrupted by the user |

Mixed usable/malformed input still produces a partial report, then exits 2. Up to five malformed-record diagnostics appear in the report, with the full malformed count. Invalid UTF-8 is treated as malformed. Unrelated/unsupported lines and blank lines are counted separately. No supported events produces an explicit “no assessment” result. Exit 2 takes precedence over the alert exit code.

The JSON contract has `schema_version: 1`, a `status` (`ok`, `partial`, or `no_supported_events`), configuration, coverage/outcome counts, and an `alerts` list with evidence. `ok` means processing completed for supported records; it does not promise that the logs contain no threats or that every possible format was analyzed.

## Development and current limits

```sh
python -m unittest discover -s tests -v
```

Tests exercise parsing, exact timestamps, window boundaries, isolated hosts/accounts/IPs, evidence, clean logs, gzip, stdin, malformed records, exit codes, and output protection. A GitHub Actions workflow is provided for Python 3.10/3.13 on Ubuntu and Windows; it has not been run here.

This version is a batch analyzer scoped to SSH. It does not detect general sudo, firewall, kernel, Windows Event Log, full RFC 5424 envelopes, binary journal files, or custom application formats. Unsupported lines are counted but not analyzed. It does not persist state between runs, tail live files, deduplicate overlapping exports, or send notifications.

All parsed events are retained and sorted in memory. Use bounded time ranges for large logs. Rule processing is linear after sorting; this is not a streaming SIEM or a validated detector for every OpenSSH/distribution version.

The four project context files record current implementation status, decisions, requirements, and known issues.
