# Current state: Sentinel

Last updated: 2026-11-01

## Project and scope

- Project: Sentinel — Security log analyzer.
- Goal: Read system logs and highlight suspicious activity, such as repeated failed login attempts.
- Stage: Initial CLI release implemented and verified locally; ready for use with exported logs.
- Requirements and constraints: See [instructions.md](instructions.md).

## Implemented and verified

- Python package in `sentinel/`: CLI, syslog/journal parser, batch analyzer, three detection rules, and text/JSON reports.
- Inputs: Plain UTF-8 files, gzip files, multiple sources, or stdin. Authentication messages from sshd, sshd-session, and sshd-auth are supported; IPv4/IPv6 addresses are validated.
- Alerts: Repeated failures, multiple targeted usernames, and success following failures, scoped by host/source IP and by username for success correlation. Each alert includes source-line evidence.
- Configurable thresholds, inclusive sliding windows, explicit year/timezone assumptions, input-coverage counts, malformed-record diagnostics, and useful exit statuses.
- Input paths are protected against being used as report output; the hard-link variant is implemented but unverified locally (I-002).
- Local runtime: Python 3.11.7 on Windows.
- `python -m unittest discover -s tests -v`: 36 tests collected, 35 passed, 1 skipped on 2026-11-01. The skipped test requires hard-link creation denied by the sandbox (I-002).
- Four isolated detector mutations were rejected by the regression tests: exclusive boundary, merged hosts, merged usernames, and same-timestamp success correlation.
- Offline wheel build succeeded with `python -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir dist`, using TEMP/TMP inside `.build-tmp/` because the sandbox's default build-temp rename failed.
- Installed the wheel into an isolated temporary target; verified import from that target, console entry point metadata, three expected demo alerts, and exit 1 with `--fail-on-alert`.
- Linux runtime validation: Unverified; WSL listing failed with Wsl/E_ACCESSDENIED (I-001).
- Deployment: None.

## Structure and environment

- Intended technology: Python, Linux, and security fundamentals, per the user.
- Runtime dependencies: None; Python 3.10+ declared in `pyproject.toml`. Packaging uses setuptools.
- Usage: `python -m sentinel analyze examples/auth.log --year 2026` from this directory. The synthetic example produces three alerts; `examples/clean.log` produces none.
- [README.md](README.md) documents installation, Linux usage, rule semantics, timestamps, JSON/exit statuses, and limitations.
- `tests/` contains parser, detector, and subprocess CLI tests; `examples/` contains fabricated syslog and journal fixtures.
- `.github/workflows/tests.yml` defines Ubuntu/Windows tests on Python 3.10/3.13. It has not been run remotely.
- `dist/sentinel_log_analyzer-0.1.0-py3-none-any.whl` is a verified build artifact; build output and temporary directories are ignored by Git.

## Work in progress

- Initial implementation is complete. Community documentation and GitHub publication are in progress under D-006.
- Prepared README, detailed usage guide, MIT license, contributor/conduct/security guides, changelog, issue/PR templates, release notes, package metadata, and a tag-triggered release workflow.
- Limits: SSH only, batch/in-memory processing, no live monitoring or persistent state, and no deduplication of overlapping exports. See README for unsupported formats and yearless-log assumptions.

## Next action

Finish distribution checks, initialize Git, create/push the public GitHub repository, wait for cross-platform CI, then publish v0.1.0 through the tagged release workflow and verify its assets.

## Latest checkpoint

- Delivered the first working CLI, synthetic examples, installable wheel, documentation, tests, and CI definition. Local checks passed subject to the two environment-related validation gaps.
