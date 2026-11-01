# Current state: Sentinel

Last updated: 2026-11-01

## Project and scope

- Project: Sentinel — Security log analyzer.
- Goal: Read system logs and highlight suspicious activity, such as repeated failed login attempts.
- Stage: Initial CLI, public GitHub repository, community documentation, and v0.1.0 release published and verified.
- Requirements and constraints: See [instructions.md](instructions.md).

## Implemented and verified

- Python package in `sentinel/`: CLI, syslog/journal parser, batch analyzer, three detection rules, and text/JSON reports.
- Inputs: Plain UTF-8 files, gzip files, multiple sources, or stdin. Authentication messages from sshd, sshd-session, and sshd-auth are supported; IPv4/IPv6 addresses are validated.
- Alerts: Repeated failures, multiple targeted usernames, and success following failures, scoped by host/source IP and by username for success correlation. Each alert includes source-line evidence.
- Configurable thresholds, inclusive sliding windows, explicit year/timezone assumptions, input-coverage counts, malformed-record diagnostics, and useful exit statuses.
- Input paths are protected against being used as report output; the hard-link branch passed in Ubuntu CI (I-002 resolved).
- Local runtime: Python 3.11.7 on Windows.
- `python -m unittest discover -s tests -v`: 36 tests collected, 35 passed, 1 skipped on 2026-11-01. The skipped test requires hard-link creation denied by the sandbox (I-002).
- Four isolated detector mutations were rejected by the regression tests: exclusive boundary, merged hosts, merged usernames, and same-timestamp success correlation.
- Offline wheel build succeeded with `python -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir dist`, using TEMP/TMP inside `.build-tmp/` because the sandbox's default build-temp rename failed.
- Installed the wheel into an isolated temporary target; verified import from that target, console entry point metadata, three expected demo alerts, and exit 1 with `--fail-on-alert`.
- Cross-platform validation: All four jobs passed in [GitHub Actions run 41292580916](https://github.com/PranavP2207/sentinel-log-analyzer/actions/runs/41292580916), on Ubuntu/Windows with Python 3.10/3.13. The Ubuntu job passed all 36 tests with no skips and the installed CLI smoke test (I-001 and I-002 resolved).
- Distribution: Public [GitHub repository](https://github.com/PranavP2207/sentinel-log-analyzer) with `main` tracking `origin/main`; [v0.1.0 release](https://github.com/PranavP2207/sentinel-log-analyzer/releases/tag/v0.1.0) published from tested commit `2ce1703a3b2b98d2616b2810954f84287e03aa9f`.
- Final release-preparation CI [run 41292855580](https://github.com/PranavP2207/sentinel-log-analyzer/actions/runs/41292855580) passed all four Ubuntu/Windows Python 3.10/3.13 jobs with the current official action versions.
- Release workflow [run 41292979163](https://github.com/PranavP2207/sentinel-log-analyzer/actions/runs/41292979163) passed on Ubuntu, verified version agreement, ran tests, built/installed the wheel, exercised the CLI, and published the release.
- Published assets: `sentinel_log_analyzer-0.1.0-py3-none-any.whl`, `sentinel_log_analyzer-0.1.0.tar.gz`, and `SHA256SUMS`. Downloaded assets into `.build-tmp/published-v0.1.0/` and verified both package hashes against the published checksums.
- Local wheel and source archive built with isolated build tooling in `.build-tmp/release-tools`; verified MIT SPDX metadata/license and inclusion of examples, tests, and documentation.
- GitHub community profile reports 100% health; MIT licensing and private vulnerability reporting are enabled.

## Structure and environment

- Intended technology: Python, Linux, and security fundamentals, per the user.
- Runtime dependencies: None; Python 3.10+ declared in `pyproject.toml`. Packaging uses setuptools.
- Usage: `python -m sentinel analyze examples/auth.log --year 2026` from this directory. The synthetic example produces three alerts; `examples/clean.log` produces none.
- [README.md](README.md) documents installation, Linux usage, rule semantics, timestamps, JSON/exit statuses, and limitations.
- `tests/` contains parser, detector, and subprocess CLI tests; `examples/` contains fabricated syslog and journal fixtures.
- `.github/workflows/tests.yml` tests Ubuntu/Windows on Python 3.10/3.13. `.github/workflows/release.yml` tests/builds/publishes assets on version tags. Official action versions were updated after the first run reported deprecated Node 20 action versions.
- `dist/sentinel_log_analyzer-0.1.0-py3-none-any.whl` is a verified build artifact; build output and temporary directories are ignored by Git.

## Work in progress

- Initial implementation, community documentation, and repository/release publication under D-006 are complete. No active implementation work remains.
- Prepared README, detailed usage guide, MIT license, contributor/conduct/security guides, changelog, issue/PR templates, release notes, package metadata, and a tag-triggered release workflow.
- Limits: SSH only, batch/in-memory processing, no live monitoring or persistent state, and no deduplication of overlapping exports. See README for unsupported formats and yearless-log assumptions.

## Next action

Collect feedback or analyze a representative non-overlapping log export when requested. For future releases, follow `docs/RELEASING.md`; keep metadata/package/tag versions aligned and add versioned release notes before pushing a tag.

## Latest checkpoint

- Published the public repository and v0.1.0, passed cross-platform and release checks, verified downloadable package checksums, and closed the initial Linux/hard-link verification gaps. GitHub reports 100% community-profile health; private vulnerability reporting is enabled.
