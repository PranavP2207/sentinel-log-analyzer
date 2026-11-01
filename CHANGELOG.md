# Changelog

Notable user-visible changes are recorded here. Released versions correspond to Git tags and GitHub Releases.

## Unreleased

No unreleased changes.

## 0.1.0 — 2026-11-01

### Added

- Offline Python CLI with no runtime dependencies.
- SSH authentication parsing for traditional syslog, ISO timestamp syslog, and journal JSON lines, including sshd, sshd-session, and sshd-auth records.
- Plain/gzip files, multiple inputs, and stdin, with IPv4/IPv6 validation.
- Sliding-window detection of repeated failures, multiple targeted usernames, and successful logins following failures.
- Host/source/account isolation, configurable thresholds, UTC reports, and explicit year/offset assumptions.
- Source-line evidence, text and schema-versioned JSON reports, input diagnostics, and script-friendly exit statuses.
- Synthetic examples, parser/detector/CLI regression tests, cross-platform CI, and tagged release automation.
- MIT license, contributor and security guidance, code of conduct, issue templates, and release notes.

### Known limits

- Batch processing retains parsed events in memory.
- Overlapping inputs are not deduplicated; yearless records require chronological order and appropriate year/offset assumptions.
- SSH scope only; no live monitoring, persistent state, automatic remediation, or PyPI publication.
