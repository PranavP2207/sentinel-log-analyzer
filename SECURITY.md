# Security policy

## Supported versions

Sentinel is an early-stage project. Security fixes target the latest published release; older releases do not have a separate maintenance branch.

| Version | Security fixes |
| --- | --- |
| Latest published release | Eligible for fixes |
| Older releases | Upgrade to the latest release |

## Reporting a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/PranavP2207/sentinel-log-analyzer/security/advisories/new). Do not open a public issue with an exploit, secret, private log, or sensitive system detail.

Include the affected version, Python/OS versions, impact, reproduction steps, and a minimal synthetic log example when possible. Avoid sending credentials or full production logs. A fix or response timeline is not guaranteed.

If the private form is unavailable, use the contact options on the [maintainer's profile](https://github.com/PranavP2207) to ask for a private reporting channel, without sharing vulnerability details publicly. GitHub account or platform security problems should be reported directly to GitHub.

## Scope

Relevant issues include unsafe handling of log data, terminal-control injection, unintended file overwrites, and reproducible detection errors with security impact. A rule alert is an investigative signal, not a guarantee that malicious activity will be detected. General format requests and ordinary parser bugs can use public issues with sanitized fixtures.
