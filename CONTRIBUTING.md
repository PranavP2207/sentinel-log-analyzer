# Contributing to Sentinel

Thanks for helping improve Sentinel. Useful contributions include reproducible bug reports, real-world format coverage using synthetic fixtures, detection tests, documentation, and focused fixes.

## Before starting

Search existing issues and pull requests. For a substantial new rule, dependency, interface, or architecture change, open an issue first so the approach can be discussed. Small fixes and documentation improvements can go straight to a pull request.

Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security vulnerabilities through [SECURITY.md](SECURITY.md), rather than a public bug report.

## Local setup

Fork the repository, clone your fork, and create a branch. Python 3.10+ is required:

```sh
git checkout -b fix/short-description
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
sentinel analyze examples/auth.log --year 2026
```

On Windows, use `python` and activate `.venv\Scripts\Activate.ps1`.

## Code and test expectations

- Keep changes focused and preserve Python 3.10 compatibility.
- Prefer the standard library. Explain the need before adding a runtime dependency.
- For parser or rule changes, add an independently specified regression case that fails without the fix. Include benign input and boundary cases when relevant.
- Keep host, source-IP, username, and timestamp correlations explicit. Avoid counting both PAM and OpenSSH records for one authentication attempt.
- Treat log content as untrusted. Preserve terminal escaping and file-output protections.
- Document changes to CLI behavior, JSON output, thresholds, or assumptions. An incompatible JSON contract needs an explicit schema-version decision.
- Update `CHANGELOG.md` under `Unreleased` for user-visible changes.

Use synthetic logs with documentation IP addresses such as `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`. Remove credentials, tokens, personal data, internal hostnames, and private addresses from submitted examples. Do not attach raw production log exports.

## Pull requests

Explain the concrete problem, the resulting behavior, and how it was tested. Link an issue when one exists. Report skipped or unavailable checks honestly. Linux and Windows CI must pass before a release; maintainers decide whether a change is ready to merge.

## Releases

Maintainers follow [docs/RELEASING.md](docs/RELEASING.md). Publishing a tag builds a GitHub release; it does not upload the package to PyPI.
