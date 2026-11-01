# Known issues: Sentinel

Last updated: 2026-11-01

## Active issues

No confirmed application defects remain after local validation. The following environment-related verification gaps remain open.

### I-001: Linux execution has not been verified

- Status: open
- Impact/severity: Validation gap; Linux is the intended platform but local execution was on Windows with Python 3.11.7 only.
- First observed: 2026-11-01
- Evidence: `wsl --list --quiet` returned `Wsl/E_ACCESSDENIED`. The local test suite passed except for I-002.
- Expected: Verify parsing, CLI, packaging, and tests on Linux with supported Python versions.
- Actual: Linux execution is unavailable in this environment. The provided Ubuntu/Windows CI definition has not run remotely.
- Cause: Confirmed local WSL access restriction; no Linux application failure has been observed.
- Workaround: Use the tool on exported logs locally; run the suite on an accessible Linux host or GitHub Actions.
- Next action: Run `python -m unittest discover -s tests -v` and the installed CLI example on Linux.

### I-002: Hard-link output-protection test skipped locally

- Status: open
- Impact/severity: Low; one output-protection branch is implemented but not validated in this sandbox.
- First observed: 2026-11-01
- Evidence: `os.link` in the CLI regression test returned `PermissionError: [WinError 5] Access is denied`. The test explicitly skips when the environment cannot create hard links. Direct same-path output protection passed.
- Expected: A report output that is a hard link to an input must be rejected without changing that input.
- Actual: The fixture cannot create a hard link here, so that assertion cannot execute locally.
- Cause: Confirmed environment restriction on hard-link creation; application behavior is unverified for this case.
- Workaround: Use a distinct report output path; direct input/output equality is validated.
- Next action: Run `test_output_cannot_overwrite_input_via_hardlink` on a filesystem that permits hard links, including the provided Linux CI job.

## Resolved issues

None recorded.
