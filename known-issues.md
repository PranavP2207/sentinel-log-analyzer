# Known issues: Sentinel

Last updated: 2026-11-01

## Active issues

No confirmed application defects or open verification gaps are recorded. macOS has not been tested; Ubuntu and Windows are covered by CI.

## Resolved issues

### I-001: Linux execution has not been verified

- Status: resolved
- Impact/severity: Initial Linux validation gap, now closed by Ubuntu CI.
- First observed: 2026-11-01
- Evidence: `wsl --list --quiet` returned `Wsl/E_ACCESSDENIED`. The local test suite passed except for I-002.
- Expected: Verify parsing, CLI, packaging, and tests on Linux with supported Python versions.
- Actual: Local WSL remains inaccessible, but GitHub's Ubuntu jobs passed tests and the installed-command smoke test on Python 3.10 and 3.13.
- Cause: Confirmed local WSL access restriction; no Linux application failure has been observed.
- Workaround: Use GitHub Actions for Linux validation when local WSL is unavailable.
- Resolution: [Run 41292580916](https://github.com/PranavP2207/sentinel-log-analyzer/actions/runs/41292580916) passed all four Ubuntu/Windows jobs on 2026-11-01; Ubuntu passed all 36 tests and the installed CLI demo.
- Next action: Keep the Linux CI checks passing for future changes.

### I-002: Hard-link output-protection test skipped locally

- Status: resolved
- Impact/severity: Low; a branch was unavailable to validate in the local sandbox, now verified in Ubuntu CI.
- First observed: 2026-11-01
- Evidence: `os.link` in the CLI regression test returned `PermissionError: [WinError 5] Access is denied`. The test explicitly skips when the environment cannot create hard links. Direct same-path output protection passed.
- Expected: A report output that is a hard link to an input must be rejected without changing that input.
- Actual: The fixture cannot create a hard link locally, but `test_output_cannot_overwrite_input_via_hardlink` executed and passed in Ubuntu CI.
- Cause: Confirmed local restriction on hard-link creation.
- Workaround: Use a distinct report output path; direct input/output equality is validated.
- Resolution: Ubuntu Python 3.10 job 124806698933 in [run 41292580916](https://github.com/PranavP2207/sentinel-log-analyzer/actions/runs/41292580916) explicitly reported the hard-link test as `ok` on 2026-11-01.
- Next action: Retain this check in CI; local permission-related skips remain explicit.
