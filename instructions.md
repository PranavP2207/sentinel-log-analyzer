# Instructions: Sentinel

Last updated: 2026-11-01

## Product goal

Sentinel is a security log analyzer intended to read system logs and highlight suspicious activity, such as repeated failed login attempts.

## Scope and acceptance criteria

- Required capability: Read system logs and highlight suspicious activity, including repeated failed login attempts.
- Current authorized task: Create a new GitHub repository, push the project, prepare community-oriented documentation, and include releases, per the user's 2026-11-01 follow-up.
- First implementation scope selected by the agent: An offline Python CLI for SSH authentication logs, with configurable time windows and thresholds, evidence references, and text/JSON reports. See D-003 in [decisions.md](decisions.md).
- Validation target selected by the agent: Exercise real parsing, time-window detection, and CLI behavior using synthetic fixtures, including clean input and malformed input.
- Initial scope has been delivered; see [current-state.md](current-state.md) for observed checks and remaining platform-validation gaps.
- Publication choices selected by the agent: Public `PranavP2207/sentinel-log-analyzer` repository, MIT licensing, community files, and a `v0.1.0` GitHub release with wheel/source/checksums. See D-006 in [decisions.md](decisions.md).

## Project constraints

- Technology and subject areas supplied by the user: Python, Linux, security fundamentals.
- The user has not specified log formats, thresholds, interface, dependencies, or deployment details; initial choices are recorded as implementation decisions.

## Working conventions

- Use the project-context skill before implementation and maintain the four canonical context files at meaningful checkpoints and handoff, as directed by the user's AGENTS.md instructions.
- Preserve the distinction between planned capabilities and verified implementation.

## Instruction sources

- User's project brief, 2026-10-20: “Sentinel — Security log analyzer”; read system logs and highlight suspicious activity, such as repeated failed login attempts; technology: Python, Linux, security fundamentals.
- User's original scope instruction, 2026-10-20: Save information only; superseded by “start building this” on 2026-11-01.
- User's publication request, 2026-11-01: Create a new repository, push it to GitHub, make a community-recommended README, and include releases.
- User-provided AGENTS.md instructions in this conversation: Maintain project context in the actual app workspace.
