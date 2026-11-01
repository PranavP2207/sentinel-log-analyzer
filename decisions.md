# Decisions: Sentinel

Last updated: 2026-11-01

## Active decisions

### D-001: Retain the brief and defer implementation

- Date: 2026-10-20
- Status: superseded
- Source: Explicit user instruction.
- Decision: Save the project information without building the application.
- Reason: The user requested information capture only.
- Alternatives: Immediate implementation was excluded by the user.
- Consequences: No application code, dependencies, or deployment setup until the user requests further work.
- Superseded by: D-003 on 2026-11-01, following the user's request to start building.

### D-002: Use Python and target Linux

- Date: 2026-10-20
- Status: accepted
- Source: User's technology brief: Python, Linux, security fundamentals.
- Decision: Treat Python and Linux as the intended technology and platform, with security fundamentals informing future detection behavior.
- Reason: These are the technologies and subject areas supplied by the user.
- Alternatives: None evaluated; detailed architecture has not been selected.
- Consequences: Future planning should follow this direction; specific versions and libraries remain undecided.

### D-003: Build an offline Python CLI as the initial release

- Date: 2026-11-01
- Status: accepted
- Source: User authorization to start building; implementation choices made by the agent within that scope.
- Decision: Use Python 3.10+ and its standard library for a CLI. Accept syslog SSH records and journalctl JSON lines from files, gzip files, or stdin. Detect repeated failures, multiple targeted usernames, and success following failures; report evidence in text or JSON.
- Reason: A CLI fits Linux administration and can analyze local exports without adding services or sending logs elsewhere.
- Alternatives: A web dashboard and live monitoring are deferred to keep the first implementation focused on usable analysis.
- Consequences: Analysis is batch-based and keeps parsed events in memory. Timezone and year assumptions for traditional syslog must be explicit. No blocking or remediation is performed.
- Supersedes: D-001.

### D-004: Use explicit, evidence-backed detection semantics

- Date: 2026-11-01
- Status: accepted
- Source: Agent implementation choices within the user's build authorization.
- Decision: Default to 5 failures or 3 distinct failed usernames within an inclusive 300-second window, grouped by destination host and normalized source IP. Success correlation also requires the same username and strictly earlier failures; each success consumes prior failures for that account/source/host. Merge overlapping qualifying failure windows and report the strongest window with up to 10 evidence records.
- Reason: Avoid clock-bucket boundary misses, cross-host/account correlations, duplicate alerts for every qualifying record, and ambiguous same-timestamp ordering.
- Alternatives: Fixed clock buckets, total-file counts, and correlations across accounts would overstate or miss evidence. No automatic deduplication is used because identical-looking records can represent separate attempts.
- Consequences: Counts/timestamps describe a selected qualifying window, not an entire episode. Overlapping input exports can inflate counts. All parsed events are stored and sorted before detection.

### D-005: Make incomplete analysis visible

- Date: 2026-11-01
- Status: accepted
- Source: Agent implementation choices within the user's build authorization.
- Decision: Return a coverage report with status `partial` for malformed records and `no_supported_events` for empty/unsupported-only input, both with exit 2. Normal analysis exits 0; `--fail-on-alert` changes alerting results to exit 1. JSON uses schema version 1.
- Reason: Empty, malformed, or unsupported input must not silently appear to be a clean security assessment.
- Alternatives: Silently skipping all bad input or failing at the first malformed line would hide either coverage gaps or useful valid evidence.
- Consequences: Scripts must handle exit 2 even when a partial report contains alerts. Unrelated/unsupported lines are counted separately; an `ok` report covers only recognized SSH events.

### D-006: Publish a public community repository and tagged releases

- Date: 2026-11-01
- Status: accepted
- Source: Explicit user request to create/push a GitHub repository with a community README and releases; naming, visibility, licensing, and automation are agent choices within that scope.
- Decision: Publish under the authenticated account as `PranavP2207/sentinel-log-analyzer`, with a public repository, MIT license, contributor/security/conduct guides, issue/PR templates, and changelog. Keep the README approachable and move detailed usage into `docs/usage.md`. Publish version `v0.1.0` and automate future version tags with wheel/source/checksum assets.
- Reason: Make the tool easy to discover, try, contribute to, and install from a versioned release.
- Alternatives: A private repository would limit community participation. PyPI publication is deferred; GitHub Releases provides versioned assets without additional package-index credentials.
- Consequences: Source and community files are public. Tag, metadata, and package versions must agree; release notes and successful checks precede publication. Use the account's GitHub noreply address for commits.

## Decision history

D-001 was superseded by D-003 after the user authorized implementation.
