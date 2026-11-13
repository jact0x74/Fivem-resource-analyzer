# Changelog

## 0.3.0

- Added `--server-cfg` analysis for line-oriented Cfx resource commands and safely bounded nested `exec` includes, including `exec @resource/path` when the resource is in the scan.
- Added a static startup timeline, category expansion, dependency-order suggestions, repeated-`ensure` warnings and safe include diagnostics; runtime behavior is intentionally not emulated.
- Added convar-name heuristics to flag potentially sensitive values used with replicated/public `setr` / `sets`; **configuration values are never included in reports**.
- Added `sv_scriptHookAllowed` review hints.
- Expanded **opt-in** Lua code review to outbound HTTP, FXServer command execution and resource file writes. Findings are review signals, not vulnerability claims.
- Added **opt-in** `--performance-hints` for obvious non-yielding `while true` loops; not a runtime/resmon measurement.
- Rebuilt the self-contained HTML dashboard with offline search, severity filtering, startup timeline, and escaped untrusted content; fixed inline JavaScript does not make network requests.
- Expanded the JSON report schema to `1.3`, adding `startup_order` and `cfg_files_scanned` fields.
- Added a harmless sample server.cfg + nested exec fixture, updated documentation and current GitHub Actions versions.
- Test suite expanded from 40 to **74** unit/integration tests.

## 0.2.1

- Fixed Windows path separators in finding `file` fields for consistent JSON, text and HTML output.
- Added regression tests for manifest and Lua finding paths, plus Windows path serialization.
- Added GitHub Actions CI runs on `windows-latest` as well as Ubuntu for Python 3.10, 3.12 and 3.13.
- Ignored generated root-level reports to reduce accidental commits of local file paths.
- No report schema changes; schema version remains `1.2`.

## 0.2.0

- Added standalone, safely escaped HTML reports with resource inventory and dependency table.
- Added Graphviz DOT dependency map output, including resolved `provide` aliases.
- Added NUI HTML `src` and `href` asset existence and packaging diagnostics.
- Added `--audit-lua`: opt-in heuristics for selected dynamic-evaluation and OS-command calls in declared local Lua files (not a security verdict).
- Extended JSON dependency edge records with `resolved_to` and incremented report schema version to `1.2`.
- Added 19 tests for new behavior, for 38 total tests.
- Expanded documentation with usage, known limitations and reporting examples.

## 0.1.0

- Initial manifest parser, resource discovery and path diagnostics.
- Basic dependency checks and console / JSON reports.
- Automated test suite and GitHub Actions.
