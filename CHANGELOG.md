# Changelog

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
