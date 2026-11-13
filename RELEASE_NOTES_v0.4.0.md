# FiveM Resource Analyzer v0.4.0

This release expands reporting and opt-in source review while keeping the tool offline, read-only and Python-standard-library-only.

## What's new

- **CSV export** with spreadsheet formula-injection protection (`--format csv`).
- **Path privacy option** (`--redact-root`) to hide the absolute scan root in generated reports.
- **Lua review updates** for `loadfile()`, `dofile()`, awaited outbound HTTP calls, and plaintext literal HTTP URLs (URL contents are not recorded in findings).
- **Performance hints** for simple non-yielding `repeat` loops and logging inside simple infinite loops.
- **Offline HTML improvements:** resource-level filter, reset controls, finding breakdown per resource, more consistent table widths.
- **Contribution templates** for reproducible, sanitized bug reports, feature suggestions and pull requests.
- **96 automated unit/integration tests**, with Windows and Ubuntu test configurations retained.

## Quick start

```bash
python vra.py ./examples/demo_resources --format html --output report.html --redact-root
python vra.py ./examples/demo_resources --format csv --output findings.csv
python vra.py ./examples/demo_resources --audit-lua --performance-hints
```

**Note:** The demo includes intentionally invalid paths and may exit with status `1`. Code is never executed. Static findings are not proof of a security vulnerability or runtime performance issue. Review locally generated reports for private metadata before sharing.

## Compatibility

Python 3.10+, Windows / Linux / macOS. JSON schema remains `1.3`; there are no new third-party runtime dependencies.
