# FiveM Resource Analyzer v0.3.0

The next release of our free, read-only FiveM/Cfx.re resource analysis tool.

## What's new

- **server.cfg analysis:** Inspect `start`, `ensure`, `stop`, `restart`, category starts and safe nested `exec` includes (including `@resource/...`).
- **Startup timeline:** Review explicit resource order and possible dependency order mistakes, including `provide` aliases.
- **Configuration review:** Warn about potentially exposed secrets using `setr` or `sets` and enabled `sv_scriptHookAllowed`. No configuration values are written to reports.
- **Lua review:** More optional static signals for outbound HTTP requests, server command execution and resource file writes.
- **Performance hints:** Optional detection of simple Lua loops without obvious yielding; not a resmon measurement.
- **Interactive HTML dashboard:** Offline search, severity filtering, startup sequence, dependencies and resource inventory.
- **Testing:** 74 automated tests, with CI configured for Python 3.10/3.12/3.13 on Windows and Ubuntu.

## Example

```powershell
py vra.py ".\examples\demo_resources" --server-cfg ".\examples\demo_server\server.cfg" --format html --output report.html
Start-Process .\report.html
```

The sample deliberately contains issues for demonstration. The analyzer does not execute FiveM scripts or server configurations. Static signals require manual verification. See README.md for complete documentation and limitations.
