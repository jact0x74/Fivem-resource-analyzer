# Viento Resource Analyzer

A lightweight, **read-only** static analyzer for [FiveM/Cfx.re](https://docs.fivem.net/docs/scripting-reference/resource-manifest/) resource manifests. Run it against a single resource folder or an entire `resources/` tree, including `[category]` folders.

**Status:** initial public-development release (`v0.1.0`). Python 3.10+, no runtime dependencies. Windows, Linux and macOS.

## Features

- Locates `fxmanifest.lua` and deprecated `__resource.lua` files.
- Reports missing client/server/shared script references, files, `ui_page`, `loadscreen`, and data-file paths.
- Supports common literal Lua declarations, multi-line tables, and filesystem globs such as `client/*.lua` and `**/*.lua`.
- Detects duplicate resource names, self-dependencies, and dependency cycles within scanned resources.
- Warns when dependencies are not present **in the scanned tree** (not proof that they're absent on the server).
- Detects locally hosted NUI pages missing from the `files`/`file` packfile list.
- Warns when `fx_version` or `game`/`games` is missing and notes deprecated `lua54` declarations.
- Human-readable or JSON reporting for CI workflows; exit code can enforce policy.

The analyzer **does not execute Lua, JavaScript or any resource file**, nor does it modify files.

## Quick start — Windows (no installation)

1. Install [Python](https://www.python.org/downloads/) 3.10 or later.
2. Download and extract this repository.
3. Open PowerShell in the extracted directory.
4. Run:

```powershell
py vra.py ".\examples\demo_resources"
py vra.py "C:\your-server\resources"
py vra.py "C:\your-server\resources" --format json --output "report.json"
```

The included demonstration intentionally produces **2 findings** (missing script and unpackaged NUI page). It doesn't need a FiveM server to run.

### Linux / macOS

```bash
python3 vra.py ./examples/demo_resources
python3 vra.py /srv/fivem/resources --format json --output report.json
```

### Optional: install as a CLI

```bash
python -m pip install -e .
vra /srv/fivem/resources
```

## Output example

```text
Viento Resource Analyzer | scanned 2 resources
Errors: 1 | Warnings: 1 | Info: 0

[ERROR] PATH_NOT_FOUND | [local]/viento_example/fxmanifest.lua:5 | ...
[WARNING] UI_NOT_PACKED | [local]/viento_example/fxmanifest.lua:10 | ...
```

### CLI flags

| Flag | Purpose |
| --- | --- |
| `--format text` | Readable report (default) |
| `--format json` | Machine-readable report |
| `--output PATH` | Write report to a file |
| `--strict` | Exit nonzero on warnings too |
| `--available ox_lib` | Treat a named external resource as available; repeatable |
| `--help` | List command-line options |

Exit codes: **0** no errors (and no warnings with `--strict`), **1** analysis findings exceeding policy, **2** invalid arguments or a filesystem/scan error.

## What this tool cannot guarantee

- `fxmanifest.lua` is **executable Lua**. We deliberately parse common static declarations rather than interpret Lua. Dynamic/computed metadata is flagged for manual review and may not be fully resolved.
- We **do not** assess runtime performance (resmon), exploitability, malicious intent, or network security. The results are manifest hygiene checks, not a security audit.
- File globbing is host filesystem dependent and can differ from exact Cfx.re packfile interpretation.
- Dependency warnings are scoped to the scanned folder, which may omit built-in or separately installed resources. Use `--available` when needed.
- A clean report is not proof that a resource runs correctly.

## Development

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the test suite on Python 3.10, 3.12 and 3.13.

## Roadmap

- Improved Lua static parser coverage, with fixture-based compatibility tests.
- Dependency inventory from `server.cfg` and start-order diagnostics.
- Optional HTML report and interactive, local-only viewer.
- Opt-in code safety heuristics with clearly documented false-positive limits.

Suggestions and reproducible bug reports are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## References

- [Cfx.re Resource Manifest documentation](https://docs.fivem.net/docs/scripting-reference/resource-manifest/)
- [Cfx.re Introduction to Resources](https://docs.fivem.net/docs/scripting-manual/introduction/introduction-to-resources/)

## License

MIT — see [LICENSE](LICENSE).

> Independent community project. Not affiliated with, endorsed by or maintained by Cfx.re, FiveM, Rockstar Games or Anthropic.
