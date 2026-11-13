# FiveM Resource Analyzer

[![Python tests](https://github.com/jact0x74/Fivem-resource-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/jact0x74/Fivem-resource-analyzer/actions/workflows/tests.yml)

A **read-only, dependency-free** static analyzer for [FiveM / Cfx.re resource manifests](https://docs.fivem.net/docs/scripting-reference/resource-manifest/). Scan a resource folder or a complete `resources/` directory, including `[category]` directories. No running FiveM server required.

**Current version:** `v0.2.0` · Python 3.10+ · Windows, Linux, macOS · MIT licensed.

> Independent community project. Not affiliated with or endorsed by Cfx.re, FiveM, Rockstar Games or Anthropic.

## What it checks

- Missing paths in client/server/shared script declarations, `files`, `ui_page`, `loadscreen`, and `data_file` declarations.
- Manifest metadata such as `fx_version` and `game`/`games`, alongside legacy `__resource.lua` warnings.
- Duplicate resource names, missing-in-scan dependencies, self-dependencies, dependency cycles, and `provide` aliases.
- Whether local `ui_page` files and HTML-referenced scripts, stylesheets, and images are present and included in `files`/`file` packfiles.
- **Opt-in** Lua call heuristics for `loadstring(...)`, `load(...)`, `os.execute(...)`, and `io.popen(...)` in declared local `.lua` files.
- Self-contained **HTML report**, JSON report for automation, and **Graphviz DOT** dependency graph output.

All checks are **static**. The analyzer does not execute Lua, JavaScript, or resource files; it does not modify the source being scanned.

## Quick start (Windows, no installation)

1. Install [Python 3.10+](https://www.python.org/downloads/).
2. Download the repository's ZIP archive and extract it.
3. Open **PowerShell** in the extracted project directory.
4. Run:

```powershell
py vra.py ".\examples\demo_resources"
```

The demo intentionally includes one missing script and one unpackaged UI page so you can see example findings. An exit code of `1` is expected for this demo.

Scan your FiveM server's `resources` directory (read-only):

```powershell
py vra.py "C:\path\to\resources"
```

### New in v0.2.0: HTML report

```powershell
py vra.py ".\examples\demo_resources" --format html --output report.html
Start-Process .\report.html
```

You can open `report.html` locally without internet. It includes resource counts, findings, dependency details, and a scanned-resource inventory. Input text is HTML-escaped. Reports contain local file paths; review them before sharing.

### New in v0.2.0: dependency graph

```powershell
py vra.py "C:\path\to\resources" --format dot --output dependencies.dot
```

To render the DOT graph as an image, you may install [Graphviz](https://graphviz.org/) separately and run:

```powershell
dot -Tpng dependencies.dot -o dependencies.png
```

No Graphviz installation is required to **generate** the `.dot` file. Edges referring to missing or externally declared resources are dashed. A `provide` alias is resolved to its actual resource where known.

### New in v0.2.0: optional Lua call review

```powershell
py vra.py "C:\path\to\resources" --audit-lua
py vra.py "C:\path\to\resources" --audit-lua --format html --output audit.html
```

The Lua check examines declared **local** `.lua` scripts up to 2 MiB each. It excludes strings and comments in common Lua syntax. The detections are **review signals only**, not proof of malicious behavior or an exploitable vulnerability. The check is **off by default** to minimize false alarms.

### JSON output and CI

```powershell
py vra.py "C:\path\to\resources" --format json --output report.json
py vra.py "C:\path\to\resources" --strict
```

The JSON report includes `schema_version` (`1.2` in this release), summary counts, findings and `dependency_edges`. Edges may include `resolved_to` for declared local or provided dependencies.

### Linux / macOS

```bash
python3 vra.py ./examples/demo_resources --format html --output report.html
python3 vra.py /srv/fivem/resources --audit-lua
```

### Optional CLI installation

```bash
python -m pip install -e .
fivem-analyzer ./examples/demo_resources
# The short command "vra" works too.
```

## Command-line options

| Flag | Function |
| --- | --- |
| `--format text` | Terminal report (default) |
| `--format json` | Machine-readable JSON report |
| `--format html` | Standalone HTML report (no remote assets or JavaScript) |
| `--format dot` | Graphviz dependency graph |
| `--output PATH` | Write to the given file |
| `--audit-lua` | Opt-in Lua source call review |
| `--available RESOURCE` | Ignore absent-in-scan warning for known external dependency; repeatable |
| `--strict` | Fail on warnings as well as errors |
| `--version` | Print program version |
| `--help` | Show command reference |

**Exit codes:** `0` no policy failures, `1` findings exceeding policy, `2` invalid path or scanning / output error. A warning does not fail unless `--strict` is set.

## Limitations and safety

- `fxmanifest.lua` is executable Lua. To be safe, the analyzer parses **common literal declarations only** and never evaluates expressions. Dynamic metadata may be skipped and reported for manual review.
- Dependency presence is relative to the folder you scan. FiveM built-ins or resources located elsewhere can legitimately be reported as missing. Use `--available RESOURCE` to acknowledge these.
- HTML asset inspection currently covers **literal `src` and stylesheet/icon/preload `href` references in HTML**, not assets dynamically loaded by JavaScript or referenced inside CSS.
- File globs are matched with the local host's filesystem and may differ from all FiveM packfile behaviors.
- Lua findings are conservative **heuristics**; they do not establish exploitability, safety, or malware presence. No performance / resmon data, runtime behavior, or network traffic is evaluated.
- Do not publicly upload private scripts, credentials, access tokens or unreviewed audit reports.

## Development and contributions

Run tests:

```bash
python -m unittest discover -s tests -v
```

The test suite contains **38 tests** at release time. GitHub Actions runs tests on Python 3.10, 3.12, and 3.13.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md). Bugs and realistic test fixtures are welcome.

## Official FiveM references

- [Resource manifest](https://docs.fivem.net/docs/scripting-reference/resource-manifest/)
- [Introduction to resources](https://docs.fivem.net/docs/scripting-manual/introduction/introduction-to-resources/)
- [Fullscreen NUI](https://docs.fivem.net/docs/scripting-manual/nui-development/full-screen-nui/)

**License:** MIT — [LICENSE](LICENSE).
