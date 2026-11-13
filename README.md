# FiveM Resource Analyzer

[![Python tests](https://github.com/jact0x74/Fivem-resource-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/jact0x74/Fivem-resource-analyzer/actions/workflows/tests.yml)

An independent **read-only, dependency-free Python static analyzer** for FiveM/Cfx.re server resources and (optionally) `server.cfg`. Scan one resource or an entire `resources/` tree, including `[category]` directories, without running FXServer.

**Version:** `v0.3.0` · **Python:** 3.10+ · **Platforms:** Windows / Linux / macOS · **License:** MIT.

> Independent community project; not affiliated with or endorsed by Cfx.re, FiveM, Rockstar Games or Anthropic.

## Features

| Area | Included checks |
| --- | --- |
| Resource manifests | Missing referenced files, missing `fx_version` / `game`, legacy manifests, duplicate names, unsupported dynamic declarations |
| Dependencies | Missing-in-scan resources, `provide` aliases, self-dependencies, cycles; Graphviz DOT export |
| NUI | Local page / HTML asset existence and `files` packfile inclusion |
| `server.cfg` (v0.3.0) | `start`, `ensure`, `stop`, `restart`, category expansion, nested `exec` and `exec @resource/...` |
| Startup diagnostics (v0.3.0) | Apparent dependency ordering, duplicate `ensure`, missing / cyclic config includes, unknown resources |
| Config review (v0.3.0) | Heuristics for publicly replicated sensitive convar **names**, and enabled `sv_scriptHookAllowed` (no values are reported) |
| Lua security review | **Opt-in** flags for dynamic execution, OS commands, outbound HTTP calls, server command execution and resource writes |
| Lua performance review (v0.3.0) | **Opt-in** simple `while true do ... end` constructs without visible `Wait`/`Citizen.Wait` (review hint only) |
| Reports | Terminal, JSON, Graphviz DOT, searchable and severity-filterable standalone HTML dashboard |

All checks are **static and heuristic**. They cannot prove exploitability, correct FXServer runtime behavior, server security, or actual CPU/resmon performance.

## Quick start (Windows PowerShell)

Install [Python 3.10+](https://www.python.org/downloads/), download this repository as ZIP, extract it, and open PowerShell in the project folder.

```powershell
py vra.py ".\examples\demo_resources"
```

The demo intentionally references an absent script and an unpackaged UI page. An exit code of **1 is expected** because the demo contains an error.

### New: inspect `server.cfg` and startup order

```powershell
py vra.py ".\examples\demo_resources" --server-cfg ".\examples\demo_server\server.cfg"
```

The example config uses a nested `exec`, starts `viento_example` before its `sample_utils` dependency (an intentional `CFG_DEP_ORDER` warning), and then starts `[standalone]`.

For a real FiveM server, pass the server's **resources directory** plus its **server.cfg** path. The analyzer will not connect to, start, or modify the server:

```powershell
py vra.py "D:\FXServer\server-data\resources" --server-cfg "D:\FXServer\server-data\server.cfg" --format html --output report.html
Start-Process .\report.html
```

The above paths are examples; change them to match your machine.

### Security and performance review (opt-in)

```powershell
py vra.py ".\examples\demo_resources" --audit-lua --performance-hints --format html --output audit.html
```

- `--audit-lua` flags function calls for **manual security review**, **not** known vulnerabilities. Legitimate resources often use the flagged functions.
- `--performance-hints` looks for a limited set of trivially non-yielding loops. It **does not measure resmon**, detect all loop problems, or identify real CPU usage.
- Files, manifests and config declarations are **never executed**. Only local files are read.

### Standalone HTML report (v0.3.0)

```powershell
py vra.py ".\examples\demo_resources" --server-cfg ".\examples\demo_server\server.cfg" --format html --output report.html
Start-Process .\report.html
```

Filter findings by severity, search resources/rule names/paths, inspect dependencies, and review the static startup timeline. The dashboard contains a small inline JavaScript filter (no external libraries or network requests). All scanned content is HTML-escaped; the script never executes or interpolates the scanned content. **Review local file paths in the report before sharing.**

### Dependency graph

```powershell
py vra.py ".\examples\demo_resources" --format dot --output dependencies.dot
```

To render the DOT file visually, install [Graphviz](https://graphviz.org/) (optional) and run `dot -Tpng dependencies.dot -o dependencies.png`.

### JSON / CI integration

```powershell
py vra.py ".\examples\demo_resources" --server-cfg ".\examples\demo_server\server.cfg" --format json --output report.json
py vra.py ".\examples\demo_resources" --strict
```

JSON `schema_version` is **`1.3`** and includes `startup_order` and `cfg_files_scanned` alongside existing fields.

### Linux / macOS

```bash
python3 vra.py ./examples/demo_resources --server-cfg ./examples/demo_server/server.cfg --format html --output report.html
```

### Optional editable installation

```bash
python -m pip install -e .
fivem-analyzer ./examples/demo_resources
# Short command: vra ./examples/demo_resources
```

## CLI reference

| Argument | Meaning |
| --- | --- |
| `path` | Resource directory or `resources/` root to scan |
| `--server-cfg FILE` | Read a server config file and statically expand supported nested `exec` commands |
| `--audit-lua` | Review declared local Lua scripts for selected calls (opt-in) |
| `--performance-hints` | Review simple possible non-yielding loops (opt-in) |
| `--format text\|json\|html\|dot` | Output format; text is default |
| `--output FILE` | Write output to a file instead of stdout |
| `--available RESOURCE` | Mark an externally provided dependency/resource as known; repeatable |
| `--strict` | Return failure on warnings as well as errors |
| `--version` / `--help` | Print version / CLI help |

**Exit status:** 0 = no policy failure; 1 = errors or (with `--strict`) warnings; 2 = invalid input/output or read failure. GitHub tests exercise Windows and Ubuntu under Python 3.10, 3.12 and 3.13.

## Important limitations

- **No live server integration:** Order analysis describes only explicit commands in the inspected config stream. FXServer can start dependencies automatically, use additional runtime commands and other resources; order diagnostics are **hints** rather than proof of broken startup. Category expansion approximates server behavior from the scanned directory structure.
- **Conservative config parser:** Reads plain, line-oriented `start`, `ensure`, `stop`, `restart`, `exec`, `set`, `setr`, `sets`, and `sv_scriptHookAllowed`; it does not emulate variable substitution, conditional behavior, arbitrary commands or FiveM's complete config interpreter. Includes use paths relative to the server-data directory, with `@resource/path` supported when the resource is in the scan. Unknown includes and path traversal are not followed. Include depth/count/size are bounded.
- **Config privacy:** Values of `set`, `setr` and `sets` are not stored in reports. The analyzer **still reads the files locally** to inspect commands. Do not publish real `server.cfg`, tokens, or sensitive local reports. If credentials occur inside filenames or unrelated manifest fields, those may appear as text.
- **Manifest safety:** `fxmanifest.lua` is executable Lua; this program parses common literal declarations only, and never executes expressions. Dynamic metadata may be skipped.
- **Lua audit limits:** Only manifest-declared local `.lua` files up to 2 MiB are inspected. Detection does not cover all malicious code or all performance problems, and may flag harmless patterns.
- **Packfile hints:** Local filesystem globbing can differ from actual FXServer packfile rules. HTML asset checking covers literal HTML references, not dynamically loaded JavaScript/CSS assets.
- **Read-only:** The scan does not edit resources or configuration; only `--output FILE` writes a report where you request it.

## Contributing

Issues, real (redacted) reproducible examples, tests and pull requests are welcome. **Never upload private scripts, access tokens, database strings, credentials, or server secrets** in an issue or report. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).

Run unit tests with:

```bash
python -m unittest discover -s tests -v
```

## Official Cfx.re references

- [Server commands (`start`, `ensure`, `exec`)](https://docs.fivem.net/docs/server-manual/server-commands/)
- [Resource manifest (`dependency`, `provide`, NUI)](https://docs.fivem.net/docs/scripting-reference/resource-manifest/)
- [Convars (`set`, `setr`, `sets`)](https://docs.fivem.net/docs/scripting-reference/convars/)
- [Resource directories and categories](https://docs.fivem.net/docs/scripting-manual/introduction/introduction-to-resources/)

**License:** [MIT](LICENSE).
