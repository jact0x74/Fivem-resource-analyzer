"""Conservative, read-only parser for a FiveM server.cfg and nested exec files.

Cfx executes config files as console command streams. We inspect only static,
line-oriented literal commands; we NEVER execute anything or display convar values.
Includes are resolved relative to the server data directory or @resource path.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

MAX_CFG_BYTES = 2 * 1024 * 1024
MAX_CFG_FILES = 128
MAX_DEPTH = 16


@dataclass(frozen=True)
class CfgCommand:
    command: str
    argument: str
    file: str
    line: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class CfgNotice:
    severity: str
    code: str
    message: str
    file: str
    line: int | None = None


def split_command(line: str) -> list[str]:
    """Small lexer: whitespace/comments, quotes, Windows paths (no backslash escaping)."""
    out: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    in_token = False
    for ch in line.lstrip('\ufeff'):
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            in_token = True
        elif ch in ('"', "'"):
            quote = ch
            in_token = True
        elif ch == '#' and not in_token:
            break
        elif ch.isspace():
            if in_token:
                out.append(''.join(buf))
                buf.clear()
                in_token = False
        else:
            buf.append(ch)
            in_token = True
    if quote:
        # Unbalanced quotes are not interpreted; caller may flag unsupported input.
        return []
    if in_token:
        out.append(''.join(buf))
    return out


class CfgParser:
    def __init__(self, path: Path, resource_paths: dict[str, Path]):
        self.path = path.resolve()
        self.base = self.path.parent
        self.resource_paths = resource_paths
        self.commands: list[CfgCommand] = []
        self.notices: list[CfgNotice] = []
        self._files_seen = 0

    def label(self, path: Path) -> str:
        try:
            return path.relative_to(self.base).as_posix()
        except ValueError:
            for name, resource_path in self.resource_paths.items():
                if path.is_relative_to(resource_path.resolve()):
                    return '@' + name + '/' + path.relative_to(resource_path.resolve()).as_posix()
            return path.name

    def notice(self, sev: str, code: str, message: str, path: Path, line: int | None = None) -> None:
        self.notices.append(CfgNotice(sev, code, message, self.label(path), line))

    def _target(self, raw: str) -> Path | None:
        if not raw or '\x00' in raw:
            return None
        if raw.startswith('@'):
            parts = raw[1:].replace('\\', '/').split('/', 1)
            if len(parts) != 2 or not parts[1]:
                return None
            root = self.resource_paths.get(parts[0].casefold())
            if root is None:
                return None
            candidate = (root / parts[1]).resolve()
            return candidate if candidate.is_relative_to(root.resolve()) else None
        candidate = (self.base / raw.replace('\\', '/')).resolve()
        return candidate if candidate.is_relative_to(self.base) else None

    def _read(self, path: Path, stack: tuple[Path, ...]) -> None:
        if len(stack) >= MAX_DEPTH:
            self.notice('warning', 'CFG_EXEC_LIMIT', 'Maximum nested exec depth reached.', path)
            return
        if path in stack:
            self.notice('warning', 'CFG_EXEC_CYCLE', 'Recursive exec cycle detected; stopped following includes.', path)
            return
        self._files_seen += 1
        if self._files_seen > MAX_CFG_FILES:
            self.notice('warning', 'CFG_EXEC_LIMIT', 'Maximum number of config files reached.', path)
            return
        try:
            if not path.is_file():
                self.notice('warning', 'CFG_EXEC_NOT_FOUND', 'Included config file not found.', path)
                return
            if path.stat().st_size > MAX_CFG_BYTES:
                self.notice('warning', 'CFG_TOO_LARGE', 'Config file exceeds 2 MiB scan limit.', path)
                return
            body = path.read_text(encoding='utf-8-sig')
        except (OSError, UnicodeError):
            self.notice('warning', 'CFG_READ_FAILED', 'Config file could not be read.', path)
            return
        for lineno, raw_line in enumerate(body.splitlines(), 1):
            tokens = split_command(raw_line)
            if not tokens:
                continue
            command = tokens[0].casefold()
            if command == 'exec':
                if len(tokens) != 2:
                    self.notice('info', 'CFG_EXEC_DYNAMIC', 'Unsupported exec declaration; inspect manually.', path, lineno)
                    continue
                included = self._target(tokens[1])
                if included is None:
                    self.notice('warning', 'CFG_EXEC_UNRESOLVED',
                                'Exec path could not be resolved inside allowed roots; no file opened.', path, lineno)
                    continue
                if included in stack + (path,):
                    self.notice('warning', 'CFG_EXEC_CYCLE', 'Recursive exec cycle detected.', path, lineno)
                    continue
                self._read(included, stack + (path,))
            elif command in {'ensure', 'start', 'stop', 'restart'}:
                if len(tokens) != 2:
                    self.notice('info', 'CFG_RESOURCE_DYNAMIC',
                                f'{command} declaration could not be parsed statically.', path, lineno)
                    continue
                self.commands.append(CfgCommand(command, tokens[1], self.label(path), lineno))
            elif command in {'set', 'setr', 'sets'}:
                # The actual value is intentionally NEVER retained or included in the report.
                if len(tokens) < 2:
                    continue
                name = tokens[1].casefold()
                sensitive = any(tag in name for tag in
                                ('password', 'secret', 'token', 'licensekey', 'api_key',
                                 'apikey', 'connection_string', 'privatekey'))
                if command in {'setr', 'sets'} and sensitive:
                    self.notice('warning', 'CFG_SECRET_EXPOSURE',
                                f'{command} publishes or replicates a potentially sensitive convar ({tokens[1]}). '
                                'Use server-only set where appropriate; the value was not read into the report.',
                                path, lineno)
            elif command == 'sv_scripthookallowed':
                if len(tokens) >= 2 and tokens[1].lower() in {'1', 'true'}:
                    self.notice('warning', 'CFG_SCRIPTHOOK_ENABLED',
                                'sv_scriptHookAllowed is enabled. Review whether this is intended.', path, lineno)

    def parse(self) -> tuple[list[CfgCommand], list[CfgNotice]]:
        if not self.path.is_file():
            raise ValueError(f'server.cfg not found: {self.path}')
        self._read(self.path, ())
        return self.commands, self.notices


def evaluate_startup(commands: list[CfgCommand], resources: list, resource_root: Path,
                     available: set[str]) -> tuple[list[dict], list[tuple[str, str, str, str, int | None]]]:
    """Return startup timeline and conservative diagnostics; no FXServer execution.

    Details are approximate: Cfx may auto-start dependencies and resources outside
    the scanned tree. This checker only evaluates the visible static command order.
    """
    by_name = {res.name.casefold(): res for res in resources}
    provided: dict[str, str] = {}
    for res in resources:
        for alias in res.manifest.values('provide'):
            provided.setdefault(alias.casefold(), res.name.casefold())
    cat_names: dict[str, list[str]] = {}
    for res in resources:
        try:
            parts = res.path.relative_to(resource_root).parts[:-1]
        except ValueError:
            parts = ()
        for part in parts:
            if part.startswith('[') and part.endswith(']'):
                cat_names.setdefault(part.casefold(), []).append(res.name)
    for names in cat_names.values():
        names.sort(key=str.casefold)
    timeline: list[dict] = []
    issues: list[tuple[str, str, str, str, int | None]] = []
    active: set[str] = set()
    explicit: set[str] = set()
    seen_ensures: set[str] = set()
    # Known future resource starts allow us to distinguish 'out of order' from
    # 'not explicitly listed' without misrepresenting runtime dependency loading.
    expanded: list[tuple[CfgCommand, list[str]]] = []
    for cmd in commands:
        literal = cmd.argument.casefold()
        if literal.startswith('[') and literal.endswith(']'):
            names = cat_names.get(literal, [])
            if not names:
                issues.append(('info', 'CFG_CATEGORY_NOT_IN_SCAN',
                               f'Category {cmd.argument!r} is absent from the scanned tree.', cmd.file, cmd.line))
        else:
            actual = provided.get(literal, literal)
            names = [by_name[actual].name] if actual in by_name else []
            if not names and literal not in available:
                issues.append(('info', 'CFG_RESOURCE_NOT_IN_SCAN',
                               f'Resource {cmd.argument!r} is not in this scan; it may be provided externally.',
                               cmd.file, cmd.line))
        expanded.append((cmd, names))
        if cmd.command in {'ensure', 'start', 'restart'}:
            explicit.update(name.casefold() for name in names)
    for cmd, names in expanded:
        timeline.append({'command': cmd.command, 'target': cmd.argument,
                         'expanded_resources': names, 'file': cmd.file, 'line': cmd.line})
        for name in names:
            key = name.casefold()
            if cmd.command == 'stop':
                active.discard(key)
                continue
            if cmd.command == 'ensure' and key in seen_ensures:
                issues.append(('warning', 'CFG_REPEATED_ENSURE',
                               f'Resource {name!r} is ensured multiple times; ensure may restart it.',
                               cmd.file, cmd.line))
            if cmd.command == 'ensure':
                seen_ensures.add(key)
            res = by_name[key]
            for dep in res.manifest.values('dependency', 'dependencies'):
                if dep.startswith('/'):
                    continue  # Runtime build/policy constraints, not resource names.
                dep_key = provided.get(dep.casefold(), dep.casefold())
                if dep_key == key or dep_key not in by_name or dep_key in active:
                    continue
                if dep_key in explicit:
                    issues.append(('warning', 'CFG_DEP_ORDER',
                                   f'{name!r} is explicitly started before local dependency '
                                   f'{by_name[dep_key].name!r}. Recheck command order.',
                                   cmd.file, cmd.line))
                else:
                    issues.append(('info', 'CFG_DEP_NOT_EXPLICIT',
                                   f'{name!r} depends on {by_name[dep_key].name!r}, which is not explicitly '
                                   'started in inspected configs; it may be auto-started elsewhere.',
                                   cmd.file, cmd.line))
            active.add(key)
    return timeline, issues
