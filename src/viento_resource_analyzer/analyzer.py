"""Read-only checks for FiveM resource directories."""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

from .manifest import Manifest, parse_manifest
from .lua_audit import scan_lua
from .nui import referenced_files
from .cfg_audit import CfgParser, evaluate_startup
from .performance import scan_performance

SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.mypy_cache', '.pytest_cache'}
SCRIPT_KEYS = {'client_script', 'server_script', 'shared_script',
               'client_scripts', 'server_scripts', 'shared_scripts'}
FILE_KEYS = SCRIPT_KEYS | {'file', 'files', 'ui_page', 'loadscreen',
                           'data_file', 'before_level_meta', 'after_level_meta'}
SPECIAL_DEPS = ('/',)


@dataclass(frozen=True)
class Finding:
    severity: str  # error, warning, info
    code: str
    resource: str
    message: str
    file: str
    line: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Resource:
    name: str
    path: Path
    manifest_path: Path
    manifest: Manifest


class Analyzer:
    def __init__(self, root: Path, available: set[str] | None = None, *, audit_lua: bool = False,
                 server_cfg: Path | None = None, performance_hints: bool = False) -> None:
        self.root = root.resolve()
        self.available = {v.casefold() for v in (available or set())}
        self.findings: list[Finding] = []
        self.resources: list[Resource] = []
        self.audit_lua = audit_lua
        self.dependency_edges: list[dict[str, str | None]] = []
        self.server_cfg = server_cfg
        self.performance_hints = performance_hints
        self.startup_order: list[dict] = []
        self.cfg_files_scanned = 0

    def add(self, severity: str, code: str, res: Resource, message: str,
            line: int | None = None, location: Path | None = None) -> None:
        path = location or res.manifest_path
        self.findings.append(Finding(severity, code, res.name, message,
                                     path.relative_to(self.root).as_posix()
                                     if path.is_relative_to(self.root) else path.name, line))

    def discover(self) -> None:
        manifest_paths: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and
                                 not Path(dirpath, d).is_symlink())
            if 'fxmanifest.lua' in filenames:
                manifest_paths.append(Path(dirpath, 'fxmanifest.lua'))
            elif '__resource.lua' in filenames:
                manifest_paths.append(Path(dirpath, '__resource.lua'))
        for path in sorted(manifest_paths):
            try:
                contents = path.read_text(encoding='utf-8-sig')
            except (OSError, UnicodeError) as exc:
                self.findings.append(Finding('error', 'MANIFEST_UNREADABLE', path.parent.name,
                                             f'Cannot read manifest: {exc}',
                                             path.relative_to(self.root).as_posix()))
                continue
            resource = Resource(path.parent.name, path.parent, path, parse_manifest(contents))
            self.resources.append(resource)
            if path.name == '__resource.lua':
                self.add('warning', 'LEGACY_MANIFEST', resource,
                         'Legacy __resource.lua is deprecated; consider fxmanifest.lua.')
            if path.name == 'fxmanifest.lua' and (path.parent / '__resource.lua').exists():
                self.add('warning', 'BOTH_MANIFESTS', resource,
                         'Both fxmanifest.lua and __resource.lua are present.')

    def _file_matches(self, resource: Resource, raw: str) -> list[Path] | None:
        value = raw.replace('\\', '/')
        # Paths in another resource are valid and not part of the local tree.
        if value.startswith('@') or '://' in value or value.startswith('nui:'):
            return None
        if value.startswith('/') or value.startswith('~') or '\x00' in value:
            return []
        # Resolve each match and ensure it stays inside the scanned resource.
        try:
            candidates = resource.path.glob(value)
            return [p for p in candidates if p.exists() and p.resolve().is_relative_to(resource.path.resolve())]
        except (ValueError, OSError, NotImplementedError):
            return []

    def check_resources(self) -> None:
        names = Counter(res.name.casefold() for res in self.resources)
        for res in self.resources:
            if names[res.name.casefold()] > 1:
                self.add('error', 'DUPLICATE_RESOURCE', res,
                         f'Resource name {res.name!r} appears multiple times in the scan.')
            manifest = res.manifest
            if res.manifest_path.name == 'fxmanifest.lua':
                if not manifest.values('fx_version'):
                    self.add('warning', 'NO_FX_VERSION', res, 'fx_version is not declared.')
                if not manifest.values('game', 'games'):
                    self.add('warning', 'NO_GAME', res, 'game or games is not declared.')
            for key, line in manifest.dynamic_lines:
                self.add('info', 'DYNAMIC_DECLARATION', res,
                         f'{key} contains a dynamic or unsupported expression; check manually.', line)
            for key, value, line in manifest.paths():
                if not value.strip():
                    self.add('warning', 'EMPTY_FILE_PATH', res, f'{key} has an empty path.', line)
                    continue
                found = self._file_matches(res, value)
                if found is not None and not found:
                    self.add('error', 'PATH_NOT_FOUND', res,
                             f'{key} references {value!r}, which matches no file/directory in this resource.', line)
                if key == 'ui_page' and found:
                    packed = set()
                    for pack_value in manifest.values('file', 'files'):
                        matches = self._file_matches(res, pack_value)
                        if matches is not None:
                            packed.update(p.resolve() for p in matches)
                    if not all(p.resolve() in packed for p in found):
                        self.add('warning', 'UI_NOT_PACKED', res,
                                 f'Local ui_page {value!r} is not covered by files/file; clients may not receive it.', line)
            if manifest.values('lua54'):
                self.add('info', 'LUA54_DEPRECATED', res,
                         'lua54 metadata is no longer required in current FXServer versions.')
            self.check_nui_assets(res)
            if self.audit_lua or self.performance_hints:
                self.check_lua(res)


    def check_nui_assets(self, res: Resource) -> None:
        """Check literal local HTML src/link assets against the NUI packfile."""
        manifest = res.manifest
        packed: set[Path] = set()
        for raw in manifest.values('file', 'files'):
            matches = self._file_matches(res, raw)
            if matches:
                packed.update(p.resolve() for p in matches if p.is_file())
        for raw in manifest.values('ui_page'):
            if not raw.lower().endswith(('.html', '.htm')):
                continue
            pages = self._file_matches(res, raw)
            if not pages or len(pages) != 1 or not pages[0].is_file():
                continue
            page = pages[0]
            try:
                if page.stat().st_size > 1024 * 1024:
                    continue
                html = page.read_text(encoding='utf-8-sig')
            except (OSError, UnicodeError):
                continue
            for ref in sorted(referenced_files(html, raw)):
                matches = self._file_matches(res, ref)
                if not matches:
                    self.add('warning', 'NUI_ASSET_MISSING', res,
                             f'Local HTML asset {ref!r} is not present in this resource.', location=page)
                elif any(p.resolve() not in packed for p in matches if p.is_file()):
                    self.add('warning', 'NUI_ASSET_NOT_PACKED', res,
                             f'Local HTML asset {ref!r} is not included in files/file.', location=page)

    def check_lua(self, res: Resource) -> None:
        """Review declared local .lua scripts without executing them (opt-in)."""
        seen: set[Path] = set()
        for key, raw, _ in res.manifest.paths():
            if key not in SCRIPT_KEYS:
                continue
            matches = self._file_matches(res, raw)
            for path in matches or []:
                if not path.is_file() or path.suffix.casefold() != '.lua' or path in seen:
                    continue
                seen.add(path)
                try:
                    if path.stat().st_size > 2 * 1024 * 1024:
                        self.add('info', 'LUA_AUDIT_SKIPPED', res,
                                 f'Script exceeds 2 MiB audit size limit: {path.name}', location=path)
                        continue
                    contents = path.read_text(encoding='utf-8-sig')
                except (OSError, UnicodeError):
                    self.add('info', 'LUA_AUDIT_SKIPPED', res,
                             f'Unable to read source file: {path.name}', location=path)
                    continue
                if self.audit_lua:
                    for flag in scan_lua(contents):
                        self.add('warning', flag.code, res, flag.description,
                                 flag.line, location=path)
                if self.performance_hints:
                    for flag in scan_performance(contents):
                        self.add('info', flag.code, res, flag.description,
                                 flag.line, location=path)

    def check_dependencies(self) -> None:
        lookup = {res.name.casefold(): res for res in self.resources}
        aliases: dict[str, str] = {}
        for res in self.resources:
            for alias in res.manifest.values('provide'):
                aliases.setdefault(alias.casefold(), res.name.casefold())
        graph: dict[str, set[str]] = {key: set() for key in lookup}
        for res in self.resources:
            owner = res.name.casefold()
            for dep in res.manifest.values('dependency', 'dependencies'):
                target = dep.casefold()
                resolved = aliases.get(target, target)
                if dep.startswith(SPECIAL_DEPS):
                    status = 'constraint'
                elif resolved == owner:
                    status = 'self'
                    self.add('error', 'SELF_DEPENDENCY', res, f'Resource depends on itself via {dep!r}.')
                elif resolved in lookup:
                    status = 'provided' if target in aliases and target != resolved else 'local'
                    graph[owner].add(resolved)
                elif target in self.available:
                    status = 'external'
                else:
                    status = 'missing'
                    self.add('warning', 'DEP_NOT_IN_SCAN', res,
                             f'Dependency {dep!r} was not found in the scanned tree. '
                             'It may exist elsewhere; pass --available to suppress this warning.')
                self.dependency_edges.append({'resource': res.name, 'dependency': dep,
                                              'status': status,
                                              'resolved_to': lookup[resolved].name
                                              if status in {'local', 'provided'} else None})
        self.dependency_edges.sort(key=lambda x: (x['resource'].casefold(), x['dependency'].casefold()))
        # Iterative DFS avoids recursion-depth errors on large server resource trees.
        state: dict[str, int] = {}
        reported: set[tuple[str, str]] = set()
        for first in sorted(graph):
            if state.get(first, 0):
                continue
            state[first] = 1
            stack: list[tuple[str, object]] = [(first, iter(sorted(graph[first])))]
            while stack:
                node, edges = stack[-1]
                dest = next(edges, None)
                if dest is None:
                    state[node] = 2
                    stack.pop()
                elif state.get(dest) == 1 and (node, dest) not in reported:
                    self.add('error', 'DEPENDENCY_CYCLE', lookup[node],
                             f'Dependency cycle detected involving {lookup[node].name!r} and {lookup[dest].name!r}.')
                    reported.add((node, dest))
                elif state.get(dest, 0) == 0:
                    state[dest] = 1
                    stack.append((dest, iter(sorted(graph[dest]))))

    def check_server_cfg(self) -> None:
        """Read server configs without executing commands or serializing secret values."""
        if self.server_cfg is None:
            return
        lookup = {r.name.casefold(): r.path for r in self.resources}
        parser = CfgParser(Path(self.server_cfg), lookup)
        commands, notices = parser.parse()
        self.cfg_files_scanned = parser._files_seen
        for notice in notices:
            self.findings.append(Finding(notice.severity, notice.code, '[server.cfg]',
                                         notice.message, notice.file, notice.line))
        self.startup_order, issues = evaluate_startup(commands, self.resources, self.root, self.available)
        for severity, code, message, file, line in issues:
            self.findings.append(Finding(severity, code, '[server.cfg]', message, file, line))

    def run(self) -> dict:
        if not self.root.is_dir():
            raise ValueError(f'Scan path is not a directory: {self.root}')
        self.findings.clear()
        self.resources.clear()
        self.dependency_edges.clear()
        self.startup_order.clear()
        self.cfg_files_scanned = 0
        self.discover()
        self.check_resources()
        self.check_dependencies()
        self.check_server_cfg()
        self.findings.sort(key=lambda f: (f.resource.casefold(), f.file, f.line or 0,
                                          f.severity, f.code, f.message))
        counts = Counter(f.severity for f in self.findings)
        return {
            'schema_version': '1.3',
            'scan_root': str(self.root),
            'resources_scanned': len(self.resources),
            'resource_names': sorted((r.name for r in self.resources), key=str.casefold),
            'dependency_edges': self.dependency_edges,
            'startup_order': self.startup_order,
            'cfg_files_scanned': self.cfg_files_scanned,
            'summary': {sev: counts[sev] for sev in ('error', 'warning', 'info')},
            'findings': [f.to_dict() for f in self.findings],
        }
