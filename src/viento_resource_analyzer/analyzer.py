"""Read-only checks for FiveM resource directories."""
from __future__ import annotations

import fnmatch
import os
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

from .manifest import Manifest, parse_manifest

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
    def __init__(self, root: Path, available: set[str] | None = None) -> None:
        self.root = root.resolve()
        self.available = {v.casefold() for v in (available or set())}
        self.findings: list[Finding] = []
        self.resources: list[Resource] = []

    def add(self, severity: str, code: str, res: Resource, message: str,
            line: int | None = None) -> None:
        self.findings.append(Finding(severity, code, res.name, message,
                                     str(res.manifest_path.relative_to(self.root))
                                     if res.manifest_path.is_relative_to(self.root)
                                     else res.manifest_path.name, line))

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
                                             str(path.relative_to(self.root))))
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

    def check_dependencies(self) -> None:
        known = {res.name.casefold() for res in self.resources} | self.available
        # 'provide' lets a resource fulfill a dependency on its replacement alias.
        for res in self.resources:
            known.update(p.casefold() for p in res.manifest.values('provide'))
        graph: dict[str, set[str]] = {}
        lookup = {res.name.casefold(): res for res in self.resources}
        for res in self.resources:
            deps = res.manifest.values('dependency', 'dependencies')
            owner = res.name.casefold()
            graph.setdefault(owner, set())
            for dep in deps:
                if dep.startswith(SPECIAL_DEPS):
                    continue
                dep_key = dep.casefold()
                if dep_key == owner:
                    self.add('error', 'SELF_DEPENDENCY', res, 'Resource depends on itself.')
                elif dep_key not in known:
                    self.add('warning', 'DEP_NOT_IN_SCAN', res,
                             f'Dependency {dep!r} was not found in the scanned tree. '
                             'It may exist elsewhere; pass --available to suppress this warning.')
                elif dep_key in lookup:
                    graph[owner].add(dep_key)
        # DFS reports each directed back-edge once. Only discovered resources can form proven cycles.
        state: dict[str, int] = {}
        reported: set[tuple[str, str]] = set()

        def visit(node: str) -> None:
            state[node] = 1
            for dest in sorted(graph.get(node, ())):
                if state.get(dest) == 1 and (node, dest) not in reported:
                    self.add('error', 'DEPENDENCY_CYCLE', lookup[node],
                             f'Dependency cycle detected involving {lookup[node].name!r} and {lookup[dest].name!r}.')
                    reported.add((node, dest))
                elif state.get(dest, 0) == 0:
                    visit(dest)
            state[node] = 2

        for node in sorted(graph):
            if state.get(node, 0) == 0:
                visit(node)

    def run(self) -> dict:
        if not self.root.is_dir():
            raise ValueError(f'Scan path is not a directory: {self.root}')
        self.discover()
        self.check_resources()
        self.check_dependencies()
        self.findings.sort(key=lambda f: (f.resource.casefold(), f.file, f.line or 0,
                                          f.severity, f.code, f.message))
        counts = Counter(f.severity for f in self.findings)
        return {
            'schema_version': '1.0',
            'scan_root': str(self.root),
            'resources_scanned': len(self.resources),
            'summary': {sev: counts[sev] for sev in ('error', 'warning', 'info')},
            'findings': [f.to_dict() for f in self.findings],
        }
