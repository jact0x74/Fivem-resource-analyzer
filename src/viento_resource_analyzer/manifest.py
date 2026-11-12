"""Conservative static extraction of literal fxmanifest.lua declarations.

Manifest files are executable Lua, so this module deliberately DOES NOT evaluate them.
Only statically written single/double-quoted strings (and Lua long strings) are
recognized. Dynamic declarations may be skipped and are reported to the caller.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Only these metadata keys have meaning to the analyzer.
SINGLE_PATH_KEYS = {
    'client_script', 'server_script', 'shared_script', 'file',
    'ui_page', 'loadscreen', 'before_level_meta', 'after_level_meta',
}
MULTI_PATH_KEYS = {'client_scripts', 'server_scripts', 'shared_scripts', 'files'}
METADATA_KEYS = {'fx_version', 'game', 'games', 'dependency', 'dependencies',
                 'provide', 'data_file', 'lua54'}
KNOWN_KEYS = SINGLE_PATH_KEYS | MULTI_PATH_KEYS | METADATA_KEYS


@dataclass(frozen=True)
class Declaration:
    key: str
    values: tuple[str, ...]
    line: int
    dynamic: bool = False


@dataclass
class Manifest:
    declarations: list[Declaration] = field(default_factory=list)
    dynamic_lines: list[tuple[str, int]] = field(default_factory=list)

    def values(self, *keys: str) -> list[str]:
        return [value for item in self.declarations if item.key in keys for value in item.values]

    def paths(self) -> list[tuple[str, str, int]]:
        rows = []
        for decl in self.declarations:
            if decl.key in SINGLE_PATH_KEYS | MULTI_PATH_KEYS:
                for value in decl.values:
                    rows.append((decl.key, value, decl.line))
            elif decl.key == 'data_file' and len(decl.values) >= 2:
                rows.append((decl.key, decl.values[1], decl.line))
        return rows


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    col: int


def _long_start(source: str, i: int) -> tuple[int, str] | None:
    """Lua [=[ strings/comments: return start length and closing delimiter."""
    m = re.match(r'\[(=*)\[', source[i:])
    if not m:
        return None
    return len(m.group(0)), ']' + m.group(1) + ']'


def tokenize(source: str) -> list[Token]:
    result: list[Token] = []
    i, line, col = 0, 1, 1

    def advance(piece: str) -> None:
        nonlocal line, col
        n = piece.count('\n')
        if n:
            line += n
            col = len(piece.rsplit('\n', 1)[-1]) + 1
        else:
            col += len(piece)

    while i < len(source):
        start_line, start_col = line, col
        c = source[i]
        if c.isspace():
            advance(c)
            i += 1
            continue
        if source.startswith('--', i):
            start = _long_start(source, i + 2)
            if start:
                opener_len, closing = start
                begin = i + 2 + opener_len
                end = source.find(closing, begin)
                end = len(source) if end == -1 else end + len(closing)
            else:
                end = source.find('\n', i)
                end = len(source) if end == -1 else end
            advance(source[i:end]); i = end
            continue
        if c in ("'", '"'):
            quote = c
            j = i + 1
            literal = []
            closed = False
            while j < len(source):
                if source[j] == '\\' and j + 1 < len(source):
                    escape = source[j + 1]
                    literal.append({'n': '\n', 'r': '\r', 't': '\t'}.get(escape, escape))
                    j += 2
                elif source[j] == quote:
                    j += 1; closed = True; break
                else:
                    literal.append(source[j]); j += 1
            result.append(Token('string' if closed else 'unknown', ''.join(literal), start_line, start_col))
            advance(source[i:j]); i = j
            continue
        if c == '[':
            long_start = _long_start(source, i)
            if long_start:
                opener_len, closing = long_start
                begin = i + opener_len
                end = source.find(closing, begin)
                closed = end != -1
                end = len(source) if not closed else end + len(closing)
                value = source[begin:end - len(closing)] if closed else source[begin:end]
                result.append(Token('string' if closed else 'unknown', value, start_line, start_col))
                advance(source[i:end]); i = end
                continue
        if c.isalpha() or c == '_':
            m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', source[i:])
            assert m
            value = m.group(0)
            result.append(Token('ident', value, start_line, start_col))
            advance(value); i += len(value)
            continue
        result.append(Token('symbol', c, start_line, start_col))
        advance(c); i += 1
    return result


def parse_manifest(source: str) -> Manifest:
    """Extract declarations that start at beginning of a logical line.

    This supports normal directive syntax and multi-line literal tables, but not
    computed paths or arbitrary executable Lua. No Lua code is run.
    """
    tokens = tokenize(source)
    manifest = Manifest()
    i = 0
    previous_line = 0
    lines = source.splitlines()
    while i < len(tokens):
        tok = tokens[i]
        # Ignore declarations nested inside a literal table already consumed.
        if tok.kind != 'ident' or tok.value not in KNOWN_KEYS or tok.line == previous_line:
            i += 1
            continue
        # Only a directive at the beginning of a line, not an identifier inside an expression.
        line_prefix = lines[tok.line - 1][:tok.col - 1]
        if line_prefix.strip():
            i += 1
            continue
        key = tok.value
        previous_line = tok.line
        j = i + 1
        if j >= len(tokens):
            manifest.dynamic_lines.append((key, tok.line)); i = j; continue
        # Optional function-call syntax e.g. client_script('client.lua')
        parentheses = tokens[j].value == '('
        if parentheses:
            j += 1
        if j >= len(tokens):
            manifest.dynamic_lines.append((key, tok.line)); i = j; continue
        values: list[str] = []
        dynamic = False
        if tokens[j].value == '{':
            depth = 0
            while j < len(tokens):
                t = tokens[j]
                if t.value == '{':
                    depth += 1
                elif t.value == '}':
                    depth -= 1
                    if depth == 0:
                        j += 1; break
                elif t.kind == 'string' and depth > 0:
                    values.append(t.value)
                elif t.kind == 'ident' and depth > 0:
                    dynamic = True
                j += 1
            if depth != 0:
                dynamic = True
        elif tokens[j].kind == 'string':
            values.append(tokens[j].value)
            j += 1
            if key == 'data_file' and j < len(tokens) and tokens[j].kind == 'string':
                values.append(tokens[j].value)
                j += 1
        else:
            dynamic = True
            # Skip a dynamic expression on the same line.
            while j < len(tokens) and tokens[j].line == tok.line:
                j += 1
        if parentheses and j < len(tokens) and tokens[j].value == ')':
            j += 1
        if not values or dynamic:
            manifest.dynamic_lines.append((key, tok.line))
        if values:
            manifest.declarations.append(Declaration(key, tuple(values), tok.line, dynamic))
        i = j
    return manifest
