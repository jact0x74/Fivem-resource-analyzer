"""Opt-in conservative Lua token checks; not vulnerability detection."""
from __future__ import annotations
from dataclasses import dataclass
from .manifest import tokenize

@dataclass(frozen=True)
class LuaSignal:
    code: str
    line: int
    description: str

CALLS = {
    ('loadstring',): ('LUA_DYNAMIC_EXEC', 'Uses loadstring(); review dynamically evaluated code.'),
    ('load',): ('LUA_DYNAMIC_EXEC', 'Uses load(); review dynamically evaluated code.'),
    ('loadfile',): ('LUA_FILE_EXEC', 'Uses loadfile(); review the loaded source and path.'),
    ('dofile',): ('LUA_FILE_EXEC', 'Uses dofile(); review the executed file and path.'),
    ('os', 'execute'): ('LUA_OS_COMMAND', 'Uses os.execute(); review command execution.'),
    ('io', 'popen'): ('LUA_OS_COMMAND', 'Uses io.popen(); review shell process access.'),
    ('PerformHttpRequest',): ('LUA_EXTERNAL_HTTP', 'Uses PerformHttpRequest(); review destination and data handling.'),
    ('PerformHttpRequestAwait',): ('LUA_EXTERNAL_HTTP', 'Uses PerformHttpRequestAwait(); review destination and data handling.'),
    ('ExecuteCommand',): ('LUA_SERVER_COMMAND', 'Uses ExecuteCommand(); review authorization and command arguments.'),
    ('SaveResourceFile',): ('LUA_RESOURCE_WRITE', 'Uses SaveResourceFile(); review write scope and input validation.'),
}

def scan_lua(source: str) -> list[LuaSignal]:
    tokens = tokenize(source)
    signals: list[LuaSignal] = []
    seen: set[tuple[str, int]] = set()
    for i, tok in enumerate(tokens):
        if tok.kind != 'ident' or (i and tokens[i - 1].value in {'.', ':', 'function'}):
            continue
        for pieces, (code, message) in CALLS.items():
            if tok.value != pieces[0]:
                continue
            j = i
            for piece in pieces[1:]:
                if not (j + 2 < len(tokens) and tokens[j + 1].value == '.' and
                        tokens[j + 2].kind == 'ident' and tokens[j + 2].value == piece):
                    break
                j += 2
            else:
                if j + 1 < len(tokens) and tokens[j + 1].value == '(' and (code, tok.line) not in seen:
                    signals.append(LuaSignal(code, tok.line, message))
                    seen.add((code, tok.line))
                # Only examine a *literal first argument*. Never serialize its
                # content: URLs sometimes include tokens in query parameters.
                if (tok.value in {'PerformHttpRequest', 'PerformHttpRequestAwait'}
                        and j + 2 < len(tokens) and tokens[j + 2].kind == 'string'
                        and tokens[j + 2].value.casefold().startswith('http://')
                        and ('LUA_INSECURE_HTTP', tok.line) not in seen):
                    signals.append(LuaSignal('LUA_INSECURE_HTTP', tok.line,
                        'A literal plaintext HTTP URL is used; review transport security.'))
                    seen.add(('LUA_INSECURE_HTTP', tok.line))
    return signals
