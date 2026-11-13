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
    ('os', 'execute'): ('LUA_OS_COMMAND', 'Uses os.execute(); review command execution.'),
    ('io', 'popen'): ('LUA_OS_COMMAND', 'Uses io.popen(); review shell process access.'),
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
    return signals
