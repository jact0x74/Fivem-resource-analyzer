"""Opt-in performance hints; deliberately conservative, never measures resmon."""
from __future__ import annotations
from dataclasses import dataclass
from .manifest import tokenize


@dataclass(frozen=True)
class PerformanceSignal:
    code: str
    line: int
    description: str


def _has_yield(body: list) -> bool:
    # Heuristic: a visible Wait/Citizen.Wait token is enough to suppress the
    # busy-loop hint. It is not a proof that the call actually runs.
    return any(t.kind == 'ident' and t.value in {'Wait', 'Citizen'} for t in body)


def _plain_body(body: list) -> bool:
    # Do not try to parse nested control flow with this token-based heuristic.
    return not any(t.kind == 'ident' and t.value in
                   {'while', 'for', 'if', 'function', 'repeat', 'do', 'break', 'return', 'goto'} for t in body)


def _logs_each_iteration(body: list) -> bool:
    for i, t in enumerate(body[:-1]):
        if t.kind == 'ident' and t.value == 'print' and body[i + 1].value == '(':
            if not i or body[i - 1].value not in {'.', ':', 'function'}:
                return True
    return False


def scan_performance(source: str) -> list[PerformanceSignal]:
    """Flag simple infinite loops without Wait, and per-iteration print calls.

    This is not a control-flow engine. Complex loops are deliberately skipped.
    """
    tokens = tokenize(source)
    results: list[PerformanceSignal] = []
    for i in range(len(tokens)):
        t = tokens[i]
        if t.kind != 'ident':
            continue
        body = None
        if (t.value == 'while' and i + 2 < len(tokens)
                and tokens[i + 1].value == 'true' and tokens[i + 2].value == 'do'):
            after = tokens[i + 3:i + 503]
            end = next((j for j, x in enumerate(after) if x.kind == 'ident' and x.value == 'end'), None)
            if end is not None:
                body = after[:end]
        elif t.value == 'repeat':
            after = tokens[i + 1:i + 501]
            until = next((j for j, x in enumerate(after) if x.kind == 'ident' and x.value == 'until'), None)
            if until is not None and until + 1 < len(after) and after[until + 1].value == 'false':
                body = after[:until]
        if body is None or not _plain_body(body):
            continue
        if not _has_yield(body):
            results.append(PerformanceSignal('LUA_POSSIBLE_BUSY_LOOP', t.line,
                'A simple infinite loop has no visible Wait()/Citizen.Wait(); '
                'review for a potential busy loop. No runtime measurements were made.'))
        if _logs_each_iteration(body):
            results.append(PerformanceSignal('LUA_LOOP_LOGGING', t.line,
                'A simple infinite loop calls print(); review log volume and runtime impact.'))
    return results
