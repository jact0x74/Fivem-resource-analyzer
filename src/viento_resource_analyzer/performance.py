"""Opt-in performance hints; deliberately conservative, never measures resmon."""
from __future__ import annotations
from dataclasses import dataclass
from .manifest import tokenize


@dataclass(frozen=True)
class PerformanceSignal:
    code: str
    line: int
    description: str


def scan_performance(source: str) -> list[PerformanceSignal]:
    """Spot trivially unyielding infinite loops, ignoring strings and comments.

    Nested/control-flow-heavy loops are skipped to avoid inaccurate conclusions;
    an issue is only a hint for review, not a runtime performance measurement.
    """
    tokens = tokenize(source)
    results: list[PerformanceSignal] = []
    for i in range(len(tokens) - 3):
        if not (tokens[i].value == 'while' and tokens[i].kind == 'ident' and
                tokens[i + 1].value == 'true' and tokens[i + 2].value == 'do'):
            continue
        # Conservative bound and skip nested control flow we cannot properly model.
        body = tokens[i + 3:i + 503]
        end = next((j for j, t in enumerate(body) if t.kind == 'ident' and t.value == 'end'), None)
        if end is None:
            continue
        body = body[:end]
        if any(t.kind == 'ident' and t.value in {'while', 'for', 'if', 'function', 'repeat', 'do', 'break', 'return', 'goto'}
               for t in body):
            continue
        if any(t.kind == 'ident' and t.value in {'Wait', 'Citizen'} for t in body):
            continue
        results.append(PerformanceSignal('LUA_POSSIBLE_BUSY_LOOP', tokens[i].line,
                                         'A simple while true loop has no visible Wait()/Citizen.Wait(); '
                                         'review for a potential busy loop. No runtime measurements were made.'))
    return results
