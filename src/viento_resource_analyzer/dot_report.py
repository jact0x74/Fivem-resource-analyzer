"""Graphviz DOT exporter; safely quotes graph identifiers."""
from __future__ import annotations

import json


def render_dot(report: dict) -> str:
    # JSON double-quoted string syntax safely represents identifiers in DOT,
    # including slashes, quotes and literal newlines.
    def q(value: object) -> str:
        return json.dumps(str(value), ensure_ascii=True)

    lines = ['digraph FiveMResources {', '  rankdir=LR;', '  node [shape=box];']
    for name in report['resource_names']:
        lines.append(f'  {q(name)};')
    for edge in report['dependency_edges']:
        if edge['status'] == 'constraint':
            continue
        status = edge['status']
        target = edge.get('resolved_to') or edge['dependency']
        attrs: list[str] = []
        if status in {'missing', 'external'}:
            attrs.append('style=dashed')
        if status == 'provided':
            attrs.append(f'label={q(edge["dependency"])}')
        suffix = f' [{", ".join(attrs)}]' if attrs else ''
        lines.append(f'  {q(edge["resource"])} -> {q(target)}{suffix};')
    lines.append('}')
    return '\n'.join(lines) + '\n'
