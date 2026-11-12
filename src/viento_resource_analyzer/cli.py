"""Command-line interface for the Viento Resource Analyzer."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import Analyzer


def render_text(report: dict) -> str:
    summary = report['summary']
    lines = [f"Viento Resource Analyzer | scanned {report['resources_scanned']} resources",
             f"Errors: {summary['error']} | Warnings: {summary['warning']} | Info: {summary['info']}", '']
    if not report['findings']:
        lines.append('No findings. (Static analysis cannot guarantee runtime correctness.)')
    for item in report['findings']:
        position = item['file'] + (f":{item['line']}" if item['line'] is not None else '')
        lines.append(f"[{item['severity'].upper()}] {item['code']} | {position} | {item['message']}")
    return '\n'.join(lines) + '\n'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Read-only static checks for FiveM resource manifests.')
    parser.add_argument('path', type=Path, help='Resource folder or resources/ root to scan')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Report format')
    parser.add_argument('--output', type=Path, help='Write report to a file instead of stdout')
    parser.add_argument('--strict', action='store_true', help='Return nonzero on warnings as well as errors')
    parser.add_argument('--available', action='append', default=[], metavar='RESOURCE',
                        help='Known external resource (repeat as necessary)')
    args = parser.parse_args(argv)
    try:
        result = Analyzer(args.path, set(args.available)).run()
        content = json.dumps(result, ensure_ascii=False, indent=2) + '\n' if args.format == 'json' else render_text(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(content, encoding='utf-8')
            print(f'Report written to: {args.output}', file=sys.stderr)
        else:
            print(content, end='')
        return 1 if (result['summary']['error'] or args.strict and result['summary']['warning']) else 0
    except (OSError, ValueError) as exc:
        print(f'vra: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
