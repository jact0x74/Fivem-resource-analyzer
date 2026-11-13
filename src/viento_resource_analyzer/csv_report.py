"""RFC 4180-style UTF-8 CSV of findings for offline spreadsheet review.

Untrusted script/resource names must not be interpreted as spreadsheet formulas.
The export intentionally contains findings only and no raw server.cfg values.
"""
from __future__ import annotations

import csv
import io

FIELDS = ('severity', 'code', 'resource', 'file', 'line', 'message')


def _safe_cell(value: object) -> str:
    text = '' if value is None else str(value)
    # Excel and other spreadsheet applications may interpret leading formula
    # characters as executable formulas. A leading apostrophe forces text.
    # Ignore whitespace when looking for a dangerous initial character, since
    # a leading CR/tab/space is not a reliable escape in spreadsheet importers.
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def render_csv(report: dict) -> str:
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\r\n')
    writer.writerow(FIELDS)
    for item in report.get('findings', []):
        writer.writerow(_safe_cell(item.get(field)) for field in FIELDS)
    return stream.getvalue()
