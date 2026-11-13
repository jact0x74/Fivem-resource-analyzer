"""v0.4.0 regression tests for CSV safety, reporting and opt-in heuristics."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from viento_resource_analyzer.csv_report import FIELDS, render_csv
from viento_resource_analyzer.lua_audit import scan_lua
from viento_resource_analyzer.performance import scan_performance
from viento_resource_analyzer.analyzer import Analyzer
from viento_resource_analyzer.html_report import render_html
from viento_resource_analyzer.cli import main


class CsvTests(unittest.TestCase):
    def test_header_no_findings(self):
        rows = list(csv.reader(io.StringIO(render_csv({'findings': []}))))
        self.assertEqual(rows, [list(FIELDS)])

    def test_comma_quote_and_newline_roundtrip(self):
        finding = {'severity': 'warning', 'code': 'LUA_TEST', 'resource': 'say,"hey"',
                   'file': 'a\nscript.lua', 'line': 12, 'message': 'Hello, "world"\nmore'}
        parsed = list(csv.DictReader(io.StringIO(render_csv({'findings': [finding]}))))[0]
        self.assertEqual(parsed['resource'], 'say,"hey"')
        self.assertEqual(parsed['file'], 'a\nscript.lua')
        self.assertEqual(parsed['message'], 'Hello, "world"\nmore')
        self.assertEqual(parsed['line'], '12')

    def test_formula_injection_is_literal_text(self):
        payloads = ['=HYPERLINK("http://example.invalid", "x")', '+SUM(1,2)',
                    '-1+2', '@SUM(1)', '  =SUM(1,2)', '\t=SUM(1,2)', '\r=SUM(1,2)', '\n=SUM(1,2)']
        for payload in payloads:
            finding = dict.fromkeys(FIELDS, payload)
            row = list(csv.DictReader(io.StringIO(render_csv({'findings': [finding]}))))[0]
            for value in row.values():
                self.assertTrue(value.startswith("'"), repr(value))

    def test_none_line_is_empty(self):
        finding = dict(severity='info', code='TEST', resource='test', file='file', line=None, message='ok')
        row = list(csv.DictReader(io.StringIO(render_csv({'findings': [finding]}))))[0]
        self.assertEqual(row['line'], '')

    def test_real_csv_cli_with_root_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'resources'; root.mkdir()
            resource = root / 'my_resource'; resource.mkdir()
            (resource / 'fxmanifest.lua').write_text("fx_version 'cerulean'\ngame 'gta5'\nclient_script 'missing.lua'\n")
            destination = Path(temp)/'out.csv'
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = main([str(root), '--format', 'csv', '--output', str(destination), '--redact-root'])
            self.assertEqual(exit_code, 1)  # missing file is a real error
            content = destination.read_text(encoding='utf-8')
            self.assertIn('PATH_NOT_FOUND', content)
            self.assertNotIn(str(root), content)


class ExtendedLuaAuditTests(unittest.TestCase):
    def test_plain_http_literal_flagged_without_disclosing_url(self):
        source = "PerformHttpRequest('http://user:token123@evil.test/a?key=SECRET_VALUE', cb)"
        signals = scan_lua(source)
        self.assertEqual({s.code for s in signals}, {'LUA_EXTERNAL_HTTP', 'LUA_INSECURE_HTTP'})
        self.assertNotIn('SECRET_VALUE', str(signals))
        self.assertEqual({s.line for s in signals}, {1})

    def test_https_not_flagged_as_plaintext(self):
        codes = [s.code for s in scan_lua('PerformHttpRequest("https://example.org", cb)')]
        self.assertEqual(codes, ['LUA_EXTERNAL_HTTP'])

    def test_await_plaintext(self):
        codes = {s.code for s in scan_lua('PerformHttpRequestAwait([[http://example.invalid]])')}
        self.assertEqual(codes, {'LUA_EXTERNAL_HTTP', 'LUA_INSECURE_HTTP'})

    def test_dynamic_http_address_no_plaintext_assertion(self):
        codes = [s.code for s in scan_lua('PerformHttpRequest(url, cb)')]
        self.assertEqual(codes, ['LUA_EXTERNAL_HTTP'])

    def test_comments_and_method_calls_ignored(self):
        src = '-- PerformHttpRequest("http://example.com")\nobj:PerformHttpRequest("http://evil.example")'
        self.assertEqual(scan_lua(src), [])

    def test_file_execution_flag(self):
        codes = [s.code for s in scan_lua('loadfile("x.lua")\ndofile("y.lua")')]
        self.assertEqual(codes, ['LUA_FILE_EXEC', 'LUA_FILE_EXEC'])

    def test_file_exec_definitions_not_flagged(self):
        self.assertEqual(scan_lua('function dofile(path) end\na:dofile("x.lua")'), [])


class ExtendedPerformanceTests(unittest.TestCase):
    def test_repeat_until_false_flagged(self):
        found = scan_performance('repeat\nwork()\nuntil false')
        self.assertEqual([(x.code, x.line) for x in found], [('LUA_POSSIBLE_BUSY_LOOP', 1)])

    def test_repeat_with_wait_suppresses_busy_loop(self):
        self.assertEqual(scan_performance('repeat Wait(250) until false'), [])

    def test_log_spam_with_wait(self):
        found = scan_performance('while true do print("hello") Wait(0) end')
        self.assertEqual([x.code for x in found], ['LUA_LOOP_LOGGING'])

    def test_log_spam_without_wait(self):
        found = scan_performance('while true do print("hello") end')
        self.assertEqual({x.code for x in found}, {'LUA_LOOP_LOGGING', 'LUA_POSSIBLE_BUSY_LOOP'})

    def test_nested_loop_skipped(self):
        self.assertEqual(scan_performance('repeat if x then print("ok") end until false'), [])

    def test_string_and_comment_ignored(self):
        self.assertEqual(scan_performance('-- repeat print("test") until false\nprint("while true do end")'), [])


class Html040Tests(unittest.TestCase):
    def test_resource_filter_and_reset_controls(self):
        data = {'summary': {'error': 1, 'warning': 0, 'info': 0},
                'scan_root': '[redacted]', 'resources_scanned': 1,
                'resource_names': ['my_resource'], 'dependency_edges': [],
                'findings': [{'severity': 'error', 'code': 'TEST', 'resource': 'my_resource',
                              'file': 'fxmanifest.lua', 'line': 1, 'message': 'Message'}]}
        html = render_html(data)
        self.assertIn('id="finding-resource"', html)
        self.assertIn('id="finding-reset"', html)
        self.assertIn('data-resource="my_resource"', html)
        self.assertIn('Resource findings', html)
        self.assertIn('v0.4.0', html)
        self.assertNotIn('/home/', html)

    def test_escape_resource_attribute_and_dropdown(self):
        nasty = '<img src=x onerror=alert(1)>'
        data = {'summary': {'error': 0, 'warning': 1, 'info': 0},
                'scan_root': 'no', 'resources_scanned': 1, 'resource_names': [nasty],
                'findings': [{'severity': 'warning', 'code': 'TEST', 'resource': nasty,
                              'file': 'a', 'line': None, 'message': nasty}]}
        html = render_html(data)
        self.assertNotIn(nasty, html)
        self.assertIn('&lt;img', html)
        self.assertIn('data-resource="&lt;img', html)

    def test_cli_json_redacts_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'res'; root.mkdir()
            out = Path(tmp)/'report.json'
            with contextlib.redirect_stderr(io.StringIO()):
                rc = main([str(root), '--redact-root', '--format', 'json', '--output', str(out)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out.read_text())['scan_root'], '[redacted]')


class RealIntegration040Tests(unittest.TestCase):
    def test_flags_only_when_opted_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)/'s'; folder.mkdir()
            (folder/'fxmanifest.lua').write_text("fx_version 'cerulean'\ngame 'gta5'\nserver_script 'main.lua'\n")
            (folder/'main.lua').write_text('PerformHttpRequest("http://example.invalid", cb)\nrepeat print("tick") until false\n')
            normal = Analyzer(Path(tmp)).run()
            self.assertFalse(any(f['code'].startswith('LUA_') for f in normal['findings']))
            audited = Analyzer(Path(tmp), audit_lua=True, performance_hints=True).run()
            codes = {f['code'] for f in audited['findings']}
            self.assertTrue({'LUA_EXTERNAL_HTTP', 'LUA_INSECURE_HTTP',
                             'LUA_POSSIBLE_BUSY_LOOP', 'LUA_LOOP_LOGGING'}.issubset(codes))


if __name__ == '__main__':
    unittest.main()
