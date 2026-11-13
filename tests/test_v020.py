"""Regression and integration checks added with 0.2.0."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from viento_resource_analyzer.analyzer import Analyzer
from viento_resource_analyzer.cli import main
from viento_resource_analyzer.dot_report import render_dot
from viento_resource_analyzer.html_report import render_html
from viento_resource_analyzer.lua_audit import scan_lua
from viento_resource_analyzer.nui import referenced_files


BASE = "fx_version 'cerulean'\ngame 'gta5'\n"


class HtmlAndGraphTests(unittest.TestCase):
    def test_html_escapes_untrusted_names_and_messages(self):
        report = {
            'scan_root': '</code><script>alert(1)</script>',
            'resources_scanned': 1,
            'resource_names': ['<svg/onload=alert(1)>'],
            'summary': {'error': 1, 'warning': 0, 'info': 0},
            'dependency_edges': [{'resource': '<b>', 'dependency': '<img src=x>', 'status': 'missing'}],
            'findings': [{'severity': 'error', 'code': 'XSS', 'resource': 'bad<script>',
                          'file': 'bad.html', 'line': 1, 'message': '<script>alert(1)</script>'}]
        }
        output = render_html(report)
        self.assertNotIn('<script>', output)
        self.assertNotIn('<img src=x>', output)
        self.assertIn('&lt;script&gt;', output)
        self.assertIn('&lt;svg/onload=alert(1)&gt;', output)

    def test_html_empty_state(self):
        output = render_html({'scan_root': '/tmp', 'resources_scanned': 0,
                              'resource_names': [], 'summary': {'error': 0, 'warning': 0, 'info': 0},
                              'dependency_edges': [], 'findings': []})
        self.assertIn('No findings', output)
        self.assertIn('No dependencies', output)

    def test_dot_escapes_quotes_and_line_breaks(self):
        output = render_dot({'resource_names': ['weird"name'],
                             'dependency_edges': [{'resource': 'weird"name',
                                                   'dependency': 'escape\nnext', 'status': 'missing'}]})
        self.assertIn('"weird\\"name"', output)
        self.assertIn('"escape\\nnext"', output)
        self.assertIn('style=dashed', output)
        self.assertNotIn('escape\nnext', output)

    def test_dot_resolves_provided_dependencies(self):
        output = render_dot({'resource_names': ['replacement', 'consumer'],
                             'dependency_edges': [{'resource': 'consumer',
                                                   'dependency': 'oldname', 'status': 'provided',
                                                   'resolved_to': 'replacement'}]})
        self.assertIn('"consumer" -> "replacement" [label="oldname"]', output)
        self.assertNotIn('"consumer" -> "oldname"', output)


class LuaAuditTests(unittest.TestCase):
    def test_flags_risky_dynamic_functions(self):
        results = scan_lua('loadstring("return 1")\nload("return 1")\nos.execute("x")\nio.popen("x")\n')
        self.assertEqual([f.code for f in results].count('LUA_DYNAMIC_EXEC'), 2)
        self.assertEqual([f.code for f in results].count('LUA_OS_COMMAND'), 2)

    def test_does_not_flag_comments_or_string_literals(self):
        source = '''-- loadstring('oops')
--[[ os.execute('nope') ]]
local x = "io.popen('bad')"
print([[load('bad')]])
'''
        self.assertEqual(scan_lua(source), [])

    def test_does_not_flag_definitions_or_member_calls(self):
        source = 'function load(code) return code end\nlocal function loadstring(x) end\nobj:load("x")\nt.loadstring("x")\n'
        self.assertEqual(scan_lua(source), [])

    def test_deduplicates_same_kind_on_same_line(self):
        results = scan_lua('load("x"); load("y")\n')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].line, 1)


class NuiTests(unittest.TestCase):
    def test_local_html_links(self):
        html = '''<script src="./js/app.js?hash=1"></script>
<link rel="stylesheet" href="styles/site.css">
<img src="/images/logo.png">
<script src="https://cdn.example.com/a.js"></script>
<a href="unused.html">ignored</a>
'''
        paths = referenced_files(html, 'ui/index.html')
        self.assertEqual(paths, {'ui/js/app.js', 'ui/styles/site.css', 'images/logo.png'})

    def test_ignore_url_and_escaping_outside_resource(self):
        html = '<script src="../../../etc/passwd"></script><script src="data:text/javascript,x"></script>'
        self.assertEqual(referenced_files(html, 'ui/index.html'), set())


class AnalyzerV020Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def resource(self, name: str, manifest: str = BASE, files: dict[str, str] | None = None) -> Path:
        res = self.root / name
        res.mkdir(exist_ok=True)
        (res / 'fxmanifest.lua').write_text(manifest, encoding='utf-8')
        for name, content in (files or {}).items():
            file = res / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(content, encoding='utf-8')
        return res

    def test_script_audit_only_if_opted_in(self):
        self.resource('a', BASE + "client_script 'client.lua'\n", {'client.lua': 'os.execute("bad")'})
        self.assertNotIn('LUA_OS_COMMAND', [f['code'] for f in Analyzer(self.root).run()['findings']])
        self.assertIn('LUA_OS_COMMAND', [f['code'] for f in Analyzer(self.root, audit_lua=True).run()['findings']])

    def test_report_file_points_to_lua_line(self):
        self.resource('a', BASE + "server_script 'main.lua'\n", {'main.lua': '-- safe\nload("return 1")'})
        findings = Analyzer(self.root, audit_lua=True).run()['findings']
        issue = next(f for f in findings if f['code'] == 'LUA_DYNAMIC_EXEC')
        self.assertEqual(issue['line'], 2)
        self.assertEqual(issue['file'], 'a/main.lua')

    def test_html_asset_missing_and_not_packed(self):
        self.resource('a', BASE + "ui_page 'html/index.html'\nfiles {'html/index.html'}\n",
                      {'html/index.html': '<script src="js/main.js"></script><img src="img/missing.png">',
                       'html/js/main.js': 'console.log(1)'})
        findings = [f['code'] for f in Analyzer(self.root).run()['findings']]
        self.assertIn('NUI_ASSET_NOT_PACKED', findings)
        self.assertIn('NUI_ASSET_MISSING', findings)
        self.assertNotIn('UI_NOT_PACKED', findings)

    def test_html_assets_in_glob_no_warning(self):
        self.resource('a', BASE + "ui_page 'html/index.html'\nfiles {'html/**/*'}\n",
                      {'html/index.html': '<script src="assets/main.js"></script>',
                       'html/assets/main.js': 'console.log(1)'})
        findings = [f['code'] for f in Analyzer(self.root).run()['findings']]
        self.assertNotIn('UI_NOT_PACKED', findings)
        self.assertNotIn('NUI_ASSET_NOT_PACKED', findings)

    def test_dependency_alias_resolved_in_json(self):
        self.resource('replacement', BASE + "provide 'oldname'\n")
        self.resource('consumer', BASE + "dependency 'oldname'\n")
        report = Analyzer(self.root).run()
        edge = next(e for e in report['dependency_edges'] if e['resource'] == 'consumer')
        self.assertEqual(edge['resolved_to'], 'replacement')
        self.assertEqual(edge['status'], 'provided')
        self.assertEqual(report['schema_version'], '1.2')

    def test_cli_generates_html_report(self):
        self.resource('a')
        dest = self.root / 'report.html'
        with contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.root), '--format', 'html', '--output', str(dest)])
        self.assertEqual(code, 0)
        self.assertIn('<!DOCTYPE html>', dest.read_text(encoding='utf-8'))
        self.assertIn('FiveM Resource Analyzer', dest.read_text(encoding='utf-8'))

    def test_cli_generates_dot_report(self):
        self.resource('a', BASE + "dependency 'b'\n")
        self.resource('b')
        dest = self.root / 'dependency.dot'
        with contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.root), '--format', 'dot', '--output', str(dest)])
        self.assertEqual(code, 0)
        self.assertIn('"a" -> "b"', dest.read_text(encoding='utf-8'))

    def test_cli_audit_lua_warns_and_strict_exits_one(self):
        self.resource('a', BASE + "client_script 'main.lua'\n", {'main.lua': 'loadstring("some code")'})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main([str(self.root), '--audit-lua', '--strict'])
        self.assertEqual(code, 1)

    def test_read_only_does_not_change_source_files(self):
        res = self.resource('a', BASE + "client_script 'main.lua'\n", {'main.lua': 'load("x")'})
        before = (res / 'main.lua').read_bytes()
        Analyzer(self.root, audit_lua=True).run()
        self.assertEqual(before, (res / 'main.lua').read_bytes())


if __name__ == '__main__':
    unittest.main()
