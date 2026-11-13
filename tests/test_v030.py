"""v0.3.0 regression tests for server.cfg, offline UI, Lua heuristics and privacy."""
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
from viento_resource_analyzer.cfg_audit import CfgParser, split_command
from viento_resource_analyzer.cli import main
from viento_resource_analyzer.html_report import render_html
from viento_resource_analyzer.lua_audit import scan_lua
from viento_resource_analyzer.performance import scan_performance

BASE = "fx_version 'cerulean'\ngame 'gta5'\n"


class ConfigLexerTests(unittest.TestCase):
    def test_quoted_and_comment(self):
        self.assertEqual(split_command('  ensure "my resource"  # comment'), ['ensure', 'my resource'])

    def test_windows_backslash_path(self):
        self.assertEqual(split_command(r'exec configs\sub.cfg'), ['exec', r'configs\sub.cfg'])

    def test_literal_hash_inside_word(self):
        self.assertEqual(split_command('sets name foo#bar # comment'), ['sets', 'name', 'foo#bar'])

    def test_empty_and_unbalanced_quote(self):
        self.assertEqual(split_command(' # hello'), [])
        self.assertEqual(split_command('exec "unfinished'), [])


class LuaSignalTests(unittest.TestCase):
    def test_security_signals_detect_direct_calls(self):
        signals = scan_lua('PerformHttpRequest("https://example.org", cb)\n'
                           'ExecuteCommand("say hello")\nSaveResourceFile("a", "b", 0)\n')
        self.assertEqual([x.code for x in signals],
                         ['LUA_EXTERNAL_HTTP', 'LUA_SERVER_COMMAND', 'LUA_RESOURCE_WRITE'])

    def test_security_ignores_comments_strings_methods_definitions(self):
        signals = scan_lua('-- PerformHttpRequest("evil")\n'
                           'local s = "ExecuteCommand(1)"\n'
                           'obj:SaveResourceFile("x")\n'
                           'function ExecuteCommand(x) end\n')
        self.assertEqual(signals, [])

    def test_performance_detects_simple_busy_loop(self):
        signals = scan_performance('while true do\n  doWork()\nend\n')
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].code, 'LUA_POSSIBLE_BUSY_LOOP')
        self.assertEqual(signals[0].line, 1)

    def test_performance_ignores_wait_and_comments(self):
        self.assertFalse(scan_performance('while true do Wait(0) end\n'
                                          'while true do Citizen.Wait(300) end\n'
                                          '-- while true do end\n'))

    def test_performance_avoids_nested_control_flow(self):
        self.assertFalse(scan_performance('while true do if x then work() end end'))

    def test_performance_ignores_string(self):
        self.assertFalse(scan_performance('print("while true do end")'))


class ConfigIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.resources = self.base / 'resources'
        self.resources.mkdir()
        self.cfg = self.base / 'server.cfg'

    def tearDown(self):
        self.tmp.cleanup()

    def res(self, name: str, *, dep: str | None = None, category: str = '',
            extra_manifest: str = '', files: dict[str, str] | None = None) -> Path:
        path = self.resources / category / name
        path.mkdir(parents=True, exist_ok=True)
        (path / 'fxmanifest.lua').write_text(BASE + (f"dependency '{dep}'\n" if dep else '')
                                             + extra_manifest, encoding='utf-8')
        for rel, data in (files or {}).items():
            file = path / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(data, encoding='utf-8')
        return path

    def report(self, **kwargs):
        return Analyzer(self.resources, server_cfg=self.cfg, **kwargs).run()

    def findings(self, **kwargs):
        return self.report(**kwargs)['findings']

    def test_nested_exec_and_order(self):
        self.res('base')
        self.res('app', dep='base')
        folder = self.base / 'config'
        folder.mkdir()
        (folder / 'more.cfg').write_text('ensure base\n')
        self.cfg.write_text('ensure app\nexec config/more.cfg\n')
        result = self.report()
        self.assertEqual([x['target'] for x in result['startup_order']], ['app', 'base'])
        self.assertEqual(result['cfg_files_scanned'], 2)
        self.assertIn('CFG_DEP_ORDER', [f['code'] for f in result['findings']])
        issue = next(f for f in result['findings'] if f['code'] == 'CFG_DEP_ORDER')
        self.assertEqual((issue['file'], issue['line']), ('server.cfg', 1))

    def test_correct_order_has_no_order_warning(self):
        self.res('base')
        self.res('app', dep='base')
        self.cfg.write_text('ensure base\nensure app\n')
        self.assertNotIn('CFG_DEP_ORDER', [f['code'] for f in self.findings()])

    def test_missing_explicit_dep_is_info_not_error(self):
        self.res('base')
        self.res('app', dep='base')
        self.cfg.write_text('ensure app\n')
        items = self.findings()
        issue = next(f for f in items if f['code'] == 'CFG_DEP_NOT_EXPLICIT')
        self.assertEqual(issue['severity'], 'info')

    def test_provide_dependency_order(self):
        self.res('replacement', extra_manifest="provide 'oldbase'\n")
        self.res('app', dep='oldbase')
        self.cfg.write_text('ensure app\nensure replacement\n')
        self.assertIn('CFG_DEP_ORDER', [f['code'] for f in self.findings()])

    def test_category_and_nested_category(self):
        self.res('a', category='[standalone]')
        self.res('b', category='[standalone]/[nested]')
        self.cfg.write_text('ensure [standalone]\n')
        timeline = self.report()['startup_order']
        self.assertEqual(timeline[0]['expanded_resources'], ['a', 'b'])

    def test_alias_expands_to_real_resource(self):
        self.res('replacement', extra_manifest="provide 'legacy'\n")
        self.cfg.write_text('ensure legacy\n')
        self.assertEqual(self.report()['startup_order'][0]['expanded_resources'], ['replacement'])

    def test_missing_resource_is_non_fatal(self):
        self.res('a')
        self.cfg.write_text('ensure externalname\n')
        issue = next(f for f in self.findings() if f['code'] == 'CFG_RESOURCE_NOT_IN_SCAN')
        self.assertEqual(issue['severity'], 'info')
        self.assertNotIn('CFG_RESOURCE_NOT_IN_SCAN',
                         [f['code'] for f in self.findings(available={'externalname'})])

    def test_missing_category_is_informational(self):
        self.cfg.write_text('ensure [cars]\n')
        self.assertIn('CFG_CATEGORY_NOT_IN_SCAN', [f['code'] for f in self.findings()])

    def test_duplicate_ensure_warns(self):
        self.res('a')
        self.cfg.write_text('ensure a\nensure a\n')
        self.assertIn('CFG_REPEATED_ENSURE', [f['code'] for f in self.findings()])

    def test_stop_then_start(self):
        self.res('base')
        self.res('app', dep='base')
        self.cfg.write_text('ensure base\nstop base\nensure app\n')
        self.assertIn('CFG_DEP_ORDER', [f['code'] for f in self.findings()])

    def test_exec_missing_file(self):
        self.cfg.write_text('exec doesnt-exist.cfg\n')
        self.assertIn('CFG_EXEC_NOT_FOUND', [f['code'] for f in self.findings()])

    def test_exec_cycle(self):
        self.cfg.write_text('exec next.cfg\n')
        (self.base / 'next.cfg').write_text('exec server.cfg\n')
        self.assertIn('CFG_EXEC_CYCLE', [f['code'] for f in self.findings()])

    def test_exec_traversal_blocked(self):
        self.cfg.write_text('exec ../outside.cfg\n')
        self.assertIn('CFG_EXEC_UNRESOLVED', [f['code'] for f in self.findings()])

    def test_exec_resource_local(self):
        self.res('a', files={'config/extra.cfg': 'ensure a\n'})
        self.cfg.write_text('exec @a/config/extra.cfg\n')
        self.assertEqual([x['target'] for x in self.report()['startup_order']], ['a'])

    def test_exec_resource_traversal(self):
        self.res('a')
        self.cfg.write_text('exec @a/../../server.cfg\n')
        self.assertIn('CFG_EXEC_UNRESOLVED', [f['code'] for f in self.findings()])

    def test_secret_is_not_in_json_or_html(self):
        self.cfg.write_text('set mysql_connection_string "mysql://secret:PASS-DO-NOT-LEAK@db"\n'
                            'setr sample_api_key "SENSITIVE_VALUE_123"\n'
                            'sets server_token "PUBLIC_NOT_OK_777"\n')
        report = self.report()
        as_json = json.dumps(report)
        html = render_html(report)
        for secret in ('PASS-DO-NOT-LEAK', 'SENSITIVE_VALUE_123', 'PUBLIC_NOT_OK_777'):
            self.assertNotIn(secret, as_json)
            self.assertNotIn(secret, html)
        self.assertEqual([f['code'] for f in report['findings']].count('CFG_SECRET_EXPOSURE'), 2)

    def test_scripthook_warning(self):
        self.cfg.write_text('sv_scriptHookAllowed 1\n')
        self.assertIn('CFG_SCRIPTHOOK_ENABLED', [f['code'] for f in self.findings()])

    def test_invalid_cli_config_exit_code(self):
        self.res('a')
        with contextlib.redirect_stderr(io.StringIO()):
            ret = main([str(self.resources), '--server-cfg', str(self.base / 'not_found.cfg')])
        self.assertEqual(ret, 2)

    def test_server_cfg_does_not_mutate_resources(self):
        file = self.res('a', files={'main.lua': 'print("original")'}) / 'main.lua'
        self.cfg.write_text('ensure a\n')
        old = file.read_bytes()
        self.report(audit_lua=True, performance_hints=True)
        self.assertEqual(old, file.read_bytes())

    def test_cli_combined_flags_html(self):
        self.res('a', extra_manifest="server_script 'main.lua'\n",
                 files={'main.lua': 'while true do work() end\n'})
        self.cfg.write_text('ensure a\n')
        dest = self.base / 'report.html'
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.resources), '--server-cfg', str(self.cfg),
                                   '--performance-hints', '--format', 'html', '--output', str(dest)]), 0)
        body = dest.read_text(encoding='utf-8')
        self.assertIn('LUA_POSSIBLE_BUSY_LOOP', body)
        self.assertIn('Startup order', body)
        self.assertIn('finding-search', body)

    def test_cli_json_with_startup_details(self):
        self.res('a')
        self.cfg.write_text('ensure a\n')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([str(self.resources), '--server-cfg', str(self.cfg), '--format', 'json']), 0)
        parsed = json.loads(output.getvalue())
        self.assertEqual(parsed['schema_version'], '1.3')
        self.assertEqual(parsed['startup_order'][0]['target'], 'a')

    def test_run_twice_does_not_keep_old_cfg_commands(self):
        self.res('a')
        self.cfg.write_text('ensure a\n')
        analyzer = Analyzer(self.resources, server_cfg=self.cfg)
        self.assertEqual(len(analyzer.run()['startup_order']), 1)
        self.assertEqual(len(analyzer.run()['startup_order']), 1)


class DashboardTests(unittest.TestCase):
    def test_dashboard_preserves_safe_escaping_with_js(self):
        bad = 'x</script><script>alert("PWN")</script>'
        report = {'scan_root': bad, 'resources_scanned': 1, 'resource_names': [bad],
                  'summary': {'error': 1, 'warning': 0, 'info': 0},
                  'dependency_edges': [], 'startup_order': [{'command': 'ensure', 'target': bad,
                      'expanded_resources': [bad], 'file': 'server.cfg', 'line': 1}],
                  'findings': [{'severity': 'error', 'code': 'BAD', 'resource': bad,
                                'file': 'bad', 'line': 1, 'message': bad}]}
        html = render_html(report)
        self.assertNotIn(bad, html)
        self.assertIn('&lt;/script&gt;', html)
        self.assertIn('type="text/javascript"', html)
        self.assertIn('textContent', html)
        self.assertNotIn('innerHTML', html)
        self.assertIn('Content-Security-Policy', html)

    def test_dashboard_no_config(self):
        html = render_html({'scan_root': 'dummy', 'resources_scanned': 0,
                            'resource_names': [], 'summary': {'error': 0, 'warning': 0, 'info': 0},
                            'findings': [], 'dependency_edges': []})
        self.assertIn('No server.cfg supplied', html)
        self.assertIn('No explicit startup commands', html)


if __name__ == '__main__':
    unittest.main()
