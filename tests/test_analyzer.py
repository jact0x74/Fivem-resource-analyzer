from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from viento_resource_analyzer.analyzer import Analyzer
from viento_resource_analyzer.cli import main, render_text
from viento_resource_analyzer.manifest import parse_manifest, tokenize


class ManifestTests(unittest.TestCase):
    def test_comments_and_lua_long_strings(self):
        source = """-- fx_version 'bad'
--[=[\nserver_script 'bad.lua'\n]=]
fx_version 'cerulean'
games { 'gta5', 'rdr3' }
client_script 'foo--bar.lua'
server_script [[server.lua]]
"""
        parsed = parse_manifest(source)
        self.assertEqual(parsed.values('fx_version'), ['cerulean'])
        self.assertEqual(parsed.values('games'), ['gta5', 'rdr3'])
        self.assertEqual(parsed.values('server_script'), ['server.lua'])
        self.assertEqual(parsed.values('client_script'), ['foo--bar.lua'])

    def test_parentheses_and_data_file(self):
        source = """fx_version('cerulean')
game('gta5')
data_file 'HANDLING_FILE' 'data/handling.meta'
"""
        parsed = parse_manifest(source)
        self.assertIn(('data_file', 'data/handling.meta', 3), parsed.paths())
        self.assertEqual(parsed.values('game'), ['gta5'])

    def test_dynamic_expression_is_never_executed(self):
        source = "client_script loadfile('evil.lua')\n"
        manifest = parse_manifest(source)
        self.assertEqual(manifest.values('client_script'), [])
        self.assertEqual(manifest.dynamic_lines, [('client_script', 1)])

    def test_tokenizer_ignores_comment_metadata(self):
        toks = tokenize("-- server_script 'x'\nclient_script 'y'\n")
        self.assertEqual([t.value for t in toks if t.kind == 'ident'], ['client_script'])


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def res(self, name: str, manifest: str, files: list[str] | None = None,
            old: bool = False) -> Path:
        directory = self.root / '[category]' / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / ('__resource.lua' if old else 'fxmanifest.lua')).write_text(manifest, encoding='utf-8')
        for file in files or []:
            path = directory / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('test', encoding='utf-8')
        return directory

    def run_scan(self):
        return Analyzer(self.root).run()

    def codes(self, report):
        return [entry['code'] for entry in report['findings']]

    def test_empty_directory(self):
        report = self.run_scan()
        self.assertEqual(report['resources_scanned'], 0)
        self.assertEqual(report['summary']['error'], 0)

    def test_missing_scripts_and_good_glob(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\nclient_scripts { 'client/*.lua', 'missing.lua' }\n",
                 ['client/a.lua', 'client/b.lua'])
        report = self.run_scan()
        self.assertEqual(self.codes(report).count('PATH_NOT_FOUND'), 1)
        self.assertEqual(report['resources_scanned'], 1)

    def test_existing_resource_dependency(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\ndependency 'bar'\n")
        self.res('bar', "fx_version 'cerulean'\ngame 'gta5'\n")
        self.assertNotIn('DEP_NOT_IN_SCAN', self.codes(self.run_scan()))

    def test_unknown_dependency_is_warning(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\ndependencies {'ox_lib', '/onesync'}\n")
        report = self.run_scan()
        self.assertEqual(self.codes(report).count('DEP_NOT_IN_SCAN'), 1)
        report_available = Analyzer(self.root, {'ox_lib'}).run()
        self.assertNotIn('DEP_NOT_IN_SCAN', self.codes(report_available))

    def test_provide_alias(self):
        self.res('compat', "fx_version 'cerulean'\ngame 'gta5'\nprovide 'legacy'\n")
        self.res('consumer', "fx_version 'cerulean'\ngame 'gta5'\ndependency 'legacy'\n")
        self.assertNotIn('DEP_NOT_IN_SCAN', self.codes(self.run_scan()))

    def test_cycle(self):
        self.res('a', "fx_version 'cerulean'\ngame 'gta5'\ndependency 'b'\n")
        self.res('b', "fx_version 'cerulean'\ngame 'gta5'\ndependency 'a'\n")
        self.assertIn('DEPENDENCY_CYCLE', self.codes(self.run_scan()))

    def test_ui_page_not_packed(self):
        self.res('nui', "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/style.css'}\n",
                 ['html/index.html', 'html/style.css'])
        self.assertIn('UI_NOT_PACKED', self.codes(self.run_scan()))

    def test_ui_page_packed_by_glob(self):
        self.res('nui', "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/*.html'}\n",
                 ['html/index.html'])
        self.assertNotIn('UI_NOT_PACKED', self.codes(self.run_scan()))

    def test_external_script_and_remote_ui(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\nshared_script '@ox_lib/init.lua'\nui_page 'https://example.com/'\n")
        self.assertNotIn('PATH_NOT_FOUND', self.codes(self.run_scan()))

    def test_both_legacy_and_current(self):
        r = self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\n")
        (r / '__resource.lua').write_text('client_script "old.lua"')
        self.assertIn('BOTH_MANIFESTS', self.codes(self.run_scan()))

    def test_legacy_manifest(self):
        self.res('foo', "client_script 'main.lua'", ['main.lua'], old=True)
        self.assertIn('LEGACY_MANIFEST', self.codes(self.run_scan()))

    def test_duplicate_names(self):
        self.res('same', "fx_version 'cerulean'\ngame 'gta5'\n")
        dir2 = self.root / '[other]' / 'same'
        dir2.mkdir(parents=True)
        (dir2 / 'fxmanifest.lua').write_text("fx_version 'cerulean'\ngame 'gta5'\n")
        self.assertIn('DUPLICATE_RESOURCE', self.codes(self.run_scan()))

    def test_safe_escape_is_not_resolved(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\nclient_script '../secret.lua'\n")
        self.assertIn('PATH_NOT_FOUND', self.codes(self.run_scan()))

    def test_json_roundtrip_and_exit_codes(self):
        self.res('bad', "fx_version 'cerulean'\ngame 'gta5'\nclient_script 'missing.lua'\n")
        report = self.run_scan()
        self.assertEqual(json.loads(json.dumps(report))['summary']['error'], 1)
        self.assertIn('PATH_NOT_FOUND', render_text(report))
        self.assertEqual(main([str(self.root), '--format', 'json', '--output', str(self.root / 'out.json')]), 1)
        output = json.loads((self.root / 'out.json').read_text())
        self.assertEqual(output['resources_scanned'], 1)

    def test_symlink_skipped(self):
        self.res('foo', "fx_version 'cerulean'\ngame 'gta5'\n")
        target = self.root / 'elsewhere'
        target.mkdir()
        (target / 'fxmanifest.lua').write_text("fx_version 'cerulean'\ngame 'gta5'")
        try:
            (self.root / 'link').symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('OS cannot create symlinks')
        self.assertEqual(self.run_scan()['resources_scanned'], 2)


if __name__ == '__main__':
    unittest.main()
