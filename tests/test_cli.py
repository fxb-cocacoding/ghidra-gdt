import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CliTests(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(ROOT / 'build.py'), *map(str, args)],
                              text=True, capture_output=True, cwd=cwd)

    def test_ghidra_required_for_build(self):
        result = self.run_cli('--manifest', ROOT / 'windows_10_22h2/sources.json')
        self.assertEqual(result.returncode, 2)
        self.assertIn('--ghidra', result.stderr)

    def test_offline_missing_pdb_writes_failures_without_ghidra(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_cli('--manifest', ROOT / 'windows_10_22h2/sources.json',
                                  '--download-only', '--offline', cwd=root)
            self.assertEqual(result.returncode, 1, result.stderr)
            manifests = list((root / 'sources').glob('*/sources.json'))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text())
            self.assertEqual(len(manifest['modules']), 4)
            self.assertTrue(all(m['status'] == 'failed' for m in manifest['modules']))

    def test_pdb_and_cache_ignored_but_gdt_and_manifest_trackable(self):
        ignored = ['.cache/ghidra-gdt/a', 'foo/test.pDb', 'nested/UPPER.PDB', 'test.pdb']
        result = subprocess.run(['git', 'check-ignore', '--stdin'], cwd=ROOT,
                                input='\n'.join(ignored + ['archives/a.gdt', 'sources/a/sources.json']),
                                text=True, capture_output=True)
        self.assertEqual(set(result.stdout.splitlines()), set(ignored))

    def test_invalid_local_binary_is_recorded_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'broken.dll'
            binary.write_bytes(b'not a PE')
            result = self.run_cli('--binary', binary, '--download-only', '--offline',
                                  cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn('Traceback', result.stderr)
            record = json.loads(next((root / 'sources').glob('*/sources.json')).read_text())
            self.assertEqual(record['modules'][0]['status'], 'failed')

    def test_source_validation_failure_is_not_retried_as_success(self):
        from unittest.mock import patch
        from gdt_pipeline.cli import main
        module = json.loads((ROOT / 'windows_10_22h2/sources.json').read_text())['modules'][0]
        module.update(status='failed', error='binary SHA-256 mismatch')
        with tempfile.TemporaryDirectory() as directory:
            with patch('gdt_pipeline.cli.manifest_modules', return_value=[module]), \
                 patch('gdt_pipeline.cli.Path.cwd', return_value=Path(directory)), \
                 patch('gdt_pipeline.cli.ensure_pdb', return_value=module) as acquire:
                code = main(['--manifest', 'unused.json', '--download-only'])
            self.assertEqual(code, 1)
            acquire.assert_not_called()

    def test_help_keeps_options_focused(self):
        result = self.run_cli('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('--list-builds', result.stdout)
        for option in ('--cache-dir', '--output-dir', '--sources-dir', '--iso', '--image'):
            self.assertNotIn(option, result.stdout)

    def test_removed_list_versions_alias_is_rejected(self):
        result = self.run_cli('--winbindex', 'ntdll.dll', '--list-versions', '--offline')
        self.assertEqual(result.returncode, 2)
        self.assertIn('unrecognized arguments: --list-versions', result.stderr)

    def test_list_builds_needs_no_ghidra_or_binary_download(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        from gdt_pipeline.cli import main
        candidate = {'module': 'ntdll.dll', 'architecture': 'x64', 'binary_version': '10.0.1.2',
                     'binary_sha256': 'a' * 64, 'provenance': {'windows_versions': ['22H2']}}
        output = StringIO()
        with patch('gdt_pipeline.cli.winbindex_candidates', return_value=[candidate]), \
             patch('gdt_pipeline.cli.acquire_winbindex') as download, redirect_stdout(output):
            code = main(['--winbindex', 'ntdll.dll', '--list-builds'])
        self.assertEqual(code, 0)
        self.assertIn('10.0.1.2', output.getvalue())
        self.assertIn('22H2', output.getvalue())
        download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
