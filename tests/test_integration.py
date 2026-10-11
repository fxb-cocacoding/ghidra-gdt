"""Opt-in real-input tests. See README for GDT_TEST_* environment variables."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from gdt_pipeline.ghidra import run_headless
from gdt_pipeline.layouts import compare_layouts, parse_llvm_types

ROOT = Path(__file__).resolve().parent.parent
INSTALLATIONS = [Path(p) for p in os.environ.get('GDT_TEST_GHIDRA', '').split(os.pathsep) if p]


@unittest.skipUnless(INSTALLATIONS, 'Set GDT_TEST_GHIDRA to run real Ghidra integrations')
class RealPipelineTests(unittest.TestCase):
    def setUp(self):
        # Cache can be shared across test runs; every input is still verified on reuse.
        self.cache = Path(os.environ.get('GDT_TEST_CACHE', ROOT / '.cache/ghidra-gdt')).resolve()
        parent = self.cache / 'integration'
        parent.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=parent))

    def cli(self, *arguments, cwd=None):
        cwd = cwd or self.work
        (cwd / '.cache').mkdir(parents=True, exist_ok=True)
        link = cwd / '.cache/ghidra-gdt'
        if not link.exists():
            link.symlink_to(self.cache, target_is_directory=True)
        command = [sys.executable, str(ROOT / 'build.py'), *map(str, arguments)]
        result = subprocess.run(command, text=True, capture_output=True, cwd=cwd)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def build(self, source, ghidra, index):
        cwd = self.work / f'build-{index}'
        output = cwd / 'archives'
        self.cli(*source, '--ghidra', ghidra, cwd=cwd)
        files = list(output.glob('*/*/*/verification.json'))
        self.assertEqual(len(files), 1)
        check = subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=files[0].parent,
                               text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
        report = json.loads(files[0].read_text())
        for module in report['modules']:
            if module['status'] == 'verified':
                self.assertFalse(module['llvm']['failures'])
                self.assertGreater(module['ghidra']['types_reopened'], 0)
        return report, files[0].parent

    def test_manifest_without_binaries_and_audited_archives(self):
        legacy = json.loads((ROOT / 'windows_10_22h2/sources.json').read_text())
        for index, ghidra in enumerate(INSTALLATIONS):
            with self.subTest(ghidra=ghidra):
                report, output = self.build(['--manifest', ROOT / 'windows_10_22h2/sources.json'], ghidra, index)
                self.assertEqual(len(report['modules']), 4)
                jobs = []
                version = report['ghidra']['version']
                for number, module in enumerate(legacy['modules']):
                    old = next((a for a in module['archives'] if a['ghidra_version'].startswith(version + ' ')), None)
                    self.assertIsNotNone(old, f'No audited archive for {version}')
                    jobs.append({'module': module['module'], 'architecture': module['architecture'],
                                 'output': str(ROOT / old['path']), 'audit_only': True,
                                 'layout': str(self.work / f'old-{index}-{number}.tsv')})
                run_headless(ghidra, jobs, self.work / f'audit-{index}')
                for job, module in zip(jobs, legacy['modules']):
                    pdb = module['pdb']
                    key = pdb['guid'].replace('-', '').upper() + format(pdb['age'], 'X')
                    pdb_path = self.cache / 'symbols' / pdb['filename'] / key / pdb['filename']
                    raw = subprocess.check_output(['llvm-pdbutil', 'dump', '-types', str(pdb_path)], text=True)
                    old_comparison = compare_layouts(parse_llvm_types(raw), Path(job['layout']).read_text())
                    self.assertFalse(old_comparison['failures'])
                    new = next(m for m in report['modules'] if m['module'] == module['module'] and
                               m['architecture'] == module['architecture'])
                    for count in ('types_checked', 'fields_checked', 'bitfields_checked'):
                        self.assertEqual(new['llvm'][count], old_comparison[count])

    @unittest.skipUnless(os.environ.get('GDT_TEST_NETWORK') == '1', 'Set GDT_TEST_NETWORK=1 for Winbindex')
    def test_real_winbindex_selection(self):
        source = ['--winbindex', 'ntdll.dll', '--arch', 'x64', '--file-version', '10.0.26100.1']
        self.cli(*source, '--list-builds')
        self.cli(*source, '--download-only')
        manifests = list((self.work / 'sources').glob('*/sources.json'))
        self.assertEqual(len(manifests), 1)
        manifest = json.loads(manifests[0].read_text())
        self.assertEqual(manifest['modules'][0]['binary_sha256'],
                         '473a02e37fd071620029c844ed3df71646b18208d8806e33e00ddd72e908534f')
        for index, ghidra in enumerate(INSTALLATIONS):
            report, _ = self.build(['--manifest', manifests[0], '--offline'], ghidra, index)
            self.assertEqual(len(report['modules']), 1)
