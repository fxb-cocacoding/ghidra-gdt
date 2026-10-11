import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from gdt_pipeline.ghidra import build_set, installation_info, run_headless
from gdt_pipeline.layouts import parse_llvm_types
from test_layouts import DUMP


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_tracks_jar_and_language_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'support').mkdir()
            (root / 'support/analyzeHeadless').write_text('#!/bin/sh\n')
            (root / 'Ghidra').mkdir()
            (root / 'Ghidra/application.properties').write_text(
                'application.version=12.3\napplication.release.name=DEV\n')
            jar = root / 'Ghidra/test.jar'
            jar.write_bytes(b'one')
            language = root / 'Ghidra/x86.ldefs'
            language.write_bytes(b'language')
            first = installation_info(root)
            self.assertEqual(first['version_release'], '12.3-DEV')
            self.assertEqual(first['fingerprint'],
                             '10d58f9fa79d920f1c01d53e94a73e6209dd616951b8bfe1d367cdbc3cbb8530')
            self.assertEqual(first['fingerprint_files'], 3)
            jar.write_bytes(b'two')
            second = installation_info(root)
            self.assertNotEqual(first['fingerprint'], second['fingerprint'])
            language.write_bytes(b'other')
            self.assertNotEqual(second['fingerprint'], installation_info(root)['fingerprint'])


class PublicationTests(unittest.TestCase):
    def test_zero_headless_exit_without_results_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / '.cache/run'
            with patch('gdt_pipeline.ghidra.subprocess.run', return_value=SimpleNamespace(returncode=0)) as launch:
                with self.assertRaisesRegex(ValueError, 'Ghidra export failed'):
                    run_headless('/test/ghidra', [], work)
            project = Path(launch.call_args.args[0][1])
            self.assertFalse(any(part.startswith('.') for part in project.parts))
            self.assertFalse(project.exists())

    def test_existing_completed_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'archives/12.3-DEV/fingerprint/selection'
            destination.mkdir(parents=True)
            sentinel = destination / 'sources.json'
            sentinel.write_text('original')
            with patch('gdt_pipeline.ghidra.check_tools'):
                with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
                    build_set([], '/ghidra', SimpleNamespace(root=root / 'cache'), root / 'archives',
                              'selection', {}, {'version_release': '12.3-DEV', 'fingerprint': 'fingerprint'})
            self.assertEqual(sentinel.read_text(), 'original')

    def test_failed_llvm_validation_never_publishes(self):
        from test_layouts import DUMP
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = {'module': 'test.dll', 'architecture': 'x64', 'pdb': {
                'filename': 'test.pdb', 'guid': '00000000-0000-0000-0000-000000000001',
                'age': 1, 'sha256': 'a' * 64, 'path': '/test.pdb'}}

            def dump(*args, stdout, **kwargs):
                stdout.write(DUMP)
                return SimpleNamespace(returncode=0)

            def export(ghidra, jobs, work):
                for job in jobs:
                    Path(job['layout']).write_text('T\t_TEST\t99\n')
                return [{}]

            with patch('gdt_pipeline.ghidra.check_tools'), \
                 patch('gdt_pipeline.ghidra.subprocess.run', side_effect=dump), \
                 patch('gdt_pipeline.ghidra.run_headless', side_effect=export):
                with self.assertRaisesRegex(ValueError, 'LLVM layout verification failed'):
                    build_set([module], '/ghidra', SimpleNamespace(root=root / 'cache'),
                              root / 'archives', 'selection', {},
                              {'version_release': '12.3-DEV', 'fingerprint': 'fingerprint'})
            self.assertFalse((root / 'archives/12.3-DEV/fingerprint/selection').exists())


class BuildSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = SimpleNamespace(root=self.root / 'cache')
        self.runs = self.cache.root / 'runs'
        self.info = {'version_release': '12.3-DEV', 'fingerprint': 'fingerprint'}
        self.destination = self.root / 'archives/12.3-DEV/fingerprint/selection'
        self.module = {'module': 'test.dll', 'architecture': 'x64', 'pdb': {
            'filename': 'test.pdb', 'guid': '00000000-0000-0000-0000-000000000001',
            'age': 1, 'sha256': 'a' * 64, 'path': '/test.pdb'}}
        self.dumps = [DUMP]
        self.layout = 'T\t_TEST\t4\nF\t_TEST\tFlags\t0\t3\t2\n'
        self.addCleanup(patch.stopall)
        patch('gdt_pipeline.ghidra.check_tools').start()
        self.dump = patch('gdt_pipeline.ghidra.subprocess.run', side_effect=self.write_dump).start()
        self.export = patch('gdt_pipeline.ghidra.run_headless', side_effect=self.write_export).start()

    def write_dump(self, command, stdout, **kwargs):
        stdout.write(self.dumps.pop(0))
        return SimpleNamespace(returncode=0)

    def write_export(self, ghidra, jobs, work):
        work.mkdir()
        (work / 'headless.log').write_text('export diagnostics')
        reports = []
        for job in jobs:
            archive = Path(job['output'])
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(b'archive')
            Path(job['layout']).write_text(self.layout)
            reports.append({'types_reopened': 1})
        return reports

    def build(self, modules=None):
        return build_set([self.module] if modules is None else modules, '/ghidra', self.cache,
                         self.root / 'archives', 'selection', {}, self.info)

    def retained_work(self):
        runs = list(self.runs.iterdir())
        self.assertEqual(len(runs), 1)
        self.assertEqual((runs[0] / '0.pdb-types.txt').read_text(), DUMP)
        self.assertFalse(self.destination.exists())
        return runs[0]

    def test_successful_publication_removes_work_and_preserves_cached_inputs(self):
        cached_pdb = self.cache.root / 'symbols/test.pdb'
        cached_pdb.parent.mkdir(parents=True)
        cached_pdb.write_bytes(b'cached PDB')
        prior_work = self.runs / 'earlier-failure'
        prior_work.mkdir(parents=True)
        (prior_work / 'headless.log').write_text('prior diagnostics')

        destination, verification = self.build()

        self.assertEqual(destination, self.destination)
        self.assertEqual(list(self.runs.iterdir()), [prior_work])
        self.assertEqual(cached_pdb.read_bytes(), b'cached PDB')
        self.assertEqual((prior_work / 'headless.log').read_text(), 'prior diagnostics')
        self.assertEqual(verification['modules'][0]['status'], 'verified')
        self.assertEqual(json.loads((destination / 'verification.json').read_text()), verification)
        self.assertEqual(json.loads((destination / 'sources.json').read_text())['status'], 'complete')
        checksums = dict(line.split('  ', 1)[::-1]
                         for line in (destination / 'SHA256SUMS').read_text().splitlines())
        expected_files = {'sources.json', 'verification.json',
                          'x64/test_dll_000000000000000000000000000000011.gdt'}
        self.assertEqual(set(checksums), expected_files)
        for name, checksum in checksums.items():
            self.assertEqual(checksum, hashlib.sha256((destination / name).read_bytes()).hexdigest())

    def test_cleanup_error_does_not_fail_published_set(self):
        rmtree = shutil.rmtree
        cleanup_attempts = []

        def cleanup(path, *args, **kwargs):
            if Path(path).parent == self.runs:
                self.assertTrue((self.destination / 'SHA256SUMS').is_file())
                cleanup_attempts.append(Path(path))
                raise OSError('work is temporarily busy')
            return rmtree(path, *args, **kwargs)

        with patch('gdt_pipeline.ghidra.shutil.rmtree', side_effect=cleanup):
            destination, verification = self.build()

        self.assertEqual(destination, self.destination)
        self.assertEqual(verification['modules'][0]['status'], 'verified')
        self.assertEqual(len(cleanup_attempts), 1)
        self.assertEqual((cleanup_attempts[0] / '0.pdb-types.txt').read_text(), DUMP)

    def test_validation_failure_retains_diagnostics(self):
        self.layout = 'T\t_TEST\t99\n'
        with self.assertRaisesRegex(ValueError, 'LLVM layout verification failed'):
            self.build()
        work = self.retained_work()
        self.assertEqual((work / 'headless/headless.log').read_text(), 'export diagnostics')
        report = json.loads((work / 'verification-failure.json').read_text())
        self.assertTrue(report[0]['llvm']['failures'])

    def test_interrupted_export_retains_diagnostics(self):
        def interrupt(*args):
            self.write_export(*args)
            raise KeyboardInterrupt

        self.export.side_effect = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.build()
        work = self.retained_work()
        self.assertEqual((work / 'headless/headless.log').read_text(), 'export diagnostics')

    def test_failed_publication_retains_diagnostics(self):
        with patch('gdt_pipeline.ghidra.Path.rename', side_effect=OSError('publication failed')):
            with self.assertRaisesRegex(OSError, 'publication failed'):
                self.build()
        self.retained_work()

    def test_each_llvm_dump_is_parsed_once_including_omitted_modules(self):
        self.dumps.append('Showing 0 records')
        empty = dict(self.module, module='empty.dll')
        with patch('gdt_pipeline.ghidra.parse_llvm_types', wraps=parse_llvm_types) as parse, \
             patch('gdt_pipeline.layouts.parse_llvm_types', new=parse):
            _, verification = self.build([self.module, empty])
        self.assertEqual(parse.call_count, 2)
        self.assertEqual([m['status'] for m in verification['modules']], ['verified', 'omitted'])
        self.assertEqual(verification['modules'][0]['llvm']['bitfields_checked'], 1)


if __name__ == '__main__':
    unittest.main()
