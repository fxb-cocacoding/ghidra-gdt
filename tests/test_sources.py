import gzip
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gdt_pipeline import sources
from gdt_pipeline.cache import Cache, ensure_pdb
from test_identity import GUID, pdb_bytes, pe_bytes


class SourceTests(unittest.TestCase):
    def test_replayed_manifest_does_not_claim_historical_export_counts(self):
        root = Path(__file__).resolve().parent.parent
        original = root / 'windows_10_22h2/sources.json'
        for module in sources.manifest_modules(original):
            self.assertNotIn('type_entries', module)
            self.assertNotIn('archives', module)
            self.assertIn('manifest_path', module['provenance'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = Cache(self.root/'cache')

    def metadata(self):
        return {
            'aa'*32: {'fileInfo': {'machineType': 34404, 'version': '10.0.19041.1 (WinBuild.160101.0800)',
                                 'timestamp': 0x1234abcd, 'virtualSize': 0x12ab000}, 'windowsVersions': {'22H2': {}}},
            'bb'*32: {'fileInfo': {'machineType': 332, 'version': '10.0.19041.1',
                                 'timestamp': 1, 'virtualSize': 8192}},
            'cc'*32: {'fileInfo': {'machineType': 34404, 'version': '10.0.19041.1',
                                 'timestamp': 1, 'virtualSize': 12288}},
            'dd'*32: {'fileInfo': {'machineType': 34404, 'version': '10.0.19041.2'}},
        }

    def candidates(self):
        payload = gzip.compress(json.dumps(self.metadata()).encode())
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(payload)):
            return sources.winbindex_candidates('NTDLL.DLL', self.cache)

    def test_winbindex_reads_metadata_only_and_builds_exact_upstream_url(self):
        rows = self.candidates()
        self.assertEqual(len(rows), 4)
        row = next(row for row in rows if row['binary_sha256'] == 'aa'*32)
        self.assertEqual(row['binary_version'], '10.0.19041.1')
        self.assertEqual(row['architecture'], 'x64')
        self.assertEqual(row['download_url'],
            'https://msdl.microsoft.com/download/symbols/ntdll.dll/1234ABCD12ab000/ntdll.dll')
        self.assertNotIn('pdb', row)
        self.assertFalse((self.cache.root/'binaries').exists())
        self.assertEqual(sources.winbindex_candidates('ntdll.dll', Cache(self.cache.root, offline=True)), rows)

    def test_online_winbindex_lookup_refreshes_builds_and_offline_uses_latest_snapshot(self):
        first = self.candidates()
        metadata = self.metadata()
        metadata['ee'*32] = {'fileInfo': {'machineType': 34404, 'version': '10.0.19041.3',
                                        'timestamp': 2, 'virtualSize': 8192}}
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(gzip.compress(json.dumps(metadata).encode()))):
            second = sources.winbindex_candidates('ntdll.dll', self.cache)
        self.assertEqual(len(second), len(first)+1)
        with patch('gdt_pipeline.cache.urlopen', side_effect=AssertionError('network')):
            offline = sources.winbindex_candidates('ntdll.dll', Cache(self.cache.root, offline=True))
        self.assertEqual(offline, second)

    def test_failed_metadata_refresh_reports_failure_and_keeps_offline_snapshot(self):
        first = self.candidates()
        with patch('gdt_pipeline.cache.urlopen', side_effect=OSError('server unavailable')):
            with self.assertRaisesRegex(OSError, 'server unavailable'):
                sources.winbindex_candidates('ntdll.dll', self.cache)
        self.assertEqual(sources.winbindex_candidates('ntdll.dll', Cache(self.cache.root, offline=True)), first)

    def test_invalid_metadata_refresh_keeps_prior_verified_snapshot(self):
        first = self.candidates()
        invalid = gzip.compress(json.dumps({'invalid hash': {}}).encode())
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(invalid)):
            with self.assertRaisesRegex(ValueError, 'Invalid Winbindex metadata record'):
                sources.winbindex_candidates('ntdll.dll', self.cache)
        self.assertEqual(sources.winbindex_candidates('ntdll.dll', Cache(self.cache.root, offline=True)), first)

    def test_exact_selection_and_explicit_ambiguity(self):
        rows = self.candidates()
        with self.assertRaisesRegex(ValueError, '[Aa]mbiguous'):
            sources.select_winbindex(rows, architecture='x64', file_version='10.0.19041.1')
        selected = sources.select_winbindex(rows, architecture='x86', file_version='10.0.19041.1')
        self.assertEqual(selected['binary_sha256'], 'bb'*32)
        self.assertEqual(sources.select_winbindex(rows, sha256='AA'*32)['binary_sha256'], 'aa'*32)
        with self.assertRaisesRegex(ValueError, '[Nn]o matching'):
            sources.select_winbindex(rows, architecture='x64', file_version='22H2')

    def test_single_candidate_still_requires_explicit_version_and_arch_or_hash(self):
        candidate = self.candidates()[0]
        incomplete = [{}, {'architecture': candidate['architecture']},
                      {'file_version': candidate['binary_version']},
                      {'architecture': candidate['architecture'], 'file_version': ''}]
        for filters in incomplete:
            with self.subTest(filters=filters):
                with self.assertRaisesRegex(ValueError, '--sha256.*--file-version.*--arch'):
                    sources.select_winbindex([candidate], **filters)
        self.assertEqual(sources.select_winbindex([candidate], sha256=candidate['binary_sha256']), candidate)
        self.assertEqual(sources.select_winbindex([candidate], architecture=candidate['architecture'],
                                                 file_version=candidate['binary_version']), candidate)

    def test_incomplete_metadata_is_listable_but_not_downloadable(self):
        row = sources.select_winbindex(self.candidates(), sha256='dd'*32)
        with self.assertRaisesRegex(ValueError, 'timestamp.*image size|download'):
            sources.acquire_winbindex(row, self.cache)

    def test_acquisition_verifies_content_and_architecture(self):
        payload = pe_bytes()
        row = {'module': 'sample.dll', 'architecture': 'x64', 'binary_version': '10.0.19041.1',
               'binary_sha256': hashlib.sha256(payload).hexdigest(),
               'download_url': 'https://example.test/sample.dll', 'provenance': {'source': 'winbindex'}}
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(payload)):
            result = sources.acquire_winbindex(row, self.cache)
        self.assertEqual(result['pdb']['guid'], GUID)
        self.assertTrue(Path(result['binary_path']).is_file())
        row['architecture'] = 'x86'
        with self.assertRaisesRegex(ValueError, 'architecture'):
            sources.acquire_winbindex(row, Cache(self.cache.root, offline=True))

    def test_acquisition_retains_version_discovered_in_the_binary(self):
        payload = pe_bytes()
        row = {'module': 'sample.dll', 'architecture': 'x64', 'binary_version': None,
               'binary_sha256': hashlib.sha256(payload).hexdigest(),
               'download_url': 'https://example.test/sample.dll'}
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(payload)):
            result = sources.acquire_winbindex(row, self.cache)
        self.assertEqual(result['binary_version'], '10.0.19041.1')

    def test_local_binaries_are_retained_and_one_failure_does_not_hide_success(self):
        good = self.root/'sample.dll'
        bad = self.root/'bad.dll'
        good.write_bytes(pe_bytes())
        bad.write_bytes(b'broken')
        rows = sources.local_modules([good, bad], Cache(self.cache.root, offline=True))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['pdb']['age'], 2)
        self.assertNotEqual(rows[0]['binary_path'], str(good))
        self.assertEqual(rows[1]['status'], 'failed')
        self.assertIn('PE', rows[1]['error'])

    def test_repaired_local_binary_can_be_retried_from_failure_manifest(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(b'broken')
        failed = sources.local_modules([binary], self.cache)[0]
        self.assertEqual(failed['binary_path'], str(binary))
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [failed]}))
        binary.write_bytes(pe_bytes())
        result = sources.manifest_modules(manifest, self.cache)[0]
        self.assertNotIn('status', result)
        self.assertEqual(result['architecture'], 'x64')
        self.assertEqual(result['pdb']['guid'], GUID)
        self.assertTrue(Path(result['binary_path']).is_relative_to(self.cache.root))

    def test_local_cache_failure_keeps_already_read_binary_identity(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        with patch.object(self.cache, 'import_file', side_effect=OSError('cache unavailable')):
            failed = sources.local_modules([binary], self.cache)[0]
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['binary_sha256'], hashlib.sha256(pe_bytes()).hexdigest())
        self.assertEqual(failed['pdb']['guid'], GUID)

    def test_legacy_local_failure_recovers_relative_provenance_input(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        failed = {'module': 'sample.dll', 'status': 'failed', 'error': 'file missing',
                  'provenance': {'source': 'local', 'input_path': 'sample.dll'}}
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [failed]}))
        result = sources.manifest_modules(manifest, self.cache)[0]
        self.assertNotIn('status', result)
        self.assertEqual(result['pdb']['guid'], GUID)

    def test_failed_winbindex_transport_can_be_retried_from_manifest(self):
        payload = pe_bytes()
        candidate = {'module': 'sample.dll', 'architecture': 'x64', 'binary_version': '10.0.19041.1',
                     'binary_sha256': hashlib.sha256(payload).hexdigest(),
                     'download_url': 'https://example.test/sample.dll', 'provenance': {'source': 'winbindex'}}
        with patch('gdt_pipeline.cache.urlopen', side_effect=OSError('transport failed')):
            with self.assertRaises(OSError):
                sources.acquire_winbindex(candidate, self.cache)
        failed = dict(candidate, status='failed', error='transport failed')
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [failed]}))
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(payload)):
            result = sources.manifest_modules(manifest, self.cache)[0]
        self.assertNotIn('status', result)
        self.assertEqual(result['binary_sha256'], candidate['binary_sha256'])
        self.assertEqual(result['pdb']['guid'], GUID)

    def test_failed_winbindex_retry_still_checks_recorded_hash(self):
        failed = {'module': 'sample.dll', 'architecture': 'x64', 'binary_sha256': '00'*32,
                  'download_url': 'https://example.test/sample.dll', 'provenance': {'source': 'winbindex'},
                  'status': 'failed', 'error': 'transport failed'}
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [failed]}))
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(pe_bytes())):
            result = sources.manifest_modules(manifest, self.cache)[0]
        self.assertEqual(result['status'], 'failed')
        self.assertIn('SHA-256', result['error'])
        self.assertEqual(result['binary_sha256'], failed['binary_sha256'])

    def test_local_retry_preserves_recorded_identity_constraints(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        base = {'module': 'sample.dll', 'status': 'failed', 'binary_path': str(binary),
                'provenance': {'source': 'local', 'input_path': str(binary)}}
        constraints = [({'binary_sha256': '00'*32}, 'SHA-256'),
                       ({'architecture': 'x86'}, 'architecture'),
                       ({'architecture': 'x64', 'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 3}}, 'PDB identity')]
        manifest = self.root/'sources.json'
        for constraint, diagnostic in constraints:
            with self.subTest(constraint=constraint):
                manifest.write_text(json.dumps({'modules': [dict(base, **constraint)]}))
                result = sources.manifest_modules(manifest, self.cache)[0]
                self.assertEqual(result['status'], 'failed')
                self.assertIn(diagnostic, result['error'])

    def test_failed_pdb_validation_cannot_be_replaced_by_source_recovery(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        symbol = self.root/'sample.pdb'
        symbol.write_bytes(pdb_bytes())
        failed = {'module': 'sample.dll', 'architecture': 'x64', 'status': 'failed',
                  'error': 'PDB SHA-256 mismatch', 'provenance': {'source': 'local', 'input_path': str(binary)},
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2, 'sha256': '00'*32, 'path': str(symbol)}}
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [failed]}))
        result = sources.manifest_modules(manifest, self.cache)[0]
        self.assertEqual(result['pdb']['sha256'], '00'*32)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            ensure_pdb(result, self.cache)

    def test_manifest_supports_legacy_and_normalized_relative_paths(self):
        path = self.root/'sources.json'
        legacy = {'module': 'sample.dll', 'architecture': 'amd64', 'version': '1.2.3.4',
                  'pdb': 'sample.pdb', 'guid': GUID, 'age': 2, 'symbol': 'symbols/sample.pdb'}
        path.write_text(json.dumps({'modules': [legacy]}))
        row = sources.manifest_modules(path)[0]
        self.assertEqual(row['pdb']['path'], str(self.root/'symbols/sample.pdb'))
        self.assertEqual(row['binary_version'], '1.2.3.4')
        path.write_text(json.dumps({'modules': [row]}))
        self.assertEqual(sources.manifest_modules(path)[0]['pdb'], row['pdb'])

    def test_manifest_binary_only_reads_identity_and_checks_expected_hash(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        path = self.root/'sources.json'
        row = {'module': 'sample.dll', 'architecture': 'x64', 'binary_path': 'sample.dll'}
        path.write_text(json.dumps({'modules': [row]}))
        self.assertEqual(sources.manifest_modules(path)[0]['pdb']['guid'], GUID)
        row['binary_sha256'] = '00'*32
        path.write_text(json.dumps({'modules': [row]}))
        result = sources.manifest_modules(path)[0]
        self.assertEqual(result['status'], 'failed')
        self.assertIn('SHA-256', result['error'])

    def test_manifest_binary_is_retained_when_cache_is_supplied(self):
        binary = self.root/'sample.dll'
        binary.write_bytes(pe_bytes())
        manifest = self.root/'sources.json'
        manifest.write_text(json.dumps({'modules': [
            {'module': 'sample.dll', 'architecture': 'x64', 'binary_path': 'sample.dll'}]}))
        row = sources.manifest_modules(manifest, self.cache)[0]
        retained = Path(row['binary_path'])
        self.assertTrue(retained.is_relative_to(self.cache.root))
        self.assertEqual(retained.read_bytes(), binary.read_bytes())

    def test_repository_manifest_remains_usable_without_binaries(self):
        rows = sources.manifest_modules(Path(__file__).resolve().parents[1]/'windows_10_22h2/sources.json')
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['pdb']['sha256'] for row in rows))
