import hashlib
import http.client
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gdt_pipeline import cache
from test_identity import GUID, pdb_bytes


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_download_hash_and_offline_reuse(self):
        content = b'verified payload'
        digest = hashlib.sha256(content).hexdigest()
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(content)) as network:
            result = cache.Cache(self.root).fetch('https://example.test/a', 'binary/a', sha256=digest)
            self.assertEqual(result.read_bytes(), content)
            network.assert_called_once()
        with patch('gdt_pipeline.cache.urlopen', side_effect=AssertionError('network')):
            reused = cache.Cache(self.root, offline=True).fetch('https://example.test/a', 'binary/a')
        self.assertEqual(reused, result)

    def test_offline_miss_never_connects(self):
        with patch('gdt_pipeline.cache.urlopen', side_effect=AssertionError('network')):
            with self.assertRaisesRegex(FileNotFoundError, 'offline'):
                cache.Cache(self.root, offline=True).fetch('https://example.test/a', 'a')

    def test_refresh_updates_online_snapshot_and_offline_never_connects(self):
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(b'old')):
            path = cache.Cache(self.root).fetch('https://example.test/a', 'a')
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(b'new')):
            refreshed = cache.Cache(self.root).fetch('https://example.test/a', 'a', refresh=True)
        self.assertEqual(refreshed.read_bytes(), b'new')
        with patch('gdt_pipeline.cache.urlopen', side_effect=AssertionError('network')):
            reused = cache.Cache(self.root, offline=True).fetch('https://example.test/a', 'a', refresh=True)
        self.assertEqual(reused, path)
        self.assertEqual(reused.read_bytes(), b'new')

    def test_failed_refresh_preserves_prior_verified_snapshot(self):
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(b'original')):
            path = cache.Cache(self.root).fetch('https://example.test/a', 'a')
        recorded = Path(str(path)+'.sha256').read_bytes()
        with patch('gdt_pipeline.cache.urlopen', side_effect=OSError('refresh failed')):
            with self.assertRaisesRegex(OSError, 'refresh failed'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a', refresh=True)
        self.assertEqual(path.read_bytes(), b'original')
        self.assertEqual(Path(str(path)+'.sha256').read_bytes(), recorded)
        reused = cache.Cache(self.root, offline=True).fetch('https://example.test/a', 'a')
        self.assertEqual(reused.read_bytes(), b'original')

    def test_corrupt_cached_content_is_rejected_offline(self):
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(b'original')):
            path = cache.Cache(self.root).fetch('https://example.test/a', 'a')
        path.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            cache.Cache(self.root, offline=True).fetch('https://example.test/a', 'a')

    def test_wrong_download_is_never_published_and_retries_are_bounded(self):
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(b'wrong')) as network:
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a', sha256='00'*32)
        self.assertEqual(network.call_count, 3)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_interrupted_download_is_not_cached(self):
        class Broken(io.BytesIO):
            def read(self, *args):
                raise OSError('connection broke')
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: Broken(b'x')):
            with self.assertRaisesRegex(OSError, 'connection broke'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a')
        self.assertFalse((self.root / 'a').exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_http_incomplete_read_is_retried_and_not_published(self):
        class Incomplete(io.BytesIO):
            def read(self, *args):
                raise http.client.IncompleteRead(b'partial', 100)
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: Incomplete()) as network:
            with self.assertRaisesRegex(OSError, 'IncompleteRead|Incomplete HTTP'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a')
        self.assertEqual(network.call_count, 3)
        self.assertFalse((self.root/'a').exists())

    def test_truncated_metadata_validation_is_a_reportable_error(self):
        def invalid(path):
            raise EOFError('truncated gzip')
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(b'truncated')):
            with self.assertRaisesRegex(ValueError, 'truncated gzip'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a', validator=invalid)
        self.assertFalse((self.root/'a').exists())

    def test_short_content_length_is_rejected_without_expected_hash(self):
        def response(*args, **kwargs):
            stream = io.BytesIO(b'short')
            stream.headers = {'Content-Length': '100'}
            return stream
        with patch('gdt_pipeline.cache.urlopen', side_effect=response):
            with self.assertRaisesRegex(ValueError, '[Ll]ength|[Ii]ncomplete'):
                cache.Cache(self.root).fetch('https://example.test/a', 'a')
        self.assertFalse((self.root/'a').exists())

    def test_pdb_path_inside_cache_cannot_overwrite_known_hash(self):
        record = {'module': 'sample.dll', 'architecture': 'x64',
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2}}
        with patch('gdt_pipeline.cache.urlopen', return_value=io.BytesIO(pdb_bytes())):
            updated = cache.ensure_pdb(record, cache.Cache(self.root))
        path = Path(updated['pdb']['path'])
        # Leave GUID and age intact while changing other PDB content.
        path.write_bytes(path.read_bytes()[:-1]+b'X')
        record['pdb']['path'] = str(path)
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            cache.ensure_pdb(record, cache.Cache(self.root, offline=True))

    def test_cache_path_must_stay_in_root(self):
        with self.assertRaises(ValueError):
            cache.Cache(self.root).fetch('https://example.test/a', '../outside')

    def test_pdb_seed_is_verified_by_guid_age_then_hash_recorded(self):
        record = {'module': 'sample.dll', 'architecture': 'x64',
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2}}
        path = self.root / 'symbols' / 'sample.pdb' / (GUID.replace('-', '')+'2') / 'sample.pdb'
        path.parent.mkdir(parents=True)
        path.write_bytes(pdb_bytes())
        updated = cache.ensure_pdb(record, cache.Cache(self.root, offline=True))
        self.assertEqual(updated['pdb']['path'], str(path))
        self.assertEqual(updated['pdb']['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertTrue(Path(str(path)+'.sha256').exists())
        self.assertNotIn('path', record['pdb'])

    def test_pdb_wrong_identity_is_rejected_even_with_valid_sha(self):
        content = pdb_bytes(age=3)
        record = {'module': 'sample.dll', 'architecture': 'x64',
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2,
                          'sha256': hashlib.sha256(content).hexdigest()}}
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(content)):
            with self.assertRaisesRegex(ValueError, 'PDB identity'):
                cache.ensure_pdb(record, cache.Cache(self.root))

    def test_moved_manifest_pdb_path_falls_back_to_cache(self):
        record = {'module': 'sample.dll', 'architecture': 'x64',
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2, 'path': '/missing/example.pdb'}}
        with patch('gdt_pipeline.cache.urlopen', side_effect=lambda *a, **kw: io.BytesIO(pdb_bytes())):
            result = cache.ensure_pdb(record, cache.Cache(self.root))
        self.assertTrue(Path(result['pdb']['path']).is_file())

    def test_local_pdb_is_copied_and_verified_without_network(self):
        source = self.root / 'local.pdb'
        source.write_bytes(pdb_bytes())
        record = {'module': 'sample.dll', 'architecture': 'x64',
                  'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2, 'path': str(source)}}
        with patch('gdt_pipeline.cache.urlopen', side_effect=AssertionError('network')):
            result = cache.ensure_pdb(record, cache.Cache(self.root/'cache', offline=True))
        self.assertNotEqual(result['pdb']['path'], str(source))
        self.assertEqual(Path(result['pdb']['path']).read_bytes(), source.read_bytes())
