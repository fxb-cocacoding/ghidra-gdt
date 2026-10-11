import copy
import hashlib
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from gdt_pipeline import identity


GUID = '00112233-4455-6677-8899-AABBCCDDEEFF'


def pe_bytes(machine=0x8664, pdb_name='sample.pdb', age=2):
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 240 if machine == 0x8664 else 224
    struct.pack_into('<HHIIIHH', data, 0x84, machine, 1, 0x1234ABCD, 0, 0, optional_size, 0x2022)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b if machine == 0x8664 else 0x10b)
    struct.pack_into('<II', data, optional + 56, 0x2000, 0x200)
    directories = optional + (112 if machine == 0x8664 else 96)
    struct.pack_into('<I', data, directories - 4, 16)
    struct.pack_into('<II', data, directories + 6 * 8, 0x1000, 28)
    section = optional + optional_size
    data[section:section+8] = b'.rdata\0\0'
    struct.pack_into('<IIII', data, section+8, 0x400, 0x1000, 0x400, 0x200)
    cv = b'RSDS' + uuid.UUID(GUID).bytes_le + struct.pack('<I', age) + pdb_name.encode() + b'\0'
    struct.pack_into('<IIHHIIII', data, 0x200, 0, 0, 0, 0, 2, len(cv), 0x1040, 0x240)
    data[0x240:0x240+len(cv)] = cv
    # RT_VERSION tree and a minimal VS_VERSION_INFO / VS_FIXEDFILEINFO.
    struct.pack_into('<II', data, directories + 2 * 8, 0x1100, 0x180)
    for off, ident, target in [(0x300, 16, 0x80000020), (0x320, 1, 0x80000040), (0x340, 1033, 0x60)]:
        struct.pack_into('<HHII', data, off+12, 0, 1, ident, target)
    struct.pack_into('<IIII', data, 0x360, 0x1180, 92, 0, 0)
    struct.pack_into('<HHH', data, 0x380, 92, 52, 0)
    key = 'VS_VERSION_INFO\0'.encode('utf-16le')
    data[0x386:0x386+len(key)] = key
    struct.pack_into('<IIII', data, 0x3a8, 0xfeef04bd, 0x10000, 0xa0000, 0x4a610001)
    return bytes(data)


def pdb_bytes(guid=GUID, age=2, info_age=None):
    block = 512
    data = bytearray(block * 7)
    data[:32] = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0'
    struct.pack_into('<6I', data, 32, block, 1, 7, 28, 0, 2)
    struct.pack_into('<I', data, block * 2, 3)
    struct.pack_into('<7I', data, block * 3, 4, 0, 28, 0, 64, 4, 5)
    struct.pack_into('<III', data, block * 4, 20000404, 0, age if info_age is None else info_age)
    data[block*4+12:block*4+28] = uuid.UUID(guid).bytes_le
    struct.pack_into('<iII', data, block * 5, -1, 19990903, age)
    return bytes(data)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_pe_identity_for_both_architectures_and_version(self):
        for machine, architecture in [(0x8664, 'x64'), (0x14c, 'x86')]:
            path = self.root / 'sample.dll'
            path.write_bytes(pe_bytes(machine, r'C:\build\sample.pdb'))
            record = identity.read_pe(path)
            self.assertEqual(record['architecture'], architecture)
            self.assertEqual(record['binary_version'], '10.0.19041.1')
            self.assertEqual(record['pdb'], {'filename': 'sample.pdb', 'guid': GUID, 'age': 2})
            self.assertEqual(record['binary_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_sha256_file_matches_known_empty_and_multichunk_hashes(self):
        path = self.root / 'hashed.bin'
        for payload in (b'', b'abc', b'abcd' * 300000):
            path.write_bytes(payload)
            self.assertEqual(identity.sha256_file(path), hashlib.sha256(payload).hexdigest())

    def test_rejects_truncated_or_non_pe(self):
        for content in [b'not PE', pe_bytes()[:0x260]]:
            path = self.root / 'bad.dll'
            path.write_bytes(content)
            with self.assertRaises(ValueError):
                identity.read_pe(path)

    def test_pdb_identity_uses_dbi_age(self):
        path = self.root / 'sample.pdb'
        path.write_bytes(pdb_bytes(info_age=99))
        self.assertEqual(identity.read_pdb(path), {'guid': GUID, 'age': 2})

    def test_rejects_invalid_pdb(self):
        path = self.root / 'bad.pdb'
        path.write_bytes(pdb_bytes()[:600])
        with self.assertRaises(ValueError):
            identity.read_pdb(path)

    def test_normalize_legacy_record(self):
        record = identity.normalize_module({'module': 'NTDLL.dll', 'architecture': 'amd64',
            'version': '1.2.3.4', 'pdb': 'ntdll.pdb', 'guid': GUID.lower(), 'age': '2',
            'symbol_sha256': 'AB' * 32})
        self.assertEqual(record['architecture'], 'x64')
        self.assertEqual(record['binary_version'], '1.2.3.4')
        self.assertEqual(record['pdb']['guid'], GUID)
        self.assertEqual(record['pdb']['sha256'], 'ab' * 32)

    def test_rejects_unsafe_identity(self):
        for field, value in [('filename', '../sample.pdb'), ('guid', 'invalid'), ('age', -1)]:
            record = {'module': 'sample.dll', 'architecture': 'x64',
                'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2}}
            record['pdb'][field] = value
            with self.assertRaises(ValueError):
                identity.normalize_module(record)

    def test_set_id_ignores_order_paths_provenance_and_status(self):
        records = [{'module': 'sample.dll', 'architecture': 'x64', 'binary_sha256': 'ab'*32,
                    'pdb': {'filename': 'sample.pdb', 'guid': GUID, 'age': 2}},
                   {'module': 'other.dll', 'architecture': 'x86',
                    'pdb': {'filename': 'other.pdb', 'guid': GUID, 'age': 3}}]
        self.assertEqual(identity.set_id(records), '8a26fd17512b4438')
        changed = copy.deepcopy(records[::-1])
        changed[0].update(binary_path='/elsewhere/other.dll', status='failed', provenance={'time': 'today'})
        changed[0]['pdb']['path'] = '/elsewhere/other.pdb'
        self.assertEqual(identity.set_id(records), identity.set_id(changed))
        changed[0]['pdb']['age'] += 1
        self.assertNotEqual(identity.set_id(records), identity.set_id(changed))

    def test_failed_invalid_pdb_can_be_identified_for_failure_manifest(self):
        records = [{'module': 'bad.dll', 'architecture': 'x64', 'status': 'failed',
                    'error': 'invalid identity', 'pdb': {'guid': 'invalid'}}]
        first = identity.set_id(records)
        changed = copy.deepcopy(records)
        changed[0]['error'] = 'a different diagnostic'
        changed[0]['binary_path'] = '/somewhere/bad.dll'
        self.assertEqual(first, identity.set_id(changed))

    def test_failed_binary_candidates_keep_their_content_identity(self):
        first = {'module': 'sample.dll', 'architecture': 'x64', 'status': 'failed',
                 'binary_version': '1.2.3.4', 'binary_sha256': 'ab'*32}
        second = dict(first, binary_sha256='cd'*32)
        self.assertNotEqual(identity.set_id([first]), identity.set_id([second]))
