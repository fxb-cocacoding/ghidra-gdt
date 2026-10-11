import copy
import hashlib
import json
import re
import struct
import uuid
from pathlib import Path, PureWindowsPath


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_filename(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+ -]*', value):
        raise ValueError(f'Invalid filename: {value!r}')
    return value


def normalize_architecture(value):
    aliases = {'x64': 'x64', 'amd64': 'x64', 'x86_64': 'x64',
               'x86': 'x86', 'i386': 'x86', 'i686': 'x86', 34404: 'x64', 332: 'x86'}
    key = value.lower() if isinstance(value, str) else value
    if key not in aliases:
        raise ValueError(f'Unsupported architecture: {value!r}; expected x64 or x86')
    return aliases[key]


def _hash(value):
    value = str(value).lower()
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError(f'Invalid SHA-256: {value!r}')
    return value


def normalize_module(record):
    result = copy.deepcopy(record)
    result['module'] = safe_filename(result['module'])
    result['architecture'] = normalize_architecture(result['architecture'])
    result['provenance'] = result.get('provenance') or {}
    for old, new in [('version', 'binary_version'), ('file_version', 'binary_version'),
                     ('binary', 'binary_path')]:
        if old in result and new not in result:
            result[new] = result[old]
    if result.get('binary_sha256'):
        result['binary_sha256'] = _hash(result['binary_sha256'])
    pdb = result.get('pdb')
    if isinstance(pdb, str):
        pdb = {'filename': pdb, 'guid': result.get('guid'), 'age': result.get('age')}
        for old, new in [('symbol', 'path'), ('symbol_sha256', 'sha256'), ('url', 'download_url')]:
            if result.get(old):
                pdb[new] = result[old]
    if pdb:
        pdb = copy.deepcopy(pdb)
        pdb['filename'] = safe_filename(pdb['filename'])
        try:
            pdb['guid'] = str(uuid.UUID(str(pdb['guid']))).upper()
            if isinstance(pdb['age'], bool) or str(pdb['age']) != str(int(pdb['age'])):
                raise ValueError('age must be an integer')
            pdb['age'] = int(pdb['age'])
            if not 0 <= pdb['age'] <= 0xffffffff:
                raise ValueError('age is outside uint32 range')
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f'Invalid PDB identity for {result["module"]}: {exc}') from exc
        if pdb.get('sha256'):
            pdb['sha256'] = _hash(pdb['sha256'])
        result['pdb'] = pdb
    elif not result.get('binary_path'):
        raise ValueError(f'{result["module"]}: a binary path or PDB identity is required')
    return result


def set_id(modules):
    """Identify a set by content and symbol identity, independent of locations."""
    identities = []
    for original in modules:
        try:
            module = normalize_module(original)
        except (ValueError, KeyError, TypeError):
            if original.get('status') != 'failed':
                raise
            # Invalid inputs still need a stable destination for their failure report.
            module = copy.deepcopy(original)
            module['module'] = str(module.get('module', 'unknown'))
            try:
                module['architecture'] = normalize_architecture(module.get('architecture'))
            except (ValueError, TypeError):
                pass
            module['binary_sha256'] = str(module['binary_sha256']).lower() if module.get('binary_sha256') else None
        item = {key: module.get(key) for key in ('architecture', 'binary_version', 'binary_sha256')}
        item['module'] = module['module'].lower()
        if isinstance(module.get('pdb'), dict):
            item['pdb'] = {key: module['pdb'].get(key) for key in ('filename', 'guid', 'age')}
            if item['pdb']['filename'] is not None:
                item['pdb']['filename'] = str(item['pdb']['filename']).lower()
        elif module.get('pdb'):
            item['pdb'] = {'filename': str(module['pdb']).lower(),
                           'guid': module.get('guid'), 'age': module.get('age')}
        identities.append(item)
    rows = sorted(json.dumps(row, sort_keys=True, separators=(',', ':')) for row in identities)
    return hashlib.sha256(('[' + ','.join(rows) + ']').encode()).hexdigest()[:16]


def _unpack(data, fmt, offset):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise ValueError('Truncated or invalid binary structure')
    return struct.unpack_from(fmt, data, offset)


def read_pe(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError(f'{path}: not a PE file')
    pe, = _unpack(data, '<I', 0x3c)
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError(f'{path}: invalid PE signature')
    machine, sections, timestamp, _, _, optional_size, _ = _unpack(data, '<HHIIIHH', pe+4)
    architecture = normalize_architecture(machine)
    optional = pe + 24
    magic, = _unpack(data, '<H', optional)
    directory_offset = {0x10b: 96, 0x20b: 112}.get(magic)
    if directory_offset is None or optional_size < directory_offset:
        raise ValueError(f'{path}: unsupported PE optional header')
    image_size, headers_size = _unpack(data, '<II', optional+56)
    directory_count, = _unpack(data, '<I', optional+directory_offset-4)
    section_rows = []
    for index in range(sections):
        offset = optional + optional_size + index * 40
        virtual_size, address, raw_size, raw_offset = _unpack(data, '<IIII', offset+8)
        if raw_size and raw_offset + raw_size > len(data):
            raise ValueError(f'{path}: truncated PE section')
        section_rows.append((address, virtual_size, raw_offset, raw_size))

    def rva(value, size=1):
        if value < headers_size and value + size <= min(headers_size, len(data)):
            return value
        for address, virtual_size, raw_offset, raw_size in section_rows:
            relative = value - address
            if 0 <= relative and relative + size <= raw_size:
                return raw_offset + relative
        raise ValueError(f'{path}: invalid PE RVA 0x{value:x}')

    def directory(index):
        if directory_count <= index or optional_size < directory_offset + (index+1)*8:
            return 0, 0
        return _unpack(data, '<II', optional+directory_offset+index*8)

    debug_rva, debug_size = directory(6)
    if not debug_rva or not debug_size:
        raise ValueError(f'{path}: no CodeView PDB identity')
    debug_offset = rva(debug_rva, debug_size)
    pdb = None
    for offset in range(debug_offset, debug_offset+debug_size-27, 28):
        _, _, _, _, kind, size, _, pointer = _unpack(data, '<IIHHIIII', offset)
        if kind != 2:
            continue
        if pointer + size > len(data):
            raise ValueError(f'{path}: truncated CodeView record')
        cv = data[pointer:pointer+size]
        if cv[:4] != b'RSDS' or len(cv) < 25:
            continue
        if b'\0' not in cv[24:]:
            raise ValueError(f'{path}: unterminated PDB filename')
        filename = PureWindowsPath(cv[24:].split(b'\0', 1)[0].decode('utf-8', errors='strict')).name
        found = {'filename': filename, 'guid': str(uuid.UUID(bytes_le=cv[4:20])).upper(),
                 'age': _unpack(cv, '<I', 20)[0]}
        if pdb and found != pdb:
            raise ValueError(f'{path}: conflicting CodeView PDB identities')
        pdb = found
    if not pdb:
        raise ValueError(f'{path}: no supported RSDS PDB identity')
    result = {'module': path.name, 'architecture': architecture, 'binary_path': str(path),
              'binary_sha256': hashlib.sha256(data).hexdigest(), 'pdb': pdb,
              'timestamp': timestamp, 'image_size': image_size, 'provenance': {}}
    resource_rva, resource_size = directory(2)
    if resource_rva and resource_size:
        resource_base = rva(resource_rva, resource_size)

        def entries(relative):
            if relative + 16 > resource_size:
                raise ValueError('Invalid PE resource directory')
            names, ids = _unpack(data, '<HH', resource_base+relative+12)
            if relative + 16 + (names+ids)*8 > resource_size:
                raise ValueError('Truncated PE resource directory')
            return [_unpack(data, '<II', resource_base+relative+16+i*8) for i in range(names+ids)]

        versions = [target for name, target in entries(0) if name == 16]
        if versions:
            target = versions[0]
            for _ in range(3):
                if not target & 0x80000000:
                    break
                children = entries(target & 0x7fffffff)
                if not children:
                    raise ValueError('Empty PE version resource')
                target = children[0][1]
            if target & 0x80000000 or target+16 > resource_size:
                raise ValueError('Invalid PE version resource')
            value_rva, value_size, _, _ = _unpack(data, '<IIII', resource_base+target)
            value_offset = rva(value_rva, value_size)
            value = data[value_offset:value_offset+value_size]
            length, fixed_size, _ = _unpack(value, '<HHH', 0)
            key = 'VS_VERSION_INFO\0'.encode('utf-16le')
            fixed_offset = (6+len(key)+3) & ~3
            if value[6:6+len(key)] == key and fixed_size >= 16 and length <= value_size:
                signature, _, high, low = _unpack(value, '<IIII', fixed_offset)
                if signature == 0xfeef04bd:
                    result['binary_version'] = '.'.join(map(str, (high >> 16, high & 65535, low >> 16, low & 65535)))
    return normalize_module(result)


def read_pdb(path):
    """Read GUID and DBI age from an MSF 7.0 PDB without loading type streams."""
    path = Path(path)
    with path.open('rb') as stream:
        header = stream.read(56)
        if header[:32] != b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0':
            raise ValueError(f'{path}: not a supported MSF 7.0 PDB')
        block_size, _, blocks, directory_size, _, block_map = _unpack(header, '<6I', 32)
        if block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise ValueError(f'{path}: invalid PDB block size')
        if blocks * block_size > path.stat().st_size or directory_size > blocks * block_size:
            raise ValueError(f'{path}: truncated PDB')

        def read_block(number):
            if number >= blocks:
                raise ValueError(f'{path}: invalid PDB block reference')
            stream.seek(number*block_size)
            chunk = stream.read(block_size)
            if len(chunk) != block_size:
                raise ValueError(f'{path}: truncated PDB block')
            return chunk

        directory_blocks = (directory_size+block_size-1)//block_size
        if directory_blocks*4 > block_size:
            raise ValueError(f'{path}: unsupported oversized PDB directory map')
        block_numbers = _unpack(read_block(block_map), '<'+'I'*directory_blocks, 0)
        directory = b''.join(read_block(number) for number in block_numbers)[:directory_size]
        count, = _unpack(directory, '<I', 0)
        if count < 2 or count > (len(directory)-4)//4:
            raise ValueError(f'{path}: invalid PDB stream directory')
        sizes = _unpack(directory, '<'+'I'*count, 4)
        position = 4+count*4
        streams = {}
        for index, size in enumerate(sizes):
            number_blocks = 0 if size == 0xffffffff else (size+block_size-1)//block_size
            numbers = _unpack(directory, '<'+'I'*number_blocks, position)
            position += number_blocks*4
            if index in (1, 3):
                # Only the first block is needed for the identity headers.
                streams[index] = read_block(numbers[0])[:size] if numbers else b''
        info = streams[1]
        if len(info) < 28:
            raise ValueError(f'{path}: missing PDB identity stream')
        age, = _unpack(info, '<I', 8)
        if streams.get(3):
            age, = _unpack(streams[3], '<I', 8)
        return {'guid': str(uuid.UUID(bytes_le=info[12:28])).upper(), 'age': age}
