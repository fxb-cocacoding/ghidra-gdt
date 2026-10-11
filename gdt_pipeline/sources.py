"""Resolve local, manifest, and Winbindex inputs into module records."""

import copy
import gzip
import json
import re
from pathlib import Path

from .identity import normalize_architecture, normalize_module, read_pe, safe_filename, sha256_file


WINBINDEX_BASE = 'https://winbindex.m417z.com/data/by_filename_compressed'


def _retain(record, cache):
    target = Path('binaries') / record['binary_sha256'] / record['module']
    stored = cache.import_file(record['binary_path'], target, sha256=record['binary_sha256'])
    record['binary_path'] = str(stored)
    return record


def local_modules(paths, cache):
    modules = []
    for value in paths:
        path = Path(value).resolve()
        provenance = {'source': 'local', 'input_path': str(path)}
        record = {'module': path.name, 'binary_path': str(path), 'provenance': provenance}
        try:
            record = read_pe(path)
            record['provenance'] = provenance
            modules.append(_retain(record, cache))
        except (OSError, ValueError) as exc:
            record.update(status='failed', error=str(exc))
            modules.append(record)
    return modules


def _check_binary(record, path):
    actual = read_pe(path)
    if record.get('binary_sha256') and record['binary_sha256'] != actual['binary_sha256']:
        raise ValueError(f'{record["module"]}: binary SHA-256 mismatch')
    if record.get('architecture') and record['architecture'] != actual['architecture']:
        raise ValueError(f'{record["module"]}: binary architecture mismatch')
    if record.get('binary_version') and actual.get('binary_version') != record['binary_version']:
        raise ValueError(f'{record["module"]}: binary file version mismatch')
    if record.get('pdb'):
        for key in ('filename', 'guid', 'age'):
            expected, found = record['pdb'][key], actual['pdb'][key]
            if (expected.lower() if key == 'filename' else expected) != (found.lower() if key == 'filename' else found):
                raise ValueError(f'{record["module"]}: binary PDB identity mismatch ({key})')
        actual['pdb'].update(record['pdb'])
    return dict(actual, **{key: value for key, value in record.items()
                          if key not in ('pdb', 'binary_path', 'binary_sha256') and value is not None},
                pdb=actual['pdb'], binary_path=str(Path(path).resolve()), binary_sha256=actual['binary_sha256'])


def manifest_modules(path, cache=None):
    path = Path(path).resolve()
    manifest = json.loads(path.read_text())
    records = manifest if isinstance(manifest, list) else manifest.get('modules')
    if not isinstance(records, list) or not records:
        raise ValueError(f'{path}: manifest must contain a nonempty modules list')
    base = path.parent
    if isinstance(manifest, dict) and manifest.get('paths_relative_to') == 'repository root':
        base = next((parent for parent in path.parents if (parent/'.git').exists()), base)
    modules = []
    for original in records:
        try:
            record = copy.deepcopy(original)
            if isinstance(record, dict) and record.get('status') == 'failed' and not record.get('pdb'):
                provenance = record.get('provenance') or {}
                if provenance.get('source') == 'local':
                    source_path = record.get('binary_path') or provenance.get('input_path')
                    if source_path:
                        record['binary_path'] = str((base / source_path).resolve())
                        # Recover only absent information; recorded constraints stay authoritative.
                        if not record.get('architecture'):
                            record['architecture'] = read_pe(record['binary_path'])['architecture']
                elif (provenance.get('source') == 'winbindex' and cache is not None
                      and not record.get('binary_path') and record.get('download_url')
                      and record.get('binary_sha256')):
                    record = acquire_winbindex(record, cache)
            record = normalize_module(record)
            if record.get('binary_path'):
                record['binary_path'] = str((base / record['binary_path']).resolve())
            if record.get('pdb', {}).get('path'):
                record['pdb']['path'] = str((base / record['pdb']['path']).resolve())
            # A stale binary path can be ignored only when the PDB identity is known.
            if record.get('binary_path') and Path(record['binary_path']).is_file():
                record = _check_binary(record, record['binary_path'])
                if cache is not None:
                    record = _retain(record, cache)
            elif not record.get('pdb'):
                raise FileNotFoundError(f'{record["module"]}: binary is missing and no PDB identity is recorded')
            record.setdefault('provenance', {})
            record['provenance'].setdefault('manifest_path', str(path))
            # These describe the previous export, not the source selection being replayed.
            for derived in ('type_entries', 'archives', 'publishes_structures'):
                record.pop(derived, None)
            # A previous transient failure does not prevent an explicitly requested retry.
            record.pop('status', None)
            record.pop('error', None)
            modules.append(record)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            failed = copy.deepcopy(original) if isinstance(original, dict) else {'module': str(original)}
            failed.update(status='failed', error=str(exc))
            modules.append(failed)
    return modules


def _metadata(path):
    with gzip.open(path, 'rt', encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError('Winbindex metadata must be a SHA-256-keyed object')
    for digest, entry in data.items():
        if not re.fullmatch('[0-9a-fA-F]{64}', digest) or not isinstance(entry, dict):
            raise ValueError('Invalid Winbindex metadata record')
    return data


def winbindex_candidates(filename, cache):
    filename = safe_filename(filename).lower()
    url = f'{WINBINDEX_BASE}/{filename}.json.gz'
    metadata_path = cache.fetch(url, Path('winbindex')/(filename+'.json.gz'),
                                validator=_metadata, refresh=not cache.offline)
    metadata_hash = sha256_file(metadata_path)
    candidates = []
    for digest, entry in _metadata(metadata_path).items():
        info = entry.get('fileInfo') or {}
        try:
            architecture = normalize_architecture(info.get('machineType'))
        except ValueError:
            # This pipeline exports x86 and x64 Windows archives only.
            continue
        version = info.get('version')
        if version:
            version = re.sub(r'\s*(\(.*\)|built by:.*|@BuiltBy:.*)$', '', version).strip()
        image_size = info.get('virtualSize')
        timestamp = info.get('timestamp')
        download_url = None
        if isinstance(timestamp, int) and 0 <= timestamp <= 0xffffffff and isinstance(image_size, int) and image_size > 0:
            ident = f'{timestamp:08X}{image_size:x}'
            download_url = f'https://msdl.microsoft.com/download/symbols/{filename}/{ident}/{filename}'
        candidate = {'module': filename, 'architecture': architecture, 'binary_version': version,
                     'binary_sha256': digest.lower(), 'download_url': download_url,
                     'provenance': {'source': 'winbindex', 'metadata_url': url,
                                    'metadata_sha256': metadata_hash, 'timestamp': timestamp,
                                    'image_size': image_size,
                                    'windows_versions': sorted((entry.get('windowsVersions') or {}).keys())}}
        candidates.append(candidate)
    return sorted(candidates, key=lambda item: (item['binary_version'] or '', item['architecture'], item['binary_sha256']))


def select_winbindex(candidates, architecture=None, file_version=None, sha256=None):
    if sha256 is None and (not architecture or not file_version):
        raise ValueError('Winbindex acquisition requires --sha256 or both --file-version and --arch')
    if architecture is not None:
        architecture = normalize_architecture(architecture)
    if sha256 is not None:
        sha256 = sha256.lower()
        if not re.fullmatch('[0-9a-f]{64}', sha256):
            raise ValueError('A complete 64-character SHA-256 is required')
    matches = [candidate for candidate in candidates
               if (architecture is None or candidate['architecture'] == architecture)
               and (file_version is None or candidate.get('binary_version') == file_version)
               and (sha256 is None or candidate['binary_sha256'] == sha256)]
    if not matches:
        raise ValueError('No matching Winbindex binary; select an exact file version and architecture or SHA-256')
    if len(matches) != 1:
        choices = ', '.join(f'{row["architecture"]} {row.get("binary_version")} {row["binary_sha256"]}' for row in matches)
        raise ValueError(f'Ambiguous Winbindex selection ({len(matches)} candidates); choose --arch or --sha256: {choices}')
    return copy.deepcopy(matches[0])


def acquire_winbindex(candidate, cache):
    if not candidate.get('download_url'):
        raise ValueError(f'{candidate["module"]}: Winbindex has no timestamp and image size download identity')
    target = Path('binaries') / candidate['binary_sha256'] / candidate['module']
    # Validate the PE identity before an otherwise hash-correct download is published.
    def validate(path):
        return _check_binary(candidate, path)
    path = cache.fetch(candidate['download_url'], target, sha256=candidate['binary_sha256'], validator=validate)
    return _check_binary(candidate, path)
