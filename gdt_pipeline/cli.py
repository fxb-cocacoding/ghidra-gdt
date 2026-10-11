import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile

from .cache import Cache, ensure_pdb
from .ghidra import build_set, check_tools, installation_info
from .identity import set_id
from .sources import (acquire_winbindex, local_modules, manifest_modules,
                      select_winbindex, winbindex_candidates)


def parser():
    result = argparse.ArgumentParser(description=__doc__ or 'Download Windows PDBs and build GDT archives with headless Ghidra.')
    source = result.add_mutually_exclusive_group(required=True)
    source.add_argument('--winbindex', metavar='FILENAME', help='Winbindex module, e.g. ntdll.dll')
    source.add_argument('--binary', type=Path, action='append', help='Local Windows PE; repeat for multiple modules')
    source.add_argument('--manifest', type=Path, help='Previously recorded sources.json')
    result.add_argument('--arch', choices=('x64', 'x86'), help='Winbindex architecture')
    result.add_argument('--file-version', help='Exact Winbindex numeric file version')
    result.add_argument('--sha256', help='Exact Winbindex binary SHA-256')
    result.add_argument('--list-builds', dest='list_builds', action='store_true',
                        help='List Winbindex builds without downloading binaries or symbols')
    result.add_argument('--ghidra', type=Path, help='Built Ghidra installation (required unless downloading/listing)')
    result.add_argument('--download-only', action='store_true', help='Keep verified PDBs and provenance without Ghidra')
    result.add_argument('--offline', action='store_true', help='Use only local files and verified cache entries')
    return result


def save_manifest(path, manifest):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Preserve every prior provenance record on reruns, including partial failures.
    if path.exists():
        history = path.parent / 'history'
        history.mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix='sources-', suffix='.json', dir=history, delete=False) as previous:
            previous.write(path.read_bytes())
    handle, temporary = tempfile.mkstemp(prefix='.sources-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(handle, 'w') as out:
            json.dump(manifest, out, indent=2)
            out.write('\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None):
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    if not sys.platform.startswith('linux'):
        argument_parser.error('Only Linux execution is currently supported')
    if (args.list_builds or args.arch or args.file_version or args.sha256) and not args.winbindex:
        argument_parser.error('--list-builds, --arch, --file-version and --sha256 require --winbindex')
    if not args.download_only and not args.list_builds and not args.ghidra:
        argument_parser.error('--ghidra is required unless using --download-only or --list-builds')
    try:
        info = None
        if not args.download_only and not args.list_builds:
            check_tools(args.ghidra)
            print('Fingerprinting Ghidra installation...', file=sys.stderr, flush=True)
            info = installation_info(args.ghidra)
        workspace = Path.cwd()
        cache = Cache(workspace / '.cache/ghidra-gdt', offline=args.offline)
        if args.binary:
            modules = local_modules(args.binary, cache)
        elif args.manifest:
            modules = manifest_modules(args.manifest, cache)
        else:
            candidates = winbindex_candidates(args.winbindex, cache)
            if args.list_builds:
                matches = [c for c in candidates if
                           (not args.arch or c['architecture'] == args.arch) and
                           (not args.file_version or c.get('binary_version') == args.file_version) and
                           (not args.sha256 or c.get('binary_sha256') == args.sha256.lower())]
                print('FILE VERSION       ARCH  WINDOWS RELEASES       SHA-256')
                for candidate in matches:
                    releases = ','.join(candidate['provenance'].get('windows_versions', [])) or '-'
                    print(f'{candidate.get("binary_version") or "unknown":<18} '
                          f'{candidate["architecture"]:<5} {releases:<22} {candidate["binary_sha256"]}')
                print(f'{len(matches)} build(s)')
                return 0
            candidate = select_winbindex(candidates, architecture=args.arch,
                                        file_version=args.file_version, sha256=args.sha256)
            try:
                modules = [acquire_winbindex(candidate, cache)]
            except (ValueError, OSError) as error:
                modules = [dict(candidate, status='failed', error=str(error))]
        if not modules:
            raise ValueError('Source selection contains no modules')
        selection = set_id(modules)
        manifest = {'schema_version': 1, 'set_id': selection,
                    'created_utc': datetime.now(timezone.utc).isoformat(),
                    'status': 'downloading', 'modules': modules}
        manifest_path = workspace / 'sources' / selection / 'sources.json'
        save_manifest(manifest_path, manifest)
        failures = 0
        for index, module in enumerate(modules):
            print(f'[{index + 1}/{len(modules)}] {module.get("architecture", "unknown")} {module.get("module", "unknown")}',
                  file=sys.stderr, flush=True)
            try:
                if module.get('status') == 'failed':
                    raise ValueError(module.get('error', 'Source validation failed'))
                if not module.get('pdb'):
                    raise ValueError(module.get('error', 'No usable PDB identity'))
                verified = ensure_pdb(module, cache)
                verified['status'] = 'downloaded'
                verified.pop('error', None)
                modules[index] = verified
            except (OSError, ValueError) as error:
                module.update(status='failed', error=str(error))
                failures += 1
                print(f'  Failed: {error}', file=sys.stderr)
        manifest['status'] = 'partial' if failures else 'downloaded'
        save_manifest(manifest_path, manifest)
        print(f'Provenance: {manifest_path}', flush=True)
        if failures:
            return 1
        if not args.download_only:
            print('Exporting and validating PDB types with headless Ghidra...', file=sys.stderr, flush=True)
            destination, verification = build_set(modules, args.ghidra, cache, workspace / 'archives',
                                                  selection, manifest, info)
            omitted = sum(m['status'] == 'omitted' for m in verification['modules'])
            print(f'Verified archives: {destination} ({len(modules) - omitted} exported, {omitted} omitted)')
        return 0
    except (ValueError, OSError, RuntimeError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted; completed downloads remain cached.', file=sys.stderr)
        return 130
