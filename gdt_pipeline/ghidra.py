import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .identity import sha256_file
from .layouts import COVERAGE, compare_layouts, parse_llvm_types


SCRIPT_ROOT = Path(__file__).resolve().parent.parent / 'scripts'


def installation_info(root):
    root = Path(root).resolve()
    properties = root / 'Ghidra/application.properties'
    if not properties.is_file() or not (root / 'support/analyzeHeadless').is_file():
        raise ValueError(f'Not a built Ghidra installation: {root}')
    metadata = {}
    for line in properties.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            metadata[key.strip()] = value.strip()
    version = metadata.get('application.version')
    release = metadata.get('application.release.name')
    if not version or not release:
        raise ValueError('Ghidra application metadata lacks version/release')
    files = sorted(path for path in root.rglob('*') if path.is_file() and (
        path == properties or path.suffix == '.jar' or 'languages' in path.parts or
        path.suffix in {'.ldefs', '.cspec', '.pspec', '.sla', '.slaspec'}))
    fingerprint = hashlib.sha256()
    for path in files:
        fingerprint.update(path.relative_to(root).as_posix().encode() + b'\0')
        fingerprint.update(bytes.fromhex(sha256_file(path)))
    return {'version': version, 'release': release,
            'version_release': re.sub(r'[^A-Za-z0-9._-]', '_', version + '-' + release),
            'fingerprint': fingerprint.hexdigest(), 'fingerprint_files': len(files),
            'metadata': metadata}


def check_tools(ghidra):
    for tool in ('java', 'javac', 'llvm-pdbutil'):
        if not shutil.which(tool):
            raise ValueError(f'Required tool not found: {tool}')
    if not os.access(Path(ghidra) / 'support/analyzeHeadless', os.X_OK):
        raise ValueError(f'Missing executable support/analyzeHeadless under {ghidra}')


def run_headless(ghidra, jobs, work):
    """
    Run one JVM per set. Require a results file even if the launcher exits zero.
    """
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    job_path = work / 'jobs.json'
    result_path = work / 'results.json'
    if result_path.exists():
        raise ValueError(f'Headless work directory already used: {work}')
    job_path.write_text(json.dumps(jobs, indent=2) + '\n')
    env = os.environ.copy()
    # Isolate Ghidra preferences, script compilation and logs from the users GUI.
    user_home = work / 'home'
    user_home.mkdir()
    env['JAVA_TOOL_OPTIONS'] = env.get('JAVA_TOOL_OPTIONS', '') + (
        f' -Duser.home="{user_home}" -Dapplication.cachedir="{work / "cache"}"'
        f' -Dapplication.settingsdir="{work / "settings"}" -Dapplication.tempdir="{work / "tmp"}"')
    # Ghidra 12.3 rejects dot-prefixed elements in project paths (including .cache).
    project = tempfile.TemporaryDirectory(prefix='ghidra-gdt-project-', dir='/tmp')
    command = [str(Path(ghidra).resolve() / 'support/analyzeHeadless'), project.name, 'pdb-types',
               '-scriptPath', str(SCRIPT_ROOT), '-preScript', 'ExportPdbTypes.java',
               str(job_path), str(result_path), '-noanalysis', '-deleteProject',
               '-log', str(work / 'ghidra.log'), '-scriptlog', str(work / 'script.log')]
    log_path = work / 'headless.log'
    try:
        with log_path.open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    finally:
        project.cleanup()
    if result.returncode or not result_path.is_file():
        raise ValueError(f'Ghidra export failed; see {log_path}')
    reports = json.loads(result_path.read_text())
    if len(reports) != len(jobs):
        raise ValueError(f'Incomplete Ghidra results; see {log_path}')
    return reports


def build_set(modules, ghidra, cache, output_root, set_id, manifest, info=None):
    check_tools(ghidra)
    info = info or installation_info(ghidra)
    destination = Path(output_root).resolve() / info['version_release'] / info['fingerprint'] / set_id
    if destination.exists():
        raise ValueError(f'Completed output already exists; refusing to overwrite: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    work_parent = cache.root / 'runs'
    work_parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=set_id + '-', dir=work_parent))
    with tempfile.TemporaryDirectory(prefix='.staging-', dir=destination.parent) as directory:
        stage = Path(directory)
        jobs, selected, reports = [], [], []
        for number, module in enumerate(modules):
            pdb = module['pdb']
            dump_path = work / f'{number}.pdb-types.txt'
            with dump_path.open('w') as out:
                result = subprocess.run(['llvm-pdbutil', 'dump', '-types', pdb['path']],
                                        stdout=out, stderr=subprocess.PIPE, text=True)
            if result.returncode:
                raise ValueError(f'LLVM could not read {module["module"]}: {result.stderr.strip()}')
            parsed = parse_llvm_types(dump_path.read_text())
            report = {'module': module['module'], 'architecture': module['architecture'],
                      'pdb': {k: pdb[k] for k in ('filename', 'guid', 'age', 'sha256')}}
            reports.append(report)
            if not parsed['aggregate_definitions']:
                report.update(status='omitted', reason='PDB contains no aggregate definitions')
                continue
            key = pdb['guid'].replace('-', '').upper() + format(pdb['age'], 'X')
            filename = re.sub(r'[^a-z0-9_-]', '_', module['module'].lower()) + '_' + key + '.gdt'
            relative = Path(module['architecture']) / filename
            jobs.append({'module': module['module'], 'architecture': module['architecture'],
                         'pdb_path': pdb['path'], 'pdb_key': key,
                         'output': str(stage / relative), 'layout': str(work / f'{number}.layout.tsv')})
            selected.append((report, parsed, relative))
        if jobs:
            ghidra_reports = run_headless(ghidra, jobs, work / 'headless')
            for job, ghidra_report, (report, parsed, relative) in zip(jobs, ghidra_reports, selected):
                comparison = compare_layouts(parsed, Path(job['layout']).read_text())
                report.update(status='verified', archive=relative.as_posix(),
                              ghidra=ghidra_report, llvm=comparison)
                if comparison['failures']:
                    (work / 'verification-failure.json').write_text(json.dumps(reports, indent=2) + '\n')
                    raise ValueError(f'LLVM layout verification failed for {report["module"]}; see {work}')
        verification = {'coverage': COVERAGE, 'ghidra': info, 'modules': reports}
        (stage / 'verification.json').write_text(json.dumps(verification, indent=2) + '\n')
        completed_manifest = dict(manifest, status='complete', ghidra=info)
        (stage / 'sources.json').write_text(json.dumps(completed_manifest, indent=2) + '\n')
        paths = sorted(p for p in stage.rglob('*') if p.is_file() and not p.name.endswith(('.lock', '.ulock')))
        (stage / 'SHA256SUMS').write_text(''.join(f'{sha256_file(p)}  {p.relative_to(stage).as_posix()}\n' for p in paths))
        # Publication is one rename on the same filesystem; never replace a completed set.
        if destination.exists():
            raise ValueError(f'Output appeared while building; refusing to overwrite: {destination}')
        stage.rename(destination)
    # Only published sets can discard diagnostics; cleanup cannot undo success.
    try:
        shutil.rmtree(work)
    except OSError:
        pass
    return destination, verification
