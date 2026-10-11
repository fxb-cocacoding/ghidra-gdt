import http.client
import os
import shutil
import tempfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .identity import normalize_module, read_pdb, sha256_file


class Cache:
    def __init__(self, root, offline=False):
        self.root = Path(root).resolve()
        self.offline = offline

    def path(self, relative_path):
        relative_path = Path(relative_path)
        destination = (self.root / relative_path).resolve()
        if relative_path.is_absolute() or not destination.is_relative_to(self.root) or destination == self.root:
            raise ValueError('Cache path must stay inside the cache root')
        return destination

    @staticmethod
    def _verify(path, sha256=None, validator=None, require_record=False):
        actual = sha256_file(path)
        if sha256 and actual != sha256.lower():
            raise ValueError(f'SHA-256 mismatch for {path}: expected {sha256}, got {actual}')
        hash_path = Path(str(path)+'.sha256')
        if require_record and hash_path.is_file():
            recorded = hash_path.read_text().strip()
            if actual != recorded:
                raise ValueError(f'Cached SHA-256 mismatch for {path}: expected {recorded}, got {actual}')
        elif require_record and not sha256 and validator is None:
            raise ValueError(f'Unverified cache entry has no SHA-256 record: {path}')
        if validator is not None:
            if validator(path) is False:
                raise ValueError(f'Validation failed for {path}')
        return actual

    @staticmethod
    def _record_hash(path, digest):
        target = Path(str(path)+'.sha256')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', prefix='.hash-', dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(digest+'\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def import_file(self, source, relative_path, sha256=None, validator=None):
        """Verify and retain a local artifact; this never requires network access."""
        source = Path(source).resolve()
        destination = self.path(relative_path)
        digest = self._verify(source, sha256, validator, require_record=(source == destination))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source == destination:
            self._record_hash(destination, digest)
            return destination
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix='import-', dir=destination.parent, delete=False) as stream:
                temporary = Path(stream.name)
                with source.open('rb') as input_stream:
                    shutil.copyfileobj(input_stream, stream)
                stream.flush()
                os.fsync(stream.fileno())
            # Verify the copy too, including a possible change in the source while copying.
            self._verify(temporary, digest, validator)
            os.replace(temporary, destination)
            self._record_hash(destination, digest)
            return destination
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def fetch(self, url, relative_path, sha256=None, validator=None, *, refresh=False):
        destination = self.path(relative_path)
        if destination.is_file() and (not refresh or self.offline):
            try:
                digest = self._verify(destination, sha256, validator, require_record=True)
            except (ValueError, OSError):
                if self.offline:
                    raise
            else:
                self._record_hash(destination, digest)
                return destination
        if self.offline:
            raise FileNotFoundError(f'Artifact unavailable in offline cache: {destination}')
        if not url.startswith(('https://', 'http://')):
            raise ValueError(f'Unsupported download URL: {url}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(3):
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(prefix='download-', dir=destination.parent, delete=False) as stream:
                    temporary = Path(stream.name)
                    request = Request(url, headers={'User-Agent': 'ghidra-gdt/1.0'})
                    with urlopen(request, timeout=60) as response:
                        shutil.copyfileobj(response, stream, length=1024*1024)
                        expected_size = getattr(response, 'headers', {}).get('Content-Length')
                        if expected_size is not None and stream.tell() != int(expected_size):
                            raise ValueError(f'Incomplete download: expected Content-Length {expected_size}, got {stream.tell()}')
                    stream.flush()
                    os.fsync(stream.fileno())
                digest = self._verify(temporary, sha256, validator)
                os.replace(temporary, destination)
                self._record_hash(destination, digest)
                return destination
            except (OSError, URLError, ValueError, EOFError, http.client.HTTPException) as exc:
                if attempt == 2:
                    if isinstance(exc, http.client.HTTPException):
                        raise OSError(f'Incomplete HTTP download from {url}: {exc}') from exc
                    if isinstance(exc, EOFError):
                        raise ValueError(f'Invalid artifact from {url}: {exc}') from exc
                    raise
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        raise RuntimeError('Download retry limit exceeded')


def ensure_pdb(record, cache):
    result = normalize_module(record)
    if not result.get('pdb'):
        raise ValueError(f'{result["module"]}: PDB identity is missing')
    pdb = result['pdb']
    key = pdb['guid'].replace('-', '') + format(pdb['age'], 'X')
    relative = Path('symbols') / pdb['filename'] / key / pdb['filename']

    def validate(path):
        actual = read_pdb(path)
        expected = {field: pdb[field] for field in ('guid', 'age')}
        if actual != expected:
            raise ValueError(f'PDB identity mismatch for {result["module"]}: expected {expected}, got {actual}')

    url = pdb.get('download_url') or f'https://msdl.microsoft.com/download/symbols/{pdb["filename"]}/{key}/{pdb["filename"]}'
    local = Path(pdb['path']) if pdb.get('path') else None
    if local is not None and local.is_file():
        target = cache.import_file(local, relative, sha256=pdb.get('sha256'), validator=validate)
    else:
        target = cache.fetch(url, relative, sha256=pdb.get('sha256'), validator=validate)
    pdb.update(path=str(target), sha256=sha256_file(target), download_url=url)
    return result
