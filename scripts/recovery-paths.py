"""Path/identity helpers extracted for non-destructive recovery exports."""

import contextlib
import hashlib
import os
from pathlib import Path
import stat

SUFFIX = '.L0CK3D'
QDIR = '.rolling-delete-quarantine'
PDIR = '.rolling-delete-pins'

class Refused(RuntimeError):
    pass

def canonical(path):
    p = Path(path)
    if not p.is_absolute() or '..' in p.parts:
        raise Refused('Absolute, non-traversing paths required')
    return p

@contextlib.contextmanager
def parent_fd(path):
    p = canonical(path)
    if p == Path('/'):
        raise Refused('Root itself is not a file')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        yield fd, p.name
    finally:
        os.close(fd)

@contextlib.contextmanager
def readonly(path):
    with parent_fd(path) as (directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Refused('Regular files required')
            yield fd
        finally:
            os.close(fd)

def identity(info):
    return {k: getattr(info, 'st_' + k) for k in ('dev', 'ino', 'size', 'mtime_ns')}

def digest_fd(fd):
    before = identity(os.fstat(fd))
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    for block in iter(lambda: os.read(fd, 1024 * 1024), b''):
        digest.update(block)
    if before != identity(os.fstat(fd)):
        raise Refused('File changed while reading')
    return digest.hexdigest()

def mapping(source, source_root, output_root):
    source = canonical(source)
    source_root, output_root = canonical(source_root), canonical(output_root)
    try:
        relative = source.relative_to(source_root)
    except ValueError:
        raise Refused('Source outside approved root')
    if not relative.parts or not source.name.endswith(SUFFIX):
        raise Refused('Source must have ciphertext suffix')
    if any(p in (QDIR, PDIR) for p in relative.parts):
        raise Refused('Transaction internals cannot be candidates')
    return output_root / relative.parent / source.name[:-len(SUFFIX)]

def valid_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

def exists(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False

def private_dir(parent, name):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(fd)
        raise Refused('Transaction directory must be owner-only')
    return fd
