#!/usr/bin/env python3
"""Read-only publication gate for an already validated export runner.

No service API, chmod, rename, source deletion or file-content reread. Caller
must hold exclusive control of the completed unit on a trusted host through
mapping creation. Metadata evidence cannot defend against a hostile host.
"""
import os
from pathlib import Path
import stat


def verify_unit(runner, unit):
    # runner.validate() and load_log() must already have accepted the immutable
    # bundle and owned durable journal. Never accept a plan's completed flag.
    relative = Path(unit['relative_directory'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid publication directory')
    root = runner.target / relative
    expected = {e['id']: e for e in runner.manifest['entries']
                if root in Path(e['output']).parents}
    if not expected or set(unit['entry_ids']) != set(expected):
        raise ValueError('Unit does not cover its exact manifest subtree')
    if len(unit['entry_ids']) != len(expected):
        raise ValueError('Duplicate unit entry')
    files = set()
    directories = set()
    for ident, entry in expected.items():
        if ident not in runner.records:
            raise ValueError('Unit has incomplete files')
        runner._record_ok(entry, runner.records[ident])
        rel = Path(entry['output']).relative_to(root)
        files.add(str(rel))
        directories.update(str(p) for p in rel.parents if p != Path('.'))
    seen_files, seen_dirs = set(), set()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def walk(fd, prefix):
        before = os.fstat(fd)
        for name in os.listdir(fd):
            rel = prefix / name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if info.st_dev != runner.identity['st_dev']:
                raise ValueError('Nested filesystem in publication unit')
            if stat.S_ISDIR(info.st_mode):
                if str(rel) not in directories:
                    raise ValueError('Unexpected directory in publication unit')
                child = os.open(name, flags, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError('Directory replaced while opening')
                    seen_dirs.add(str(rel)); walk(child, rel)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                seen_files.add(str(rel))
            else:
                raise ValueError('Symlink or non-independent regular file refused')
        after = os.fstat(fd)
        if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Directory changed during observation')

    # Open each ancestor without following symlinks, including the unit root.
    fd = os.open('/', flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=fd); os.close(fd); fd = child
        if os.fstat(fd).st_dev != runner.identity['st_dev']:
            raise ValueError('Publication target device differs')
        walk(fd, Path('.'))
    finally:
        os.close(fd)
    if seen_files != files or seen_dirs != directories:
        raise ValueError('Actual directory differs from exact manifest')
    # Recheck records after enumeration: no success on a replaced known file.
    for ident, entry in expected.items():
        runner._record_ok(entry, runner.records[ident])
    return dict(unit_id=unit['id'], mapped_path=str(root), files=len(files),
                eligible_at_observation=True, published=False,
                condition='Exclusive trusted ownership must persist through mapping readback')
