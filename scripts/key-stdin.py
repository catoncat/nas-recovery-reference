#!/usr/bin/env python3
"""Feed one private 48-byte candidate to a reviewed local/SSH runner via stdin."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys


def read_material(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 48
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('Expected an owner-only independent 48-byte candidate file')
        value = os.read(fd, 49)
        after = os.fstat(fd)
        if len(value) != 48 or (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Candidate changed while reading')
        return value
    finally:
        os.close(fd)


def feed(path, command):
    if not command:
        raise ValueError('Supply a reviewed runner command after --')
    material = read_material(path)
    line = b'KEY48:' + material.hex().encode('ascii') + b'\n'
    try:
        # No shell, no key argv/env, no terminal echo. Child output goes directly
        # to the caller's private destination. The receiver must be reviewed.
        return subprocess.run(command, input=line, check=False).returncode
    finally:
        del line, material


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    try:
        return feed(args.key_file, command)
    except (OSError, ValueError) as error:
        print('Key stdin setup failed: ' + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
