#!/usr/bin/env python3
"""Verify a separately obtained pinned upstream checkout, without network access."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify():
    configured = os.environ.get('RECOVERY_CRYPTO_ROOT')
    if not configured:
        raise RuntimeError('Set RECOVERY_CRYPTO_ROOT to your separately obtained c3rb3r-rescue checkout; see docs/CODE.md')
    root = Path(configured)
    if not root.is_absolute() or not root.is_dir():
        raise RuntimeError('RECOVERY_CRYPTO_ROOT must be an absolute checkout directory')
    lock = json.loads((ROOT / 'DEPENDENCIES.json').read_text())
    for name, expected in lock['files'].items():
        path = root / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Pinned dependency absent or changed: ' + name)
    return root / 'skills/dsm-ransomware-rescue/scripts'


if __name__ == '__main__':
    verify()
    import cryptography
    import numpy
    print(json.dumps(dict(status='verified', cryptography=cryptography.__version__, numpy=numpy.__version__)))
