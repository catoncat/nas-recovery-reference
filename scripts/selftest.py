#!/usr/bin/env python3
"""Run temporary synthetic fixtures in separate processes; no live incident I/O."""
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
TESTS = ['test-recovery-manifest.py', 'test-recovery-runner.py',
         'test-recovery-runner-v2.py', 'test-recovery-runner-v3.py',
         'test-publication-eligibility.py', 'test-reference-adapter.py',
         'test-inplace-recover.py', 'test-inplace-improvements.py']

if __name__ == '__main__':
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for name in TESTS:
        result = subprocess.run([sys.executable, '-B', str(HERE / name)], env=environment)
        if result.returncode:
            raise SystemExit(result.returncode)
    print(json.dumps(dict(state='synthetic-tests-passed', suites=len(TESTS), live_incident_access=False)))
