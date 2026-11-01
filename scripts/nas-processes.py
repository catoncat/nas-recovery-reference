#!/usr/bin/env python3
"""Python 3.6+; read /proc metadata only. No mem, cmdline, environ, signals or writes.
Default is metadata; --hash-pid N explicitly reads that executable via /proc.
Raw JSON must go to private local storage. Names/paths are not trustworthy.
"""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path


def parse_stat(text):
    fields = text.rsplit(')', 1)[1].split()
    return {'state': fields[0], 'ppid': int(fields[1]), 'start_ticks': int(fields[19])}


def read_text(path, limit=262144):
    with path.open('r', errors='replace') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError('metadata_limit')
    return data


def inspect(proc, with_hash=False):
    before = parse_stat(read_text(proc / 'stat'))
    item = dict(before, pid=int(proc.name), errors=[])
    for field, filename in [('comm', 'comm'), ('io', 'io')]:
        try:
            item[field] = read_text(proc / filename).strip()
        except (OSError, ValueError) as exc:
            item['errors'].append(field + ':' + type(exc).__name__)
    try:
        item['exe'] = os.readlink(str(proc / 'exe'))
        item['deleted_exe'] = item['exe'].endswith(' (deleted)')
    except OSError as exc:
        item['errors'].append('exe:' + type(exc).__name__)
    threads = []
    try:
        for task in sorted((proc / 'task').iterdir()):
            if task.name.isdigit():
                try:
                    t = parse_stat(read_text(task / 'stat'))
                    status = read_text(task / 'status')
                    tracer = next((x.split(':', 1)[1].strip() for x in status.splitlines()
                                   if x.startswith('TracerPid:')), None)
                    threads.append(dict(t, tid=int(task.name), tracer_pid=tracer))
                except (OSError, ValueError, IndexError):
                    item['errors'].append('thread_unreadable')
        item['threads'] = threads
    except OSError:
        item['errors'].append('tasks_unreadable')
    if with_hash:
        try:
            h = hashlib.sha256()
            with (proc / 'exe').open('rb') as f:
                total = 0
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 256 * 1024 * 1024:
                        raise ValueError('exe_size_limit')
                    h.update(chunk)
            item['exe_sha256'] = h.hexdigest()
        except (OSError, ValueError) as exc:
            item['errors'].append('exe_hash:' + type(exc).__name__)
    after = parse_stat(read_text(proc / 'stat'))
    if before['start_ticks'] != after['start_ticks']:
        raise ValueError('pid_reused')
    item['state_after'] = after['state']
    item['identity_checked_at_boundaries'] = True
    return item


def collect(root=Path('/proc'), hash_pids=()):
    processes, unavailable = [], []
    for path in sorted(root.iterdir()):
        if not path.name.isdigit():
            continue
        try:
            processes.append(inspect(path, int(path.name) in hash_pids))
        except (OSError, ValueError, IndexError) as exc:
            unavailable.append({'pid': int(path.name), 'error': type(exc).__name__})
    return {'schema': 1, 'kind': 'proc-metadata', 'utc_epoch': time.time(),
            'euid': os.geteuid(), 'processes': processes, 'unavailable': unavailable,
            'limits': 'Non-atomic metadata. No malware verdict. No process memory read.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hash-pid', action='append', type=int, default=[])
    a = p.parse_args()
    if any(n <= 0 for n in a.hash_pid):
        p.error('positive PID required')
    print(json.dumps(collect(hash_pids=a.hash_pid), ensure_ascii=True))
