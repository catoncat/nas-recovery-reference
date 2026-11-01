#!/usr/bin/env python3
"""Plan or stream fixed metadata readers over an existing SSH connection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent


def plan(kind, config, hash_pids=()):
    config = Path(config).absolute()
    if config.is_symlink() or not config.is_file():
        raise ValueError('A regular existing incident SSH config is required')
    if any(n <= 0 for n in hash_pids):
        raise ValueError('Positive PID required')
    if kind == 'basic':
        if hash_pids:
            raise ValueError('--hash-pid is only for processes')
        script, remote = HERE / 'nas-basic.sh', 'sh -s'
    elif kind == 'processes':
        script = HERE / 'nas-processes.py'
        remote = 'python3 -B -' + ''.join(' --hash-pid %d' % n for n in hash_pids)
    else:
        raise ValueError('Unsupported operation')
    command = ['ssh', '-F', str(config), '-T', '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
               'victim-nas', remote]
    return command, script.read_bytes()


def execute(command, payload, output):
    output = Path(os.path.abspath(output))
    if any(p.is_symlink() for p in (output,) + tuple(output.parents)):
        raise ValueError('Output must not follow symlinks')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    started = time.time()
    with (output / 'stdout.private').open('xb') as out, (output / 'stderr.private').open('xb') as err:
        try:
            rc = subprocess.run(command, input=payload, stdout=out, stderr=err, timeout=180).returncode
        except subprocess.TimeoutExpired:
            rc = 124
        except OSError:
            rc = 125
    receipt = dict(started=started, ended=time.time(), returncode=rc,
                   script_sha256=hashlib.sha256(payload).hexdigest(), nas_writes_requested=False,
                   note='SSH success does not prove all remote sections complete; inspect private receipts.')
    with (output / 'receipt.json').open('x') as stream:
        json.dump(receipt, stream, indent=2)
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=['basic', 'processes'])
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--hash-pid', action='append', type=int, default=[])
    p.add_argument('--execute', action='store_true')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    command, payload = plan(args.kind, args.config, args.hash_pid)
    if not args.execute:
        print(json.dumps(dict(executes=False, command=command, script_sha256=hashlib.sha256(payload).hexdigest())))
        return 0
    if args.output is None:
        p.error('--output must name a new private local directory')
    receipt = execute(command, payload, args.output)
    print(json.dumps(dict(returncode=receipt['returncode'], raw_output_printed=False)))
    return 0 if receipt['returncode'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
