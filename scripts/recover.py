#!/usr/bin/env python3
"""Explicit single-root adapter. Plan by default; execution is a separate command."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def marker_value(value):
    if not re.fullmatch('[0-9a-fA-F]{8}', value):
        raise argparse.ArgumentTypeError('Marker must be exactly 8 hexadecimal characters')
    return bytes.fromhex(value)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan', help='Metadata-only exact single-root inventory; writes only the requested bundle')
    for arg in ['source-base', 'approved-source-root', 'target-root', 'target-identity', 'bundle-out']:
        plan.add_argument('--' + arg, type=Path, required=True)
    observe = sub.add_parser('observe-target', help='Linux block-backed USB mount identity; does not write or mount')
    observe.add_argument('--mount', required=True)
    run = sub.add_parser('run', help='Check approved bundle by default; --execute writes new recovery outputs')
    for arg in ['bundle', 'target-identity', 'state-dir', 'approved-source-root', 'expected-manifest-sha256']:
        run.add_argument('--' + arg, required=True)
    run.add_argument('--marker', type=marker_value, required=True)
    run.add_argument('--candidate', choices=['baseline', 'v2', 'v3'], default='baseline')
    run.add_argument('--active-directories', type=int, default=0, help='v3 only; 0 disables experimental locality restriction')
    run.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.command == 'plan':
        pre = load('reference_preflight', 'recovery-manifest.py')
        source = pre.canonical(args.approved_source_root)
        base = pre.canonical(args.source_base)
        if source == base:
            raise ValueError('Use a scope strictly below source-base')
        identity = json.loads(args.target_identity.read_text())
        target = pre.canonical(args.target_root); mount = pre.canonical(identity['mount'])
        if mount not in target.parents:
            raise ValueError('Target root must be below the reviewed mount')
        # Probe current free space; identity itself still needs independent operator review.
        proposal = dict(jobs=[dict(group=source.name, source=str(source), output_relative=str(source.relative_to(base)))],
            destination=dict(proposed_mount=str(mount), proposed_root=target.name, filesystem=identity['filesystem'],
                expected_usb=identity['usb_id'], last_free_bytes=os.statvfs(mount).f_bavail * os.statvfs(mount).f_frsize,
                last_observed_at=time.time(), reserve_bytes=50_000_000_000, metadata_budget_bytes=10_000_000_000))
        bundle = pre.make_manifest(proposal, base, target, approved_source_root=source)
        # Keep metadata outside the full source base and destination mount.
        out = pre.canonical(args.bundle_out)
        for forbidden in [base, mount]:
            if out == forbidden or forbidden in out.parents:
                raise ValueError('Bundle must be outside source-base and destination mount')
        with out.open('x') as stream:
            json.dump(bundle, stream, ensure_ascii=True, indent=2); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps(dict(manifest_sha256=bundle['hashes']['manifest'], summary=bundle['summary'])))
        return 0 if bundle['summary']['preflight_passed'] else 2
    suffix = '' if args.command == 'observe-target' or args.candidate == 'baseline' else '-' + args.candidate
    module = load('reference_runner', 'recovery-runner' + suffix + '.py')
    if args.command == 'observe-target':
        print(json.dumps(module.observe_target(args.mount), indent=2)); return 0
    if args.candidate != 'v3' and args.active_directories:
        raise ValueError('Directory restriction is available only in v3')
    master = None
    if args.execute:
        line = sys.stdin.buffer.readline(128).strip()
        if not re.fullmatch(rb'KEY48:[0-9a-fA-F]{96}', line):
            raise ValueError('Expected one KEY48 line on stdin; never use argv or an environment variable for the key')
        master = bytes.fromhex(line[6:].decode('ascii')); del line
    options = dict(approved_source_root=args.approved_source_root)
    if args.candidate == 'v3':
        options['max_active_directories'] = args.active_directories
    runner = module.Export(json.loads(Path(args.bundle).read_text()), json.loads(Path(args.target_identity).read_text()),
        args.state_dir, args.expected_manifest_sha256, master, args.marker, **options)
    result = runner.run(args.execute)
    del master
    print(json.dumps(result, ensure_ascii=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
