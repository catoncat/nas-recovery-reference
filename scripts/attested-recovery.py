#!/usr/bin/env python3
"""Candidate source-binding producer. Synthetic tests only; not NAS-deployed.

Uses the existing reviewed cipher/layout primitives without changing them.
Requires a trusted, exclusively managed recovery environment. The key is an
in-memory argument or KEY48 line on stdin, never a filename/argv/log value.
"""
import argparse
import contextlib
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

dependency_spec = importlib.util.spec_from_file_location('reference_dependencies', Path(__file__).with_name('check-dependencies.py'))
dependency = importlib.util.module_from_spec(dependency_spec); dependency_spec.loader.exec_module(dependency)
VENDOR = dependency.verify()
sys.path.insert(0, str(VENDOR))
from decrypt_copy import CALL_LIMIT, FOOTER_SIZE, RecoveryError, chacha8_call, encrypted_segments, read_footer, unwrap_record

spec = importlib.util.spec_from_file_location('recovery_path_support', Path(__file__).with_name('recovery-paths.py'))
rolling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rolling)


def stable(info):
    result = rolling.identity(info)
    result.update(ctime_ns=info.st_ctime_ns, nlink=info.st_nlink)
    return result


def regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RecoveryError('Independent regular file required; links refused')


def check_name(directory, name, before):
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    regular(current)
    if stable(current) != stable(before):
        raise RecoveryError('File pathname or metadata changed')


def stream_decode(stream, before, layout, key, nonce, emit, hook, timings=None):
    """Read every original byte in order for binding, after parsing EOF footer."""
    footer, original_size, mode, percent, segments = layout
    cipher_hash, plain_hash = hashlib.sha256(), hashlib.sha256()
    position = counter = 0
    stream.seek(0)

    def transfer(length, encrypted):
        nonlocal position, counter
        while length:
            amount = min(length, CALL_LIMIT)
            if timings is None:
                raw = stream.read(amount)
            else:
                with measured(timings, 'source_read_seconds'):
                    raw = stream.read(amount)
            if len(raw) != amount:
                raise RecoveryError('Ciphertext truncated during recovery')
            if timings is None:
                cipher_hash.update(raw)
                if encrypted:
                    block, counter = chacha8_call(raw, key, nonce, counter)
                else:
                    block = raw
                plain_hash.update(block)
                emit(block)
            else:
                with measured(timings, 'source_hash_seconds'):
                    cipher_hash.update(raw)
                if encrypted:
                    with measured(timings, 'decrypt_seconds'):
                        block, counter = chacha8_call(raw, key, nonce, counter)
                else:
                    block = raw
                with measured(timings, 'plaintext_hash_seconds'):
                    plain_hash.update(block)
                with measured(timings, 'output_write_seconds'):
                    emit(block)
            length -= amount; position += amount
            hook('body-block')

    for offset, length in segments:
        transfer(offset-position, False)
        transfer(length, True)
    transfer(original_size-position, False)
    if timings is None:
        observed_footer = stream.read(FOOTER_SIZE)
        extra = stream.read(1)
    else:
        with measured(timings, 'source_read_seconds'):
            observed_footer = stream.read(FOOTER_SIZE)
            extra = stream.read(1)
    if observed_footer != footer or extra:
        raise RecoveryError('Ciphertext footer or length changed during recovery')
    with measured(timings, 'source_hash_seconds'):
        cipher_hash.update(observed_footer)
    if stable(os.fstat(stream.fileno())) != stable(before):
        raise RecoveryError('Ciphertext metadata changed during recovery')
    return dict(bytes=original_size, output_sha256=plain_hash.hexdigest(),
                cipher_sha256=cipher_hash.hexdigest(), mode=hex(mode),
                percent_parameter=percent, cipher_blocks_consumed=counter)


@contextlib.contextmanager
def measured(timings, stage):
    if timings is None:
        yield
        return
    started = time.perf_counter()
    try:
        yield
    finally:
        if timings is not None:
            timings[stage] = timings.get(stage, 0.0) + time.perf_counter() - started


def read_output(directory, name, expected_bytes, expected_hash, hook, *, sync=True, timings=None):
    """Complete readback; sync=False only for already-durable unchanged output.

    The default retains the original file fsync. Timings are wall-clock spans,
    not separate disk-versus-CPU measurements.
    """
    started = time.perf_counter() if timings is not None else None
    read_timed = False
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = os.fstat(fd); regular(before)
        if before.st_size != expected_bytes:
            raise RecoveryError('Existing plaintext length differs')
        digest = hashlib.sha256()
        for block in iter(lambda: os.read(fd, CALL_LIMIT), b''):
            digest.update(block); hook('output-readback-block')
        if stable(os.fstat(fd)) != stable(before):
            raise RecoveryError('Existing plaintext changed during readback')
        check_name(directory, name, before)
        if not hmac.compare_digest(digest.hexdigest(), expected_hash):
            raise RecoveryError('Existing plaintext full readback mismatch')
        if timings is not None:
            timings['readback_hash_seconds'] = timings.get('readback_hash_seconds', 0.0) + time.perf_counter() - started
        read_timed = True
        if sync:
            with measured(timings, 'output_fsync_seconds'):
                os.fsync(fd)
        return before
    finally:
        if timings is not None and not read_timed:
            timings['readback_hash_seconds'] = timings.get('readback_hash_seconds', 0.0) + time.perf_counter() - started
        os.close(fd)


def attest(source, output, source_root, output_root, master, marker, *,
           existing_record=None, fault=None, timings=None):
    """New recovery or independently re-decrypt and verify historical output.

    existing_record=None creates a new O_EXCL output; otherwise output is never
    written and every byte of decoded source and current plaintext is checked
    against the historical completion hash. Returns a journal-compatible record.
    """
    if not isinstance(master, bytes) or len(master) != 48:
        raise RecoveryError('Exactly 48 in-memory key bytes required')
    if not isinstance(marker, bytes) or len(marker) != 4:
        raise RecoveryError('Explicit four-byte session marker required')
    source, output = rolling.canonical(source), rolling.canonical(output)
    source_root, output_root = rolling.canonical(source_root), rolling.canonical(output_root)
    if (source_root == Path('/') or output_root == Path('/') or source_root == output_root
            or source_root in output_root.parents or output_root in source_root.parents):
        raise RecoveryError('Approved source/output trees must be disjoint')
    if rolling.mapping(source, source_root, output_root) != output:
        raise RecoveryError('Source/output mapping differs from approved roots')
    hook = fault or (lambda point: None)
    expected_hash = None
    if existing_record is not None:
        if (existing_record.get('state') not in ('written-complete', 'written-verified')
                or existing_record.get('source') != str(source)
                or existing_record.get('output') != str(output)
                or not rolling.valid_sha(existing_record.get('output_sha256'))):
            raise RecoveryError('Historical completion record or pair binding invalid')
        expected_hash = existing_record['output_sha256']
    created = None
    with rolling.parent_fd(source) as (srcdir, srcname), rolling.parent_fd(output) as (outdir, outname):
        source_fd = os.open(srcname, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NOATIME', 0), dir_fd=srcdir)
        before = os.fstat(source_fd)
        try:
            regular(before)
            check_name(srcdir, srcname, before)
            with os.fdopen(source_fd, 'rb', closefd=False) as stream:
                with measured(timings, 'footer_parse_key_unwrap_seconds'):
                    layout = read_footer(stream, before.st_size, marker)
                    footer, original_size, _, _, _ = layout
                    key, nonce = unwrap_record(footer, master)  # Fail before output creation on wrong key.
                if existing_record is not None and existing_record['bytes'] != original_size:
                    raise RecoveryError('Historical completion length differs from ciphertext footer')
                destination_fd = None
                if existing_record is None:
                    destination_fd = os.open(outname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=outdir)
                    created = os.fstat(destination_fd)
                try:
                    def emit(block):
                        if destination_fd is not None:
                            view = memoryview(block)
                            while view:
                                amount = os.write(destination_fd, view)
                                if amount <= 0:
                                    raise RecoveryError('Plaintext write made no progress')
                                view = view[amount:]
                    with measured(timings, 'recover_copy_seconds'):
                        result = stream_decode(stream, before, layout, key, nonce, emit, hook, timings=timings)
                    if expected_hash is not None and not hmac.compare_digest(result['output_sha256'], expected_hash):
                        raise RecoveryError('Re-decrypted source differs from historical completed plaintext hash')
                    if destination_fd is not None:
                        after_output = os.fstat(destination_fd); regular(after_output)
                        if (after_output.st_dev,after_output.st_ino)!=(created.st_dev,created.st_ino) or after_output.st_size != result['bytes']:
                            raise RecoveryError('New output identity or length differs')
                        with measured(timings, 'output_fsync_seconds'):
                            os.fsync(destination_fd); os.fsync(outdir)
                        check_name(outdir, outname, after_output)
                    else:
                        read_output(outdir, outname, result['bytes'], expected_hash, hook, timings=timings)
                    hook('before-final-source-check')
                    if stable(os.fstat(source_fd)) != stable(before):
                        raise RecoveryError('Ciphertext changed before attestation')
                    check_name(srcdir, srcname, before)
                    kind = 'recovery-read-v1' if existing_record is None else 'verified-redecrypt-v1'
                    attestation = dict(kind=kind,identity=rolling.identity(before),ctime_ns=before.st_ctime_ns,
                        sha256=result.pop('cipher_sha256'),source=str(source),output=str(output),
                        output_sha256=result['output_sha256'])
                    return dict(state='written-complete',source=str(source),output=str(output),
                                source_attestation=attestation,**result)
                finally:
                    if destination_fd is not None:
                        os.close(destination_fd)
        except BaseException:
            if created is not None:
                try:
                    current = os.stat(outname, dir_fd=outdir, follow_symlinks=False)
                    if (current.st_dev,current.st_ino)==(created.st_dev,created.st_ino):
                        os.unlink(outname,dir_fd=outdir);os.fsync(outdir)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(source_fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--source-root',required=True)
    parser.add_argument('--output-root',required=True)
    parser.add_argument('--expected-marker',required=True,help='Four public marker bytes as 8 hexadecimal characters')
    parser.add_argument('--existing-record',type=Path,help='Historical completion JSON object; verify only, never rewrite output')
    args=parser.parse_args()
    record=None
    if args.existing_record:
        with rolling.readonly(args.existing_record) as fd:
            with os.fdopen(fd,'r',closefd=False) as stream:record=json.load(stream)
    line=sys.stdin.buffer.readline(128).strip()
    if not line.startswith(b'KEY48:') or len(line)!=102:
        raise RecoveryError('KEY48 stdin line required; never pass key in arguments')
    try:master=bytes.fromhex(line[6:].decode('ascii'));marker=bytes.fromhex(args.expected_marker)
    except ValueError:raise RecoveryError('Key input or marker encoding invalid')
    del line
    result=attest(args.source,args.output,args.source_root,args.output_root,master,marker,existing_record=record)
    del master
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
