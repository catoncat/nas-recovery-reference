#!/usr/bin/env python3
"""Temporary synthetic fixtures; emulate FICLONE/syncfs on non-Linux hosts.

The emulation tests cipher/journal/control flow, not CoW or power-loss durability.
No incident keys, data, network connections or host-wide sync are used.
"""
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('synthetic_inplace', 'inplace-recover.py')
v = load('synthetic_revert', 'inplace-revert.py')
from file_layout import encrypted_segments
MARKER = bytes.fromhex('a1b2c3d4')  # Synthetic, never a default for real use.
SUFFIX = '.encrypted'


class InplaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.inplace-test-', dir=HERE.parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.master = os.urandom(48)
        self.controllers = []
        self.addCleanup(self.close_controllers)
        self.barriers = []
        def syncfs(fd):
            self.barriers.append(fd)
            return 0
        library = types.SimpleNamespace(syncfs=syncfs)
        self.addCleanup(patch.stopall)
        patch.object(m.ctypes, 'CDLL', return_value=library).start()
        patch.object(m.fcntl, 'ioctl', side_effect=self.clone).start()

    @staticmethod
    def clone(destination, command, source):
        if command != m.FICLONE:
            raise AssertionError('unexpected ioctl')
        offset = 0
        while True:
            data = os.pread(source, 8 << 20, offset)
            if not data:
                break
            assert os.pwrite(destination, data, offset) == len(data)
            offset += len(data)

    def close_controllers(self):
        for recovery in self.controllers:
            try: recovery.db.close()
            except Exception: pass
            recovery.lock.close()
            try: os.close(recovery.volume_fd)
            except OSError: pass

    def recovery(self, state='state', **kwargs):
        options = {'suffix': SUFFIX}
        options.update(kwargs)
        recovery = m.Recovery(self.root / state, [str(self.inputs)], self.master, 0,
                              MARKER, **options)
        self.controllers.append(recovery)
        recovery.status['root'] = str(self.inputs)
        return recovery

    def cipher(self, name, data, mode=0x24, percent=0):
        key, nonce = os.urandom(32), os.urandom(8)
        enc = Cipher(algorithms.AES(self.master[16:]), modes.CBC(self.master[:16])).encryptor()
        footer = bytearray(588)
        footer[:48] = enc.update(key + nonce + nonce) + enc.finalize()
        footer[568:572] = MARKER
        footer[572:576] = bytes((mode, percent, 0x20, 0))
        struct.pack_into('<Q', footer, 580, len(data))
        ciphertext, counter = bytearray(data), 0
        for offset, length in encrypted_segments(len(data), mode, percent):
            while length:
                amount = min(length, m.CALL_LIMIT)
                block, counter = m.chacha8_call(bytes(ciphertext[offset:offset+amount]), key, nonce, counter)
                ciphertext[offset:offset+amount] = block
                offset += amount
                length -= amount
        source = self.inputs / (name + SUFFIX)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(ciphertext + footer)
        os.chmod(source, 0o640)
        os.utime(source, ns=(1600000000123456789, 1600000001123456789))
        return source, hashlib.sha256(data).hexdigest(), hashlib.sha256(ciphertext+footer).hexdigest()

    def prepare(self, recovery, source):
        result = recovery.prepare(str(source))
        self.assertEqual(result[0], 'ready', result)
        return result[1]

    def test_three_modes_sha_revert_and_recover(self):
        recovery = self.recovery()
        fixtures = []
        for mode, percent, size in ((0x24, 0, 1048701), (0x26, 0, (3 << 20)+17),
                                    (0x25, 10, (6 << 20)+123), (0x25, 50, (61 << 20)+123)):
            fixtures.append(self.cipher('mode-%x-%d.bin' % (mode, percent), os.urandom(size), mode, percent))
        records = [self.prepare(recovery, source) for source, _, _ in fixtures]
        recovery.commit(records)
        self.assertEqual(recovery.status['files'], 0)  # Install waits for next barrier.
        recovery.flush_pending()
        self.assertEqual(recovery.status['files'], 4)
        for (source, plain_sha, cipher_sha), record in zip(fixtures, records):
            target = Path(record['target'])
            self.assertFalse(source.exists())
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), plain_sha)
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            self.assertEqual(target.stat().st_mtime_ns, 1600000001123456789)
            v.revert(record, self.master, MARKER)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), cipher_sha)
        recovery.lock.close()
        second = self.recovery('roundtrip')
        second.run()
        for source, plain_sha, _ in fixtures:
            self.assertEqual(hashlib.sha256(Path(str(source)[:-len(SUFFIX)]).read_bytes()).hexdigest(), plain_sha)

    def test_resume_linked_target_and_missing_source(self):
        recovery = self.recovery()
        fixtures = [self.cipher(str(i)+'.bin', os.urandom(8192)) for i in range(2)]
        for index, (source, _, _) in enumerate(fixtures):
            record = self.prepare(recovery, source)
            m.append(recovery.state/'footer-archive.jsonl', [record], durable=True)
            os.link(record['tmp'], record['target'])
            os.unlink(record['tmp'])
            if index: source.unlink()
        abandoned = self.inputs/'.abandoned.inplace-0123456789abcdef'
        abandoned.write_bytes(b'partial')
        recovery.db.close(); recovery.lock.close()
        resumed = self.recovery()
        resumed.run()
        self.assertEqual(resumed.status['files'], 2)
        self.assertEqual(resumed.status['errors'], 0)
        self.assertFalse(abandoned.exists())
        for source, plain_sha, _ in fixtures:
            self.assertEqual(hashlib.sha256(Path(str(source)[:-len(SUFFIX)]).read_bytes()).hexdigest(), plain_sha)

    def test_archive_barrier_precedes_unlink_and_next_batch_completion(self):
        recovery = self.recovery()
        first = self.cipher('a.bin', b'a'*100)[0]
        second = self.cipher('b.bin', b'b'*100)[0]
        def barrier(drain=False):
            rows = [json.loads(line) for line in (recovery.state/'footer-archive.jsonl').read_text().splitlines()]
            self.assertTrue(rows)
            if len(rows) == 1:
                self.assertTrue(first.exists())
            else:
                self.assertTrue(second.exists())
        recovery.sync_volume = barrier
        recovery.commit([self.prepare(recovery, first)])
        self.assertEqual(recovery.status['files'], 0)
        recovery.commit([self.prepare(recovery, second)])
        self.assertEqual(recovery.status['files'], 1)
        recovery.sync_volume = lambda drain=False: None
        recovery.flush_pending()
        self.assertEqual(recovery.status['files'], 2)

    def test_collision_and_wrong_marker_preserve_source(self):
        recovery = self.recovery()
        source = self.cipher('keep.bin', b'original')[0]
        target = self.inputs/'keep.bin'
        target.write_bytes(b'preexisting')
        self.assertEqual(recovery.prepare(str(source))[0], 'conflicts')
        self.assertEqual(target.read_bytes(), b'preexisting')
        target.unlink()
        recovery.marker = bytes.fromhex('d4c3b2a1')
        self.assertEqual(recovery.prepare(str(source))[0], 'skipped')
        self.assertTrue(source.exists())

    def test_ficlone_failure_does_not_fall_back_or_delete(self):
        recovery = self.recovery()
        source = self.cipher('keep.bin', b'original')[0]
        with patch.object(m.fcntl, 'ioctl', side_effect=OSError(errno.EOPNOTSUPP, 'not supported')):
            self.assertEqual(recovery.prepare(str(source))[0], 'errors')
        self.assertTrue(source.exists())
        self.assertFalse((self.inputs/'keep.bin').exists())
        self.assertFalse(list(self.inputs.glob('.*.inplace-*')))

    def test_cross_filesystem_source_refused(self):
        recovery = self.recovery()
        source = self.cipher('keep.bin', b'original')[0]
        with patch.object(m.os, 'lstat', return_value=types.SimpleNamespace(st_dev=-1)):
            result = recovery.prepare(str(source))
        self.assertEqual(result[0], 'skipped')
        self.assertIn('filesystem boundary', result[2])
        self.assertTrue(source.exists())

    def test_failed_archive_sync_keeps_ciphertext(self):
        recovery = self.recovery()
        source = self.cipher('keep.bin', b'original')[0]
        record = self.prepare(recovery, source)
        with patch.object(recovery, 'sync_volume', side_effect=OSError('synthetic sync failure')):
            with self.assertRaises(OSError): recovery.commit([record])
        self.assertTrue(source.exists())
        self.assertFalse(Path(record['target']).exists())
        self.assertEqual(recovery.status['files'], 0)

    def test_magic_variants_and_unknown_retained(self):
        recovery = self.recovery()
        variants = [('png.jpg', b'\x89PNG\r\n\x1a\n'), ('ole.xlsx', bytes.fromhex('d0cf11e0a1b11ae1')),
                    ('old.mov', b'\0\0\0\x10mdat'), ('._image.jpeg', bytes.fromhex('0005160700020000')),
                    ('._single.jpeg', bytes.fromhex('0005160000020000'))]
        batch = []
        for name, head in variants:
            source = self.cipher(name, head+os.urandom(1024))[0]
            batch.append(self.prepare(recovery, source))
        for size in (162, 165):
            data = bytearray(size)
            name, marker, start = b'TestUser', * ((54, 56) if size == 162 else (55, 57))
            data[0] = len(name); data[1:1+len(name)] = name
            data[marker] = len(name); data[start:start+len(name)*2] = 'TestUser'.encode('utf-16-le')
            self.assertTrue(m.office_owner_format('~$test.xlsx', data, size))
            wrong = bytearray(data); wrong[start] ^= 1
            self.assertFalse(m.office_owner_format('~$test.xlsx', wrong, size))
            source = self.cipher('~$test-%d.xlsx'%size, bytes(data))[0]
            batch.append(self.prepare(recovery, source))
        bad = self.cipher('unknown.jpg', b'not a recognized header')[0]
        self.assertEqual(recovery.prepare(str(bad))[0], 'magic_mismatch')
        self.assertTrue(bad.exists())
        empty = self.cipher('empty.bin', b'')[0]
        batch.append(self.prepare(recovery, empty))
        recovery.commit(batch); recovery.flush_pending()
        self.assertEqual(recovery.status['files'], 8)

    def test_explicit_exclusions_hidden_files_and_links(self):
        recovery = self.recovery(exclude_prefixes=('@',))
        hidden = self.cipher('.hidden/a.bin', b'hello')[0]
        excluded = self.cipher('@skip/a.bin', b'keep')[0]
        source = self.cipher('normal.bin', b'normal')[0]
        os.symlink(source, self.inputs/('link'+SUFFIX))
        os.link(source, self.inputs/('hardlink'+SUFFIX))
        clear = self.inputs/'clear.txt'; clear.write_bytes(b'unencrypted original')
        recovery.run()
        self.assertFalse(hidden.exists())
        self.assertTrue(excluded.exists())
        self.assertTrue(source.exists())
        self.assertEqual(clear.read_bytes(), b'unencrypted original')
        self.assertEqual(recovery.status['skipped'], 2)

    def test_torn_tail_rebuilt_and_mid_journal_corruption_refused(self):
        recovery = self.recovery()
        source = self.cipher('a.bin', b'a')[0]
        recovery.commit([self.prepare(recovery, source)])
        recovery.db.close(); recovery.lock.close()
        with (recovery.state/'footer-archive.jsonl').open('ab') as stream: stream.write(b'{broken')
        resumed = self.recovery()
        resumed.run()
        self.assertEqual(resumed.status['files'], 1)
        resumed.lock.close()
        with (resumed.state/'footer-archive.jsonl').open('ab') as stream: stream.write(b'{broken\n{}\n')
        with self.assertRaisesRegex(RuntimeError, 'Corrupt non-final'):
            self.recovery()

    def test_same_state_lock_and_changed_configuration_refused(self):
        recovery = self.recovery()
        with self.assertRaises(BlockingIOError): self.recovery()
        recovery.lock.close()
        with self.assertRaisesRegex(ValueError, 'configuration differs'):
            self.recovery(suffix='.different')

    def test_revert_collision_preserves_plaintext(self):
        recovery = self.recovery()
        source = self.cipher('a.bin', b'a')[0]
        record = self.prepare(recovery, source)
        recovery.commit([record]); recovery.flush_pending()
        source.write_bytes(b'collision')
        with self.assertRaises(FileExistsError): v.revert(record, self.master, MARKER)
        self.assertEqual(Path(record['target']).read_bytes(), b'a')
        self.assertEqual(source.read_bytes(), b'collision')

    def test_pipeline_stop_drain_resume_and_overlap(self):
        recovery = self.recovery(threads=12)
        expected = [self.cipher('%04d.bin'%i, os.urandom(512)) for i in range(360)]
        original_prepare, original_commit = recovery.prepare, recovery.commit
        active, overlap, batches = [0], [False], []
        mutex = threading.Lock()
        def prepare(source):
            with mutex: active[0] += 1
            try:
                time.sleep(.003)
                return original_prepare(source)
            finally:
                with mutex: active[0] -= 1
        def commit(batch):
            with mutex: overlap[0] |= active[0] > 0
            batches.append(len(batch)); original_commit(batch)
            if len(batch) >= 256: (recovery.state/'STOP_REQUESTED').touch()
        recovery.prepare, recovery.commit = prepare, commit
        recovery.run(); recovery.lock.close()
        self.assertEqual(recovery.status['state'], 'stopped')
        self.assertEqual(recovery.status['installed_pending_files'], 0)
        self.assertTrue(overlap[0]); self.assertGreaterEqual(max(batches), 256)
        (recovery.state/'STOP_REQUESTED').unlink()
        resumed = self.recovery(); resumed.run()
        self.assertEqual(resumed.status['files'], 360)
        self.assertEqual(resumed.status['errors'], 0)
        for source, plain_sha, _ in expected:
            self.assertEqual(hashlib.sha256(Path(str(source)[:-len(SUFFIX)]).read_bytes()).hexdigest(), plain_sha)


if __name__ == '__main__':
    unittest.main(verbosity=2)
