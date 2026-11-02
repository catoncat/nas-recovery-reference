"""Conservative Btrfs data headroom and in-flight allocation accounting."""
import os
import re
import subprocess
import threading
import time


def parse_usage(text):
    def number(label):
        match = re.search(r'^\s*'+re.escape(label)+r':\s*([0-9]+)', text, re.M)
        if not match:
            raise ValueError('missing Btrfs field: '+label)
        return int(match.group(1))
    estimated = number('Free (estimated)')
    match = re.search(r'Free \(estimated\):\s*\d+\s*\(min:\s*(\d+)\)', text)
    if not match:
        raise ValueError('missing Btrfs minimum estimate')
    minimum = int(match.group(1))
    unallocated = number('Device unallocated')
    chunks = re.findall(r'^Data,([^:]+):\s*Size:\s*(\d+),\s*Used:\s*(\d+)', text, re.M)
    if not chunks:
        raise ValueError('missing separate Btrfs data chunks')
    # Do not count free metadata as data. Refuse mixed data/metadata profiles.
    if any('Metadata' in profile for profile, _, _ in chunks):
        raise ValueError('mixed Btrfs data/metadata unsupported')
    data_free = sum(max(0, int(total)-int(used)) for _, total, used in chunks)
    # The CLI minimum already applies the most conservative observed profile
    # ratio to unallocated physical bytes. Also cap by raw data+unallocated.
    conservative = max(0, min(minimum, data_free+unallocated))
    return dict(estimated_bytes=estimated, minimum_bytes=minimum,
                unallocated_bytes=unallocated, data_chunk_free_bytes=data_free,
                conservative_bytes=conservative)


class SpaceBudget:
    def __init__(self, path, sampler=None, interval=15):
        self.path = str(path)
        self.sampler = sampler or self.sample_btrfs
        self.interval = interval
        self.lock = threading.RLock()
        self.sample = None
        self.sample_time = 0
        self.pending = {}
        self.completed_since_sample = 0

    def sample_btrfs(self):
        result = subprocess.run(['btrfs', 'filesystem', 'usage', '-b', self.path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=10, check=True, env=dict(os.environ, LC_ALL='C'))
        row = parse_usage(result.stdout.decode('utf-8','replace'))
        stat = os.statvfs(self.path)
        row['statvfs_bytes'] = stat.f_bavail*stat.f_frsize
        return row

    def snapshot(self, force=False):
        with self.lock:
            now = time.monotonic()
            if force or self.sample is None or now-self.sample_time >= self.interval:
                try:
                    self.sample = dict(self.sampler(), sampled_at=time.time(), error=None)
                    self.completed_since_sample = 0
                except Exception as error:
                    # A failed/stale Btrfs sample must never authorize new work.
                    self.sample = dict(conservative_bytes=0, sampled_at=time.time(),
                                       error=type(error).__name__+': Btrfs sample unavailable')
                self.sample_time = now
            pending = sum(self.pending.values())
            return dict(self.sample, pending_allocation_bytes=pending,
                        completed_allocation_since_sample=self.completed_since_sample,
                        available_bytes=max(0, self.sample['conservative_bytes']-
                                            pending-self.completed_since_sample))

    def acquire(self, token, cost, floor):
        with self.lock:
            row = self.snapshot()
            if row['available_bytes'] < floor+cost:
                return False
            if token in self.pending:
                raise ValueError('duplicate allocation reservation')
            self.pending[token] = cost
            return True

    def release(self, token):
        with self.lock:
            cost = self.pending.pop(token, 0)
            # Keep charging even a cancelled temp until the next kernel sample;
            # its transaction may not have released the blocks yet.
            self.completed_since_sample += cost
