#!/usr/bin/env python3
"""Read one known recovery state directory. No discovery, signals or writes."""
import argparse
import json
import os
from pathlib import Path
import stat
import time


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError('Independent regular metadata file required')
    return os.fdopen(fd, 'rb')


def read_status(path):
    with open_regular(path) as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Status exceeds metadata limit')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Expected a status object')
    return value


def journal_summary(path, max_bytes=256 * 1024 * 1024):
    seen, intents = set(), set()
    result = dict(complete_files=0, complete_bytes=0, journal_complete=True,
                  torn_tail=False, manifest_sha256=None, errors=[])
    amount = 0
    with open_regular(path) as stream:
        number = 0
        while True:
            raw = stream.readline(2 * 1024 * 1024 + 1)
            if not raw:
                break
            amount += len(raw); number += 1
            if len(raw) > 2 * 1024 * 1024 or amount > max_bytes:
                result['errors'].append('journal-read-limit'); result['journal_complete'] = False; break
            if not raw.endswith(b'\n'):
                result['torn_tail'] = True; result['journal_complete'] = False; break
            try:
                row = json.loads(raw)
                if number == 1:
                    if row.get('kind') != 'header':
                        raise ValueError('Expected current runner journal header')
                    result['manifest_sha256'] = row.get('manifest_sha256')
                    continue
                ident = row.get('entry_id')
                if not isinstance(ident, str) or not ident:
                    raise ValueError('Missing entry identity')
                if row.get('kind') == 'intent':
                    intents.add(ident)
                elif row.get('kind') == 'complete':
                    size = row.get('bytes')
                    if (ident not in intents or ident in seen or type(size) is not int or size < 0
                            or row.get('readback_verified') is not True):
                        raise ValueError('Invalid completion')
                    seen.add(ident); result['complete_files'] += 1; result['complete_bytes'] += size
                else:
                    raise ValueError('Unsupported journal row')
            except (ValueError, TypeError, AttributeError):
                result['errors'].append('invalid-row-' + str(number)); result['journal_complete'] = False; break
        if number == 0:
            result['errors'].append('empty-journal'); result['journal_complete'] = False
    return result


def process_observation(pid, expected_ticks=None, expected_boot=None, proc_root=Path('/proc')):
    result = dict(pid=pid, presence='unknown', identity_match='unknown')
    if type(pid) is not int or pid <= 0 or not proc_root.is_dir():
        return result
    try:
        text = (proc_root / str(pid) / 'stat').read_text()
        fields = text.rsplit(')', 1)[1].split()
        ticks, state = int(fields[19]), fields[0]
        result.update(presence='present', state=state, start_ticks=ticks)
    except FileNotFoundError:
        result['presence'] = 'absent'; return result
    except (OSError, ValueError, IndexError):
        return result
    try:
        boot = (proc_root / 'sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        boot = None
    result['boot_id'] = boot
    if expected_ticks is not None:
        result['start_ticks_match'] = ticks == expected_ticks
        if ticks != expected_ticks:
            result['identity_match'] = False
        elif expected_boot is not None and boot is not None:
            result['identity_match'] = boot == expected_boot
        else:
            result['identity_match'] = 'start-ticks-only'
    return result


def inspect(directory, pid=None, expected_ticks=None, expected_boot=None, now=None, proc_root=Path('/proc')):
    directory = Path(directory)
    now = time.time() if now is None else now
    errors, status = [], {}
    try:
        status = read_status(directory / 'status.json')
    except (OSError, ValueError):
        errors.append('status-unavailable-or-invalid')
    try:
        journal = journal_summary(directory / 'completion.jsonl')
    except (OSError, ValueError):
        journal = dict(complete_files=None, complete_bytes=None, journal_complete=False,
                       torn_tail=False, errors=['journal-unavailable-or-invalid'])
    process = process_observation(pid if pid is not None else status.get('pid'), expected_ticks, expected_boot, proc_root)
    # Marker may mean a pause is requested but active workers have not drained.
    try:
        os.lstat(directory / 'STOP_REQUESTED'); stop = True
    except FileNotFoundError:
        stop = False
    except OSError:
        stop = None
    reported = status.get('state')
    if process['identity_match'] is False:
        observed = 'process-identity-mismatch'
    elif process.get('state') == 'T' and process['identity_match'] is True:
        observed = 'verified-process-stopped'
    elif reported == 'paused':
        observed = 'reported-paused'
    elif stop is True:
        observed = 'pause-requested-not-proven-drained'
    elif (reported == 'completed-manifest' and journal['journal_complete']
          and journal['complete_files'] == status.get('total_files')):
        observed = 'recorded-manifest-complete'
    elif process['presence'] == 'absent':
        observed = 'controller-not-observed-review-before-resume'
    elif process['presence'] == 'present':
        observed = 'process-present-compare-two-samples-for-progress'
    else:
        observed = 'current-controller-unknown'
    updated = status.get('updated')
    age = now - updated if isinstance(updated, (int, float)) else None
    return dict(schema=1, observed_at=now, observation_only=True, classification=observed,
                reported_state=reported, status_updated_at=updated, status_age_seconds=age,
                reported_completed_files=status.get('completed_files'), reported_completed_bytes=status.get('completed_bytes'),
                total_files=status.get('total_files'), total_bytes=status.get('total_bytes'),
                completion_journal=journal, process=process, stop_requested=stop, errors=errors,
                note='Counts are journal observations, not content/business verification; this command never resumes or repairs a task.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--pid', type=int)
    parser.add_argument('--expected-start-ticks', type=int)
    parser.add_argument('--expected-boot-id')
    args = parser.parse_args()
    print(json.dumps(inspect(args.state_dir, args.pid, args.expected_start_ticks, args.expected_boot_id)))


if __name__ == '__main__':
    main()
