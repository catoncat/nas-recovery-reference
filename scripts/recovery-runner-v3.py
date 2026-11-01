#!/usr/bin/env python3
"""Offline export optimization candidate; baseline and NAS deployment stay separate.

Eight bounded workers, group-durable intents/completions, full readback retained.
No source deletion, native crypto, new inventory or production launch.
Isolated v3 candidate: bounded directory preparation cache and grouped scheduling.
"""
import argparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
import uuid

spec=importlib.util.spec_from_file_location('recovery_export_baseline',Path(__file__).with_name('recovery-runner.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
a=base.a;r=base.r;pre=base.pre
observe_target=base.observe_target


class CompletionRecords(dict):
    """Only populated after durable journal append (or journal replay)."""
    def __init__(self, entries):
        super().__init__(); self.entries=entries; self.total_bytes = 0; self.groups = {}

    def __setitem__(self, key, row):
        if key in self:
            raise r.Refused('Duplicate completion accounting')
        # Source layout is validated by Export.validate before records are loaded.
        group = self.entries[key]['group']
        bucket = self.groups.setdefault(group, dict(files=0, bytes=0))
        super().__setitem__(key, row)
        self.total_bytes += row['bytes']; bucket['files'] += 1; bucket['bytes'] += row['bytes']


class Export(base.Export):
    def _prepare_parent_uncached(self,path):
        """Walk existing directories without speculative mkdir or an FD cache."""
        relative=Path(path).parent.relative_to(self.mount)
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        with r.parent_fd(self.mount/'.probe') as (mount_fd,_):
            fd=os.dup(mount_fd)
            try:
                for part in relative.parts:
                    try:new=os.open(part,flags,dir_fd=fd)
                    except FileNotFoundError:
                        try:os.mkdir(part,0o700,dir_fd=fd)
                        except FileExistsError:pass  # Another worker created it.
                        # Also sync when a competing creator won the mkdir race.
                        os.fsync(fd)
                        new=os.open(part,flags,dir_fd=fd)
                    os.close(fd);fd=new
                    if os.fstat(fd).st_dev!=self.identity['st_dev']:
                        raise r.Refused('Nested destination mount differs')
            finally:os.close(fd)

    def ensure_parent(self, path):
        """Reuse creation work, not trust: reject replaced/symlinked ancestors.

        Cache is bounded and contains metadata only, never long-lived descriptors.
        Actual file opens still use the original no-follow traversal.
        """
        parent = Path(path).parent
        parent.relative_to(self.mount)
        with self.directory_lock:
            chain = self.directory_cache.get(parent)
            if chain is not None: self.directory_cache.move_to_end(parent)
        if chain is not None:
            for directory, identity in chain:
                info = os.stat(directory, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                    raise r.Refused('Prepared directory replaced or became a symlink')
            return
        self._prepare_parent_uncached(path)
        chain = []; current = self.mount
        for part in parent.relative_to(self.mount).parts:
            current = current / part
            info = os.stat(current, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_dev != self.identity['st_dev']:
                raise r.Refused('Prepared directory identity differs')
            chain.append((current, (info.st_dev, info.st_ino)))
        with self.directory_lock:
            self.directory_cache[parent] = chain
            self.directory_cache.move_to_end(parent)
            while len(self.directory_cache) > 256: self.directory_cache.popitem(last=False)

    def __init__(self,*args,max_active_directories=2,**kwargs):
        if max_active_directories<0:raise ValueError("active directories must be nonnegative")
        self.max_active_directories=max_active_directories
        self.directory_cache=OrderedDict();self.directory_lock=threading.Lock()
        self.timing_totals={};self.attempt_count=0
        self.controller_seconds=dict(intent_log_seconds=0.0,completion_log_seconds=0.0,scheduler_wait_seconds=0.0)
        self.log_batches=dict(intent=0,completion=0)
        self.timing_lock=threading.Lock();self.telemetry=None
        super().__init__(*args,**kwargs)
        self.records=CompletionRecords(self.entry_by_id)

    def summary_timings(self):
        with self.timing_lock:
            totals=dict(self.timing_totals);attempt_count=self.attempt_count
        return dict(controller_wall_seconds=dict(self.controller_seconds),worker_sum_seconds=totals,
                    attempted_files_this_run=attempt_count,log_batches=dict(self.log_batches),
                    hierarchy=dict(recover_copy_seconds=['source_read_seconds','decrypt_seconds','source_hash_seconds','plaintext_hash_seconds','output_write_seconds']),
                    note='Worker spans overlap across eight workers; recover_copy is the inclusive parent of read/decrypt/hash/write children: never add parent and children. Shared batch log/wait costs are not per-file additive. Clear copies hash their identical source/plain stream once as source_hash; plaintext_hash/decrypt=0. Orphan revalidation may have unsegmented work.')

    def status(self,state,**extra):
        result=dict(state=state,pid=self.pid,started=self.started,updated=time.time(),workers=8,
            runner_version=3,max_active_directories=self.max_active_directories,timing_summary=self.summary_timings(),
            total_files=len(self.manifest['entries']),total_bytes=self.bundle['summary']['expected_output_bytes'],
            completed_files=len(self.records),completed_bytes=self.records.total_bytes,
            groups={name:dict(value) for name,value in self.records.groups.items()})
        result.update(extra);base.atomic_status(self.fd,'status.json',result);return result

    def append_batch(self,kind,rows):
        if not rows:return dict(id=None,size=0,wall_seconds=0.0)
        started=time.perf_counter();self.append(rows)
        duration=time.perf_counter()-started
        self.controller_seconds[kind+'_log_seconds']+=duration;self.log_batches[kind]+=1
        return dict(id=uuid.uuid4().hex,size=len(rows),wall_seconds=duration)

    def copy_clear_timed(self,entry,timings):
        with r.parent_fd(entry['source']) as (src,name),r.parent_fd(entry['output']) as (out,target):
            source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0),dir_fd=src);destination=None
            try:
                before=os.fstat(source);a.regular(before)
                destination=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=out)
                digest=hashlib.sha256()
                with a.measured(timings,'recover_copy_seconds'):
                    while True:
                        with a.measured(timings,'source_read_seconds'):block=os.read(source,5*1024**2)
                        if not block:break
                        with a.measured(timings,'source_hash_seconds'):digest.update(block)
                        with a.measured(timings,'output_write_seconds'):
                            view=memoryview(block)
                            while view:
                                written=os.write(destination,view)
                                if written<=0:raise OSError('Short output write')
                                view=view[written:]
                        self.fault('copy-block')
                if a.stable(before)!=a.stable(os.fstat(source)):raise r.Refused('Clear source changed during copy')
                a.check_name(src,name,before)
                with a.measured(timings,'output_fsync_seconds'):
                    os.fsync(destination);os.fsync(out)
                return digest.hexdigest(),a.stable(before)
            finally:
                os.close(source)
                if destination is not None:os.close(destination)

    def one(self,entry):
        timings={key:0.0 for key in ['source_read_seconds','decrypt_seconds','source_hash_seconds','plaintext_hash_seconds','output_write_seconds','footer_parse_key_unwrap_seconds']};started=time.perf_counter()
        try:
            with a.measured(timings,'prepare_metadata_seconds'):
                self._live();before=self._source_info(entry);self.ensure_parent(entry['output']);exists=base.output_exists(entry['output'])
            if exists:
                if entry['id'] not in self.intents:raise r.Refused('Existing output without owned intent')
                with a.measured(timings,'orphan_output_hash_seconds'):
                    with r.readonly(entry['output']) as fd:
                        info=os.fstat(fd);a.regular(info)
                        if info.st_size!=entry['expected_output_bytes']:raise r.Refused('Partial orphan retained; explicit reconciliation required')
                        existing_hash=r.digest_fd(fd)
                if entry['operation']=='decrypt':
                    candidate=dict(state='written-complete',source=entry['source'],output=entry['output'],bytes=entry['expected_output_bytes'],output_sha256=existing_hash)
                    result=a.attest(entry['source'],entry['output'],self.source,self.target,self.master,self.marker,existing_record=candidate,timings=timings)
                    digest=result['output_sha256'];source_info=self._source_info(entry)
                else:
                    with a.measured(timings,'recover_copy_seconds'):digest,source_info=self.hash_source(entry)
                    if digest!=existing_hash:raise r.Refused('Incorrect complete orphan retained; no overwrite')
                adopted=True
            elif entry['operation']=='decrypt':
                result=a.attest(entry['source'],entry['output'],self.source,self.target,self.master,self.marker,timings=timings)
                digest=result['output_sha256'];source_info=self._source_info(entry);adopted=False
            else:digest,source_info=self.copy_clear_timed(entry,timings);adopted=False
            if source_info!=before:raise r.Refused('Source metadata changed before delivery proof')
            with r.parent_fd(entry['output']) as (directory,name):
                # Only this-run A/clear has already fsynced BOTH file and parent.
                # An orphan may have died before either barrier: preserve baseline sync.
                verified_info=a.read_output(directory,name,entry['expected_output_bytes'],digest,
                    lambda point:self.fault('readback-block'),sync=adopted,timings=timings)
                if adopted:
                    with a.measured(timings,'output_fsync_seconds'):os.fsync(directory)
            with a.measured(timings,'final_metadata_seconds'):
                if base.current_file(entry['output'])!=a.stable(verified_info):raise r.Refused('Output changed after complete readback')
                self._live()
            self.fault('verified-output-before-record')
            return dict(kind='complete',entry_id=entry['id'],source=entry['source'],output=entry['output'],operation=entry['operation'],bytes=entry['expected_output_bytes'],
                source_identity=source_info,output_identity=a.stable(verified_info),output_sha256=digest,readback_verified=True,orphan_adopted=adopted,
                source_attestation=result['source_attestation'] if entry['operation']=='decrypt' else None,source_sha256=digest if entry['operation']=='copy' else None,
                runner_version=3,timings=timings)
        finally:
            duration=time.perf_counter()-started
            timings['worker_unclassified_seconds']=max(0.0,duration-sum(timings.get(key,0.0) for key in ['prepare_metadata_seconds','footer_parse_key_unwrap_seconds','recover_copy_seconds','output_fsync_seconds','readback_hash_seconds','orphan_output_hash_seconds','final_metadata_seconds']))
            timings['worker_wall_seconds']=duration
            with self.timing_lock:
                self.attempt_count+=1
                for key,value in timings.items():
                    if key.endswith('_seconds'):self.timing_totals[key]=self.timing_totals.get(key,0.0)+value

    def emit_timings(self,records,intents,completion,wait_event):
        # Diagnostic telemetry only: completion.jsonl is the durable authority.
        # Completion fsync duration cannot be put in its own already-written row.
        data=b''.join(pre.encode(dict(kind='file-timing',entry_id=row['entry_id'],timings=row['timings'],
            intent_log_shared=intents.get(row['entry_id'],dict(id=None,size=0,wall_seconds=None)),
            completion_log_shared=completion,scheduler_wait_shared=wait_event)) for row in records)
        while data:
            count=os.write(self.telemetry,data)
            if count<=0:raise OSError('Short timing write')
            data=data[count:]

    def transfer(self):
        self.telemetry=os.open('timings-v3.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            info=os.fstat(self.telemetry)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise r.Refused('Private timing journal invalid')
            return self._transfer()
        finally:
            try:os.fsync(self.telemetry);os.fsync(self.fd)
            finally:os.close(self.telemetry);self.telemetry=None

    def _transfer(self):
        entries=self.manifest['entries'];pending_entries=[];new_bytes=0
        for entry in entries:
            if entry['id'] in self.records:self._record_ok(entry,self.records[entry['id']]);continue
            exists=base.output_exists(entry['output'])
            if exists and entry['id'] not in self.intents:raise r.Refused('Target collision appeared after preflight; no overwrite')
            if not exists:new_bytes+=entry['expected_output_bytes']
            pending_entries.append(entry)
        if self.free()<new_bytes+base.RESERVE:raise r.Refused('Live free space insufficient after mandatory 50GB+10GB reserve')
        # Preserve first-seen directory order and exact manifest membership.
        # Group only within each group so explicit group priority remains intact.
        groups=OrderedDict()
        for entry in pending_entries:
            groups.setdefault((entry['group'],str(Path(entry['source']).parent)),[]).append(entry)
        pending_entries=[entry for group in groups.values() for entry in group]
        errors=[];position=0;pending={};last_status=0;paused=False;intent_events={} 
        with ThreadPoolExecutor(max_workers=8) as pool:
            while pending or position<len(pending_entries):
                self._live();paused=paused or self.stop_requested();selected=[];selected_bytes=0
                while not paused and not errors and position<len(pending_entries) and len(pending)+len(selected)<8:
                    entry=pending_entries[position]
                    active={str(Path(e['source']).parent) for e,_ in list(pending.values())+selected}
                    if self.max_active_directories and str(Path(entry['source']).parent) not in active and len(active)>=self.max_active_directories:break
                    amount=0 if base.output_exists(entry['output']) else entry['expected_output_bytes']
                    if self.free()-self.reserved-selected_bytes<base.RESERVE+amount:
                        if pending or selected:break
                        raise r.Refused('Remaining operational reserve reached')
                    selected.append((entry,amount));selected_bytes+=amount;position+=1
                # Authorize a bounded lookahead group durably, without creating
                # outputs or reserving bytes until actual submission. This avoids
                # one intent fsync per refill when completions arrive staggered.
                start=position-len(selected)
                lookahead=pending_entries[start:start+32] if selected else []
                rows=[dict(kind='intent',entry_id=e['id'],source=e['source'],output=e['output']) for e in lookahead if e['id'] not in self.intents]
                # Refill the intent window only when a selected task needs it.
                if not any(e['id'] not in self.intents for e,_ in selected):rows=[]
                event=self.append_batch('intent',rows)
                if rows:
                    for row in rows:self.intents.add(row['entry_id']);intent_events[row['entry_id']]=event
                    self.fault('creation-intent-durable');self.fault('intent-batch-durable')
                # No task submission before the WHOLE intent group is durable.
                for entry,amount in selected:
                    self.reserved+=amount;pending[pool.submit(self.one,entry)]=(entry,amount)
                if not pending:break
                started=time.perf_counter();ready,_=wait(pending,timeout=1,return_when=FIRST_COMPLETED)
                duration=time.perf_counter()-started;self.controller_seconds['scheduler_wait_seconds']+=duration
                ready.update(future for future in pending if future.done())
                wait_event=dict(size=len(ready),wall_seconds=duration)
                completed=[]
                for future in ready:
                    entry,amount=pending.pop(future)
                    try:completed.append(future.result())
                    except BaseException as error:errors.append(error)
                    finally:self.reserved-=amount
                if completed:
                    self.fault('verified-batch-before-log')
                    event=self.append_batch('completion',completed)
                    # No record becomes completed in RAM/status before group fsync.
                    for row in completed:self.records[row['entry_id']]=row
                    self.fault('completion-record-durable');self.fault('completion-batch-durable')
                    self.emit_timings(completed,intent_events,event,wait_event)
                if time.monotonic()-last_status>=5:
                    self.status('stopping-on-error' if errors else ('pausing' if paused else 'running'));last_status=time.monotonic()
                if errors:position=len(pending_entries)
        if errors:
            self.status('stopped-on-error',reason=str(errors[0]));raise errors[0]
        if paused:return self.status('paused',source_files_preserved=True,stop_request_retained=True)
        if len(self.records)!=len(entries):raise r.Refused('Manifest did not complete')
        for entry in entries:self._record_ok(entry,self.records[entry['id']])
        if self.probe(self.mount)!=self.identity:raise r.Refused('Final target identity differs')
        groups={}
        for entry in entries:
            group=groups.setdefault(entry['group'],dict(files=0,bytes=0,copy_files=0,decrypt_files=0));group['files']+=1;group['bytes']+=entry['expected_output_bytes'];group[entry['operation']+'_files']+=1
        return self.status('completed-manifest',manifest_sha256=self.fingerprint,groups=groups,readback_verified=True,
            source_files_preserved=True,target_identity=self.identity)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ['bundle','target-identity','state-dir','expected-manifest-sha256','approved-source-root']:parser.add_argument('--'+arg,required=True)
    parser.add_argument('--active-directories',type=int,default=2,help='Candidate locality limit; 0 disables limit. Not a measured optimum.');parser.add_argument('--execute',action='store_true');parser.add_argument('--marker',required=True);args=parser.parse_args();master=None
    if args.execute:
        line=sys.stdin.buffer.readline(128).strip()
        if len(line)!=102 or not line.startswith(b'KEY48:'):raise r.Refused('KEY48 stdin line required')
        master=bytes.fromhex(line[6:].decode('ascii'));del line
    result=Export(json.loads(Path(args.bundle).read_text()),json.loads(Path(args.target_identity).read_text()),args.state_dir,args.expected_manifest_sha256,master,bytes.fromhex(args.marker),approved_source_root=args.approved_source_root,max_active_directories=args.active_directories).run(args.execute)
    del master;print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
