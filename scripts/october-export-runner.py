#!/usr/bin/env python3
"""One-way October delivery candidate. Eight workers, no NAS-source deletion.

Consumes an approved exact preflight bundle, never scans to expand its scope.
No rolling transaction, hard links, format, overwrite or source cleanup.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

a=module('export_attested','attested-recovery.py');r=a.rolling
pre=module('export_preflight','october-export-manifest.py')
RESERVE=60_000_000_000


def observe_target(mount):
    mount=r.canonical(mount);rows=[]
    for line in Path('/proc/mounts').read_text().splitlines():
        fields=line.split()
        if fields[1]==str(mount):rows.append(fields)
    if len(rows)!=1 or not rows[0][0].startswith('/dev/') or 'rw' not in rows[0][3].split(','):raise r.Refused('Expected one writable block-backed target mount')
    device=os.path.realpath(rows[0][0]);tool=shutil.which('blkid') or next((p for p in ['/sbin/blkid','/usr/sbin/blkid','/bin/blkid'] if os.access(p,os.X_OK)),None)
    if not tool:raise r.Refused('blkid required to verify filesystem UUID')
    result=subprocess.run([tool,device],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    match=re.search(r'(?:^|\s)UUID="([^"]+)"',result.stdout.decode('utf-8','replace'))
    if result.returncode or not match:raise r.Refused('Cannot establish target filesystem UUID')
    v=os.statvfs(mount);info=os.stat(mount)
    block=Path(os.path.realpath('/sys/class/block/'+Path(device).name))
    if (block/'partition').exists():block=block.parent
    identity=dict(mount=str(mount),source=device,uuid=match.group(1),filesystem=rows[0][2],st_dev=info.st_dev,root_ino=info.st_ino,total_bytes=v.f_blocks*v.f_frsize,
                  block_bytes=int((block/'size').read_text().strip())*512,model=(block/'device/model').read_text().strip())
    for parent in [block]+list(block.parents):
        if (parent/'idVendor').exists() and (parent/'idProduct').exists():
            identity['usb_id']=(parent/'idVendor').read_text().strip()+':'+(parent/'idProduct').read_text().strip();break
    if 'usb_id' not in identity:raise r.Refused('Expected USB target identity')
    return identity


def current_file(path):
    with r.readonly(path) as fd:
        info=os.fstat(fd);a.regular(info);return a.stable(info)


def output_exists(path):
    try:
        with r.parent_fd(path) as (parent,name):return r.exists(parent,name)
    except FileNotFoundError:return False


def atomic_status(directory,name,value):
    temporary=name+'.'+uuid.uuid4().hex+'.tmp';fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        data=pre.encode(value)
        while data:
            count=os.write(fd,data);data=data[count:]
        os.fsync(fd)
    finally:os.close(fd)
    os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)


class Export:
    def __init__(self,bundle,target_identity,state_dir,expected_manifest_sha256,master=None,marker=None,*,fault=None,identity_probe=None,free_probe=None,approved_source_root=None):
        self.approved_source_root=r.canonical(approved_source_root) if approved_source_root is not None else None
        self.bundle=bundle;self.manifest=bundle['manifest'];self.identity=target_identity;self.state=r.canonical(state_dir)
        self.fingerprint=hashlib.sha256(pre.encode(self.manifest)).hexdigest()
        if self.fingerprint!=expected_manifest_sha256:raise r.Refused('Reviewed export manifest hash differs')
        if not isinstance(marker,bytes) or len(marker)!=4:raise r.Refused('Explicit four-byte incident marker required')
        self.master=master;self.marker=marker;self.fault=fault or (lambda point:None)
        self.probe=identity_probe or observe_target
        self.mount=r.canonical(target_identity['mount']);self.target=r.canonical(self.manifest['target_root']);self.source=r.canonical(self.manifest['source_base'])
        self.free=free_probe or (lambda:os.statvfs(self.mount).f_bavail*os.statvfs(self.mount).f_frsize)
        self.started=time.time();self.pid=os.getpid();self.fd=None;self.log=None;self.mount_fd=None;self.intents=set();self.records={};self.reserved=0
        self.validate();self.entry_by_id={e['id']:e for e in self.manifest['entries']}

    def validate(self):
        m=self.manifest;b=self.bundle
        if (not m.get('preflight_passed') or not b['summary'].get('preflight_passed') or any(x.get('blocking') for x in b['exceptions'])):raise r.Refused('Preflight has unresolved blocking exceptions')
        for key in ['exceptions','summary']:
            if hashlib.sha256(pre.encode(b[key])).hexdigest()!=m[key+'_sha256']:raise r.Refused('Preflight artifact hash differs')
        if b['hashes']['manifest']!=self.fingerprint:raise r.Refused('Preflight manifest hash differs')
        if self.mount not in self.target.parents:raise r.Refused('Target root outside approved USB mount')
        if self.source==self.target or self.source in self.target.parents or self.target in self.source.parents:raise r.Refused('Source/output roots overlap')
        for root in [self.source,self.target]:
            if self.state==root or root in self.state.parents or self.state in root.parents:raise r.Refused('Control/business roots overlap')
        if not self.identity.get('uuid') or not self.identity.get('source'):raise r.Refused('Explicit filesystem UUID/device identity required')
        ids=set();sources=set();outputs=set();folded=set()
        for entry in m['entries']:
            item=dict(entry);ident=item.pop('id')
            if hashlib.sha256(pre.encode(item)).hexdigest()!=ident:raise r.Refused('Manifest entry hash differs')
            source,output=r.canonical(entry['source']),r.canonical(entry['output'])
            try:relative=source.relative_to(self.source)
            except ValueError:raise r.Refused('Source outside exact approved base')
            if self.approved_source_root is not None:
                if self.approved_source_root not in source.parents:raise r.Refused('Source outside explicitly approved root')
            elif len(relative.parts)<5 or relative.parts[0]!='ExampleShare' or relative.parts[2]!='2026' or relative.parts[3] not in ('10','10月'):raise r.Refused('Not an approved October source')
            if any(part.startswith(('@','#','.')) for part in relative.parts) or pre.excluded(source.name):raise r.Refused('Protected/excluded source in manifest')
            operation='decrypt' if source.name.endswith('.L0CK3D') else 'copy'
            target_relative=relative.with_name(source.name[:-7]) if operation=='decrypt' else relative
            if output!=self.target/target_relative or entry['output_relative']!=str(target_relative) or entry['operation']!=operation:raise r.Refused('Exact source/output operation mapping differs')
            if any(pre.component_issues(part) for part in target_relative.parts):raise r.Refused('Unresolved portable filename issue')
            key=pre.portable_key(target_relative.parts)
            if ident in ids or str(source) in sources or str(output) in outputs or key in folded:raise r.Refused('Duplicate/colliding manifest entry')
            ids.add(ident);sources.add(str(source));outputs.add(str(output));folded.add(key)
            info=entry['source_identity'];expected=info['size']-588 if operation=='decrypt' else info['size']
            if info.get('nlink')!=1:raise r.Refused('Manifest includes linked source unsupported by verified producer')
            if expected<0 or entry['expected_output_bytes']!=expected:raise r.Refused('Expected output byte accounting differs')
        total=sum(e['expected_output_bytes'] for e in m['entries'])
        if total!=b['summary']['expected_output_bytes']:raise r.Refused('Manifest/summary byte totals differ')
        if self.probe(self.mount)!=self.identity:raise r.Refused('Live target UUID/device identity differs')

    def _live(self):
        info=os.stat(self.mount);v=os.statvfs(self.mount)
        if (info.st_dev,info.st_ino,v.f_blocks*v.f_frsize)!=(self.identity['st_dev'],self.identity['root_ino'],self.identity['total_bytes']):raise r.Refused('Target mount/device changed during export')
        if self.mount_fd is not None:
            held=os.fstat(self.mount_fd)
            if (held.st_dev,held.st_ino)!=(info.st_dev,info.st_ino):raise r.Refused('Target mount replaced while held')

    def _source_info(self,entry):
        current=current_file(entry['source']);expected=entry['source_identity']
        if any(current[k]!=expected[k] for k in ['dev','ino','size','mtime_ns','nlink']):raise r.Refused('Source differs from immutable manifest')
        return current

    def _record_ok(self,entry,record):
        if record.get('entry_id')!=entry['id'] or record.get('source')!=entry['source'] or record.get('output')!=entry['output'] or record.get('bytes')!=entry['expected_output_bytes']:raise r.Refused('Completion record mapping differs')
        if current_file(entry['output'])!=record['output_identity']:raise r.Refused('Completed output identity changed; no overwrite')
        if self._source_info(entry)!=record['source_identity']:raise r.Refused('Completed source identity changed')
        if not r.valid_sha(record.get('output_sha256')) or record.get('readback_verified') is not True:raise r.Refused('Completion lacks full readback proof')
        if entry['operation']=='decrypt':
            proof=record.get('source_attestation') or {}
            if (proof.get('kind') not in ('recovery-read-v1','verified-redecrypt-v1') or proof.get('source')!=entry['source'] or proof.get('output')!=entry['output']
                or proof.get('output_sha256')!=record['output_sha256'] or proof.get('identity')!={k:record['source_identity'][k] for k in ('dev','ino','size','mtime_ns')}
                or proof.get('ctime_ns')!=record['source_identity']['ctime_ns'] or not r.valid_sha(proof.get('sha256'))):raise r.Refused('Cipher completion attestation differs')
        elif record.get('source_sha256')!=record['output_sha256']:raise r.Refused('Clear copy source hash differs')

    def append(self,rows):
        data=b''.join(pre.encode(row) for row in rows)
        while data:
            count=os.write(self.log,data);data=data[count:]
        os.fsync(self.log)

    def load_log(self):
        os.lseek(self.log,0,os.SEEK_SET);raw=b''
        for block in iter(lambda:os.read(self.log,1024**2),b''):raw+=block
        lines=raw.splitlines(keepends=True)
        expected_header=dict(kind='header',manifest_sha256=self.fingerprint,target_identity=self.identity,source_base=str(self.source),target_root=str(self.target))
        if not lines:
            self.append([expected_header]);os.fsync(self.fd);return
        if not lines[0].endswith(b'\n') or json.loads(lines[0])!=expected_header:raise r.Refused('Journal header/target differs')
        if not lines[-1].endswith(b'\n'):
            # Only our own incomplete trailing append is discarded. Its output is
            # not trusted; intent/orphan proof will re-establish completion.
            raw=raw[:raw.rfind(b'\n')+1];os.ftruncate(self.log,len(raw));os.fsync(self.log);lines=raw.splitlines(keepends=True)
        by_id={e['id']:e for e in self.manifest['entries']}
        for line in lines[1:]:
            row=json.loads(line);ident=row.get('entry_id')
            if ident not in by_id:raise r.Refused('Journal entry outside manifest')
            if row['kind']=='intent':
                if row.get('source')!=by_id[ident]['source'] or row.get('output')!=by_id[ident]['output']:raise r.Refused('Journal intent mapping differs')
                self.intents.add(ident)
            elif row['kind']=='complete':
                if ident not in self.intents or ident in self.records:raise r.Refused('Duplicate/unowned completion')
                self.records[ident]=row
            else:raise r.Refused('Unknown journal row')
        os.lseek(self.log,0,os.SEEK_END)

    def ensure_parent(self,path):
        relative=Path(path).parent.relative_to(self.mount)
        with r.parent_fd(self.mount/'.probe') as (mount_fd,_):
            fd=os.dup(mount_fd)
            try:
                for part in relative.parts:
                    try:os.mkdir(part,0o700,dir_fd=fd);os.fsync(fd)
                    except FileExistsError:pass
                    new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
                    if os.fstat(fd).st_dev!=self.identity['st_dev']:raise r.Refused('Nested destination mount differs')
            finally:os.close(fd)

    def hash_source(self,entry):
        with r.parent_fd(entry['source']) as (parent,name):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0),dir_fd=parent)
            try:
                before=os.fstat(fd);a.regular(before);digest=r.digest_fd(fd)
                if a.stable(before)!=a.stable(os.fstat(fd)):raise r.Refused('Clear source changed during hash')
                a.check_name(parent,name,before);return digest,a.stable(before)
            finally:os.close(fd)

    def copy_clear(self,entry):
        with r.parent_fd(entry['source']) as (src,name),r.parent_fd(entry['output']) as (out,target):
            source=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0),dir_fd=src)
            destination=None
            try:
                before=os.fstat(source);a.regular(before)
                destination=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=out)
                digest=hashlib.sha256()
                for block in iter(lambda:os.read(source,5*1024**2),b''):
                    digest.update(block);view=memoryview(block)
                    while view:
                        written=os.write(destination,view)
                        if written<=0:raise OSError('Short output write')
                        view=view[written:]
                    self.fault('copy-block')
                if a.stable(before)!=a.stable(os.fstat(source)):raise r.Refused('Clear source changed during copy')
                a.check_name(src,name,before);os.fsync(destination);os.fsync(out)
                return digest.hexdigest(),a.stable(before)
            finally:
                os.close(source)
                if destination is not None:os.close(destination)

    def one(self,entry):
        self._live();before=self._source_info(entry);self.ensure_parent(entry['output'])
        if output_exists(entry['output']):
            if entry['id'] not in self.intents:raise r.Refused('Existing output without owned intent')
            with r.readonly(entry['output']) as fd:
                info=os.fstat(fd);a.regular(info)
                if info.st_size!=entry['expected_output_bytes']:raise r.Refused('Partial orphan retained; explicit reconciliation required')
                existing_hash=r.digest_fd(fd)
            if entry['operation']=='decrypt':
                candidate=dict(state='written-complete',source=entry['source'],output=entry['output'],bytes=entry['expected_output_bytes'],output_sha256=existing_hash)
                result=a.attest(entry['source'],entry['output'],self.source,self.target,self.master,self.marker,existing_record=candidate)
                digest=result['output_sha256'];source_info=self._source_info(entry)
            else:
                digest,source_info=self.hash_source(entry)
                if digest!=existing_hash:raise r.Refused('Incorrect complete orphan retained; no overwrite')
            adopted=True
        elif entry['operation']=='decrypt':
            result=a.attest(entry['source'],entry['output'],self.source,self.target,self.master,self.marker)
            digest=result['output_sha256'];source_info=self._source_info(entry);adopted=False
        else:digest,source_info=self.copy_clear(entry);adopted=False
        if source_info!=before:raise r.Refused('Source metadata changed before delivery proof')
        with r.parent_fd(entry['output']) as (directory,name):
            verified_info=a.read_output(directory,name,entry['expected_output_bytes'],digest,lambda point:self.fault('readback-block'))
            os.fsync(directory)
        if current_file(entry['output'])!=a.stable(verified_info):raise r.Refused('Output changed after complete readback')
        self._live();self.fault('verified-output-before-record')
        return dict(kind='complete',entry_id=entry['id'],source=entry['source'],output=entry['output'],operation=entry['operation'],bytes=entry['expected_output_bytes'],
                    source_identity=source_info,output_identity=a.stable(verified_info),output_sha256=digest,readback_verified=True,orphan_adopted=adopted,
                    source_attestation=result['source_attestation'] if entry['operation']=='decrypt' else None,source_sha256=digest if entry['operation']=='copy' else None)

    def run(self,execute=False):
        self._live()
        if not execute:return dict(state='preflight-only',execution_started=False,manifest_sha256=self.fingerprint,target_identity=self.identity,available=self.free(),required_output_bytes=self.bundle['summary']['expected_output_bytes'],required_reserve=RESERVE)
        if not isinstance(self.master,bytes) or len(self.master)!=48:raise r.Refused('KEY48 in-memory material required')
        if os.getpriority(os.PRIO_PROCESS,0)<5:os.setpriority(os.PRIO_PROCESS,0,5)
        with r.parent_fd(self.mount/'.probe') as (mount_fd,_):self.mount_fd=os.dup(mount_fd)
        try:
            with r.parent_fd(self.state) as (parent,name):self.fd=r.private_dir(parent,name)
            try:
                lock=os.open('writer.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
                try:
                    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    self.log=os.open('completion.jsonl',os.O_RDWR|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
                    try:
                        info=os.fstat(self.log)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise r.Refused('Private journal invalid')
                        self.load_log();os.fsync(self.fd)
                        self.status('validating-resume')
                        return self.transfer()
                    finally:os.close(self.log);self.log=None
                finally:os.close(lock)
            finally:os.close(self.fd);self.fd=None
        finally:os.close(self.mount_fd);self.mount_fd=None

    def status(self,state,**extra):
        stores={}
        for record in self.records.values():
            entry=self.entry_by_id[record['entry_id']]
            store=stores.setdefault(entry['store'],dict(files=0,bytes=0))
            store['files']+=1;store['bytes']+=record['bytes']
        result=dict(state=state,pid=self.pid,started=self.started,updated=time.time(),workers=8,
            total_files=len(self.manifest['entries']),total_bytes=self.bundle['summary']['expected_output_bytes'],
            completed_files=len(self.records),completed_bytes=sum(v['bytes'] for v in self.records.values()),stores=stores)
        result.update(extra);atomic_status(self.fd,'status.json',result);return result

    def stop_requested(self):return r.exists(self.fd,'STOP_REQUESTED')

    def transfer(self):
        entries=self.manifest['entries'];by_id={e['id']:e for e in entries}
        pending_entries=[];new_bytes=0
        for e in entries:
            if e['id'] in self.records:self._record_ok(e,self.records[e['id']]);continue
            exists=output_exists(e['output'])
            if exists and e['id'] not in self.intents:raise r.Refused('Target collision appeared after preflight; no overwrite')
            if not exists:new_bytes+=e['expected_output_bytes']
            pending_entries.append(e)
        if self.free()<new_bytes+RESERVE:raise r.Refused('Live free space insufficient after mandatory 50GB+10GB reserve')
        errors=[];position=0;pending={};last_status=0;paused=False
        with ThreadPoolExecutor(max_workers=8) as pool:
            while pending or position<len(pending_entries):
                self._live();paused=paused or self.stop_requested()
                while not paused and not errors and position<len(pending_entries) and len(pending)<8:
                    e=pending_entries[position];amount=0 if output_exists(e['output']) else e['expected_output_bytes']
                    if self.free()-self.reserved<RESERVE+amount:
                        if pending:break
                        raise r.Refused('Remaining operational reserve reached')
                    if e['id'] not in self.intents:
                        self.append([dict(kind='intent',entry_id=e['id'],source=e['source'],output=e['output'])]);self.intents.add(e['id']);self.fault('creation-intent-durable')
                    self.reserved+=amount;pending[pool.submit(self.one,e)]=(e,amount);position+=1
                if not pending:break
                ready,_=wait(pending,timeout=1,return_when=FIRST_COMPLETED)
                for future in ready:
                    e,amount=pending.pop(future)
                    try:
                        record=future.result();self.append([record]);self.records[e['id']]=record;self.fault('completion-record-durable')
                    except BaseException as error:errors.append(error)
                    finally:self.reserved-=amount
                if time.monotonic()-last_status>=5:
                    self.status('stopping-on-error' if errors else ('pausing' if paused else 'running'));last_status=time.monotonic()
                if errors:position=len(pending_entries)
        if errors:
            self.status('stopped-on-error',reason=str(errors[0]))
            raise errors[0]
        if paused:return self.status('paused',source_files_preserved=True,stop_request_retained=True)
        if len(self.records)!=len(entries):raise r.Refused('Manifest did not complete')
        for e in entries:self._record_ok(e,self.records[e['id']])
        if self.probe(self.mount)!=self.identity:raise r.Refused('Final target identity differs')
        stores={}
        for e in entries:
            store=stores.setdefault(e['store'],dict(files=0,bytes=0,copy_files=0,decrypt_files=0))
            store['files']+=1;store['bytes']+=e['expected_output_bytes'];store[e['operation']+'_files']+=1
        result=dict(state='completed-manifest',manifest_sha256=self.fingerprint,completed_files=len(entries),completed_bytes=sum(v['bytes'] for v in self.records.values()),
                    stores=stores,readback_verified=True,source_files_preserved=True,target_identity=self.identity,updated=time.time())
        result.update(pid=self.pid,started=self.started,total_files=len(entries),total_bytes=self.bundle['summary']['expected_output_bytes'],workers=8)
        atomic_status(self.fd,'status.json',result);return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--target-identity',type=Path,required=True);p.add_argument('--state-dir',required=True);p.add_argument('--expected-manifest-sha256',required=True);p.add_argument('--execute',action='store_true');p.add_argument('--marker',required=True)
    args=p.parse_args();bundle=json.loads(args.bundle.read_text());identity=json.loads(args.target_identity.read_text());master=None
    if args.execute:
        line=sys.stdin.buffer.readline(128).strip()
        if len(line)!=102 or not line.startswith(b'KEY48:'):raise r.Refused('KEY48 stdin line required')
        master=bytes.fromhex(line[6:].decode('ascii'));del line
    result=Export(bundle,identity,args.state_dir,args.expected_manifest_sha256,master,bytes.fromhex(args.marker)).run(args.execute)
    del master;print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
