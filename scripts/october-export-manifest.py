#!/usr/bin/env python3
"""Metadata-only October export preflight. Never copies/decrypts or creates targets."""
import argparse
import collections
import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import time

FOOTER_SIZE=588
MIN_OPERATION_RESERVE=50_000_000_000
MIN_METADATA_BUDGET=10_000_000_000
INVALID=set('<>:"/\\|?*')
DEVICES={'CON','PRN','AUX','NUL'}|{'COM'+str(n) for n in range(1,10)}|{'LPT'+str(n) for n in range(1,10)}|{'COM'+n for n in '¹²³'}|{'LPT'+n for n in '¹²³'}
RANSOM_NOTES={'read-me3.txt'}

class Refused(ValueError):pass


def canonical(value):
    p=Path(value)
    if not p.is_absolute() or '..' in p.parts:raise Refused('Absolute paths without traversal required')
    return p


@contextlib.contextmanager
def dir_fd(path):
    p=canonical(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=new
        yield fd
    finally:os.close(fd)


def metadata(info):
    return dict(dev=info.st_dev,ino=info.st_ino,size=info.st_size,mtime_ns=info.st_mtime_ns,nlink=info.st_nlink)


def utf16_units(value):
    return len(value.encode('utf-16-le'))//2


def portable_key(parts):
    # Conservative case folding: may reject some names NTFS itself distinguishes.
    # Never silently normalizes/renames the stored target name.
    return tuple(part.rstrip(' .').casefold() for part in parts)


def component_issues(name):
    issues=[]
    if not name or name in ('.','..'):issues.append('empty-or-dot-component')
    if any(c in INVALID or ord(c)<32 for c in name):issues.append('windows-invalid-character')
    if name.endswith((' ','.')):issues.append('windows-trailing-dot-or-space')
    if name.rstrip(' .').split('.')[0].upper() in DEVICES:issues.append('windows-reserved-device-name')
    try:
        if utf16_units(name)>255:issues.append('ntfs-component-over-255-utf16-units')
    except UnicodeEncodeError:issues.append('windows-unencodable-name')
    return issues


def excluded(name):
    logical=name[:-7] if name.endswith('.L0CK3D') else name
    if name.startswith(('@','#','.')):return 'excluded-hidden-system-prefix'
    if logical.casefold() in RANSOM_NOTES:return 'excluded-known-ransom-note'
    return None


def scan_directory(path):
    result=[]
    with dir_fd(path) as fd:
        before=os.fstat(fd)
        with os.scandir(fd) as iterator:
            for entry in iterator:
                try:
                    info=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                    result.append((entry.name,info,None))
                except OSError as error:result.append((entry.name,None,type(error).__name__))
        after=os.fstat(fd)
    changed=(before.st_dev,before.st_ino,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns)
    return result,changed


def make_manifest(proposal,source_base=Path('/volume2'),target_root=None,now=None,approved_source_root=None):
    source_base=canonical(source_base)
    destination=proposal['destination']
    if target_root is None:
        mount=canonical(destination['proposed_mount']);name=Path(destination['proposed_root'])
        if name.is_absolute() or '..' in name.parts or len(name.parts)!=1:raise Refused('Expected a single explicit target root name')
        target_root=mount/name
    target_root=canonical(target_root)
    if source_base==target_root or source_base in target_root.parents or target_root in source_base.parents:raise Refused('Source and destination trees overlap')
    jobs=proposal.get('jobs')
    if not isinstance(jobs,list) or not jobs:raise Refused('Explicit nonempty October jobs required')
    exceptions=[];entries=[];summaries=[];seen_roots=[];directory_variants=collections.defaultdict(set)
    def issue(code,path,store=None,blocking=True,**extra):
        exceptions.append(dict(code=code,path=str(path),store=store,blocking=blocking,**extra))
    for part in target_root.parts[1:]:
        for code in component_issues(part):issue(code,target_root,component=part)
    for job in jobs:
        source=canonical(job['source'])
        try:relative=source.relative_to(source_base)
        except ValueError:raise Refused('Job outside explicit source base')
        parts=relative.parts
        if approved_source_root is not None:
            if source!=canonical(approved_source_root) or job['store']!=source.name:raise Refused('Job differs from explicitly approved source root')
        elif len(parts)!=4 or parts[0]!='ExampleShare' or parts[2]!='2026' or parts[3] not in ('10','10月'):raise Refused('Job must be an explicit 2026 October store root')
        if str(relative)!=job['output_relative'] or (approved_source_root is None and parts[1]!=job['store']):raise Refused('Job/store relative output mapping differs')
        if any(part.startswith(('@','#','.')) for part in parts):raise Refused('Hidden/system job root refused')
        excluded_job=proposal.get('excluded_main_store',{}).get('source')
        if excluded_job and source==Path(excluded_job):raise Refused('Excluded main store cannot be silently added')
        if any(source==other or source in other.parents or other in source.parents for other in seen_roots):raise Refused('Duplicate or overlapping job roots')
        seen_roots.append(source)
        summary=dict(store=job['store'],source=str(source),decrypt_files=0,copy_files=0,decrypt_bytes=0,copy_bytes=0,unknown_output_bytes_files=0,excluded_entries=0,read_errors=0,changed_directories=0)
        summaries.append(summary);stack=[source]
        while stack:
            directory=stack.pop()
            try:children,changed=scan_directory(directory)
            except OSError as error:
                issue('source-directory-unreadable',directory,job['store'],error=type(error).__name__);summary['read_errors']+=1;continue
            if changed:
                issue('source-directory-changed-during-listing',directory,job['store']);summary['changed_directories']+=1
            for name,info,error in sorted(children,key=lambda item:item[0]):
                path=directory/name
                if error:
                    issue('source-entry-unreadable',path,job['store'],error=error);summary['read_errors']+=1;continue
                reason=excluded(name)
                if reason:
                    issue(reason,path,job['store'],False);summary['excluded_entries']+=1;continue
                if stat.S_ISLNK(info.st_mode):
                    issue('excluded-symlink',path,job['store'],False);summary['excluded_entries']+=1;continue
                if stat.S_ISDIR(info.st_mode):stack.append(path);continue
                if not stat.S_ISREG(info.st_mode):
                    issue('excluded-nonregular-file',path,job['store'],False);summary['excluded_entries']+=1;continue
                operation='decrypt' if name.endswith('.L0CK3D') else 'copy'
                relative_file=path.relative_to(source_base)
                output_relative=relative_file.with_name(name[:-7]) if operation=='decrypt' and len(name)>7 else relative_file
                if operation=='decrypt' and len(name)==7:
                    issue('empty-decoded-filename',path,job['store'])
                expected=info.st_size-FOOTER_SIZE if operation=='decrypt' else info.st_size
                if expected<0:
                    issue('ciphertext-shorter-than-footer',path,job['store']);expected=None;summary['unknown_output_bytes_files']+=1
                item=dict(source=str(path),source_relative=str(relative_file),output=str(target_root/output_relative),output_relative=str(output_relative),
                          store=job['store'],operation=operation,source_identity=metadata(info),expected_output_bytes=expected,
                          footer_validated=False if operation=='decrypt' else None)
                item['id']=hashlib.sha256(encode(item)).hexdigest();entries.append(item)
                summary[operation+'_files']+=1
                if expected is not None:summary[operation+'_bytes']+=expected
                for part in output_relative.parts:
                    for code in component_issues(part):issue(code,path,job['store'],component=part,output_relative=str(output_relative))
                try:
                    # X:\ is an illustration of a legacy Windows drive path.
                    units=utf16_units('X:\\'+target_root.name+'\\'+'\\'.join(output_relative.parts))
                    if units>=260:issue('legacy-windows-long-path-warning',path,job['store'],False,output_relative=str(output_relative),illustrative_utf16_units=units)
                except UnicodeEncodeError:pass  # component error already blocks it.
                for depth in range(1,len(output_relative.parts)):
                    parent=output_relative.parts[:depth]
                    directory_variants[portable_key(parent)].add('/'.join(parent))
        summary['metadata_complete']=summary['read_errors']==0 and summary['changed_directories']==0
        summary['expected_output_bytes']=summary['decrypt_bytes']+summary['copy_bytes']
        expected_job=job.get('delivery_bytes')
        if expected_job is not None and expected_job!=summary['expected_output_bytes']:
            issue('proposal-size-drift',source,job['store'],False,proposal_bytes=expected_job,manifest_bytes=summary['expected_output_bytes'])
    by_key=collections.defaultdict(list)
    for entry in entries:by_key[portable_key(Path(entry['output_relative']).parts)].append(entry)
    for key,group in by_key.items():
        if len(group)>1:issue('planned-file-name-collision',target_root,outputs=[e['output_relative'] for e in group],sources=[e['source'] for e in group])
        if key in directory_variants:issue('planned-file-directory-collision',target_root,outputs=[e['output_relative'] for e in group],directories=sorted(directory_variants[key]))
    for key,variants in directory_variants.items():
        if len(variants)>1:issue('planned-directory-name-collision',target_root,directories=sorted(variants))

    # Inspect only existing directories on planned paths, not unrelated target data.
    cache={}
    def existing_children(path):
        path=str(path)
        if path not in cache:
            try:
                children,changed=scan_directory(path)
                if changed:issue('target-directory-changed-during-listing',path)
                mapping=collections.defaultdict(list)
                for name,info,error in children:
                    if error:issue('target-entry-unreadable',Path(path)/name,error=error)
                    else:mapping[portable_key((name,))[0]].append((name,info))
                cache[path]=mapping
            except OSError as error:
                issue('target-directory-unreadable',path,error=type(error).__name__);cache[path]={}
        return cache[path]
    def candidates(parent,name):return existing_children(parent).get(portable_key((name,))[0],[])
    root_matches=candidates(target_root.parent,target_root.name)
    roots=[]
    for name,info in root_matches:
        real=target_root.parent/name
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):issue('existing-target-root-not-directory',real);continue
        if name!=target_root.name:issue('existing-target-root-name-alias',real,planned=str(target_root))
        roots.append(real)
    for entry in entries:
        choices=roots[:]
        parts=Path(entry['output_relative']).parts
        for index,part in enumerate(parts):
            following=[]
            for parent in choices:
                for name,info in candidates(parent,part):
                    real=parent/name
                    if index==len(parts)-1:
                        issue('existing-target-collision',real,entry['store'],source=entry['source'],planned=entry['output'])
                    elif not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        issue('existing-target-parent-not-directory',real,entry['store'],planned=entry['output'])
                    else:
                        if name!=part:issue('existing-target-directory-name-alias',real,entry['store'],planned_component=part)
                        following.append(real)
            choices=following
            if not choices:break
    free=destination.get('last_free_bytes')
    reserve=max(MIN_OPERATION_RESERVE,destination.get('reserve_bytes',MIN_OPERATION_RESERVE))
    overhead=max(MIN_METADATA_BUDGET,destination.get('metadata_budget_bytes',MIN_METADATA_BUDGET))
    budget=max(0,free-reserve-overhead) if isinstance(free,int) and not isinstance(free,bool) and free>=0 else None
    total=sum(row['expected_output_bytes'] for row in summaries)
    if budget is None:issue('missing-valid-capacity-observation',target_root)
    elif total>budget:issue('capacity-budget-exceeded',target_root,expected_output_bytes=total,budget_bytes=budget)
    eligible=not any(e['blocking'] for e in exceptions)
    summary=dict(status='metadata-preflight-only-not-recovered',preflight_passed=eligible,executable=False,
                 execution_authorized=False,requires_live_identity_and_free_space_check=True,
                 observed_capacity=dict(free_bytes=free,observed_at=destination.get('last_observed_at'),expected_usb=destination.get('expected_usb'),
                     proposed_mount=destination.get('proposed_mount'),filesystem=destination.get('filesystem'),operation_reserve_bytes=reserve,metadata_budget_bytes=overhead,budget_bytes=budget),
                 expected_output_bytes=total,margin_after_budgets=None if budget is None else budget-total,
                 files=len(entries),decrypt_files=sum(s['decrypt_files'] for s in summaries),copy_files=sum(s['copy_files'] for s in summaries),
                 blocking_exceptions=sum(e['blocking'] for e in exceptions),exceptions=len(exceptions),stores=summaries)
    manifest=dict(version=1,built_at=time.time() if now is None else now,source_base=str(source_base),target_root=str(target_root),
                  proposal_sha256=hashlib.sha256(encode(proposal)).hexdigest(),scope=('Explicit approved root: '+str(approved_source_root) if approved_source_root is not None else 'Only explicit 2026 October jobs; metadata only'),
                  excluded_prefixes=['@','#','.'],excluded_ransom_notes=sorted(RANSOM_NOTES),entries=entries,
                  exceptions_sha256=hashlib.sha256(encode(exceptions)).hexdigest(),summary_sha256=hashlib.sha256(encode(summary)).hexdigest(),
                  executable=False,preflight_passed=eligible,requires_live_identity_and_free_space_check=True)
    return dict(manifest=manifest,exceptions=exceptions,summary=summary,
                hashes={name:hashlib.sha256(encode(value)).hexdigest() for name,value in [('manifest',manifest),('exceptions',exceptions),('summary',summary)]})


def encode(value):return (json.dumps(value,sort_keys=True,ensure_ascii=True)+'\n').encode('utf-8')


def write_bundle(bundle,output_dir):
    """Optional local metadata artifacts; never place them in NAS/target trees."""
    output_dir=canonical(output_dir)
    forbidden=[Path(bundle['manifest']['source_base']),Path(bundle['manifest']['target_root']).parent]
    if any(output_dir==p or p in output_dir.parents or output_dir in p.parents for p in forbidden) or any(part.startswith('volume') and (part[6:].isdigit() or part.startswith('volumeUSB')) for part in output_dir.parts):
        raise Refused('Metadata artifacts must be outside NAS/source/target trees')
    # Caller creates the local output directory. No business/target directory is made.
    with dir_fd(output_dir) as fd:
        for name,value in [('manifest.json',bundle['manifest']),('exceptions.json',bundle['exceptions']),('summary.json',bundle['summary']),('hashes.json',bundle['hashes'])]:
            file_fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            try:
                blob=encode(value)
                while blob:
                    count=os.write(file_fd,blob);blob=blob[count:]
                os.fsync(file_fd)
            finally:os.close(file_fd)
        os.fsync(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    root=Path(__file__).resolve().parents[1]
    p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--source-base',type=Path,required=True)
    p.add_argument('--target-root',type=Path)
    p.add_argument('--local-output-dir',type=Path,help='Already existing local private directory; omit to emit bundle on stdout')
    args=p.parse_args()
    proposal=json.loads(args.plan.read_text())
    bundle=make_manifest(proposal,args.source_base,args.target_root)
    if args.local_output_dir:
        write_bundle(bundle,args.local_output_dir);print(encode(dict(hashes=bundle['hashes'],summary=bundle['summary'])).decode(),end='')
    else:print(encode(bundle).decode(),end='')
    return 0 if bundle['summary']['preflight_passed'] else 2

if __name__=='__main__':raise SystemExit(main())
