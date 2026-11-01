#!/usr/bin/env python3
"""Rebuild ciphertext from archived footer; never replace an existing source."""
import os,sys
os.environ['OPENBLAS_NUM_THREADS']='1'
import argparse,fcntl,importlib.util,json,stat,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('inplace',Path(__file__).with_name('inplace-recover.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def revert(record,master,marker):
    source=record['source'];target=record['target'];footer=bytes.fromhex(record['footer'])
    if os.path.lexists(source):raise FileExistsError('ciphertext source already exists')
    st=os.lstat(target)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size!=record['bytes']:raise ValueError('target metadata invalid')
    tmp=os.path.join(os.path.dirname(target),'.'+os.path.basename(target)+'.revert-'+uuid.uuid4().hex[:16])
    sf=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0));df=os.open(tmp,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
    try:
        fcntl.ioctl(df,m.FICLONE,sf)
        if os.pwrite(df,footer,st.st_size)!=len(footer):raise IOError('short footer write')
        m.patch(df,footer,master,marker)
        # patch truncates to original size; restore the exact archived footer afterwards.
        if os.pwrite(df,footer,st.st_size)!=len(footer):raise IOError('short footer write')
        os.fchown(df,st.st_uid,st.st_gid);os.fchmod(df,stat.S_IMODE(st.st_mode));os.utime(df,ns=(st.st_atime_ns,st.st_mtime_ns));os.fsync(df)
        if m.ident(st)!=m.ident(os.lstat(target)):raise IOError('target changed')
        # Sync only this filesystem; never trigger global sync on the host.
        volume_fd=os.open(str(Path(target).parent),os.O_RDONLY|os.O_DIRECTORY)
        try:
            syncfs=__import__('ctypes').CDLL(None,use_errno=True).syncfs
            def barrier():
                if syncfs(volume_fd)!=0:
                    error=__import__('ctypes').get_errno();raise OSError(error,os.strerror(error))
            barrier();os.link(tmp,source,follow_symlinks=False);os.unlink(tmp)
            # Make ciphertext durable before removing plaintext.
            barrier();os.unlink(target);barrier()
        finally:os.close(volume_fd)
        return dict(source=source,bytes=st.st_size,at=m.time.time())
    finally:
        os.close(sf);os.close(df)
        if os.path.lexists(tmp):os.unlink(tmp)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive')
    selection=p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--source',action='append',help='Exact ciphertext path; repeat for selected files')
    selection.add_argument('--all',action='store_true',help='Revert every archived path whose ciphertext is absent')
    p.add_argument('--marker',required=True)
    p.add_argument('--execute',action='store_true')
    a=p.parse_args()
    if not m.re.fullmatch(r'[0-9a-fA-F]{8}',a.marker):p.error('--marker must be eight hex digits')
    if not a.execute:p.error('--execute is required')
    # Revert and recovery share the same state-directory lock.
    with open(Path(a.archive).parent/'controller.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        master=m.read_key();records={}
        for line in open(a.archive):
            r=json.loads(line);records[r['source']]=r
        if a.source and any(source not in records for source in a.source):
            raise ValueError('selected source absent from archive')
        for source,r in records.items():
            if a.source and source not in a.source:continue
            if os.path.lexists(source):continue
            print(json.dumps(revert(r,master,bytes.fromhex(a.marker)),ensure_ascii=False),flush=True)


if __name__ == '__main__':
    main()
