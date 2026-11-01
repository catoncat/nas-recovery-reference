#!/usr/bin/env python3
"""Reflink and patch supported ciphertext; archive before unlink. Linux only."""
import os
os.environ['OPENBLAS_NUM_THREADS'] = '1'
import sys
from pathlib import Path
import importlib.util
_dependency_spec = importlib.util.spec_from_file_location('inplace_dependencies', Path(__file__).with_name('check-dependencies.py'))
_dependency = importlib.util.module_from_spec(_dependency_spec)
_dependency_spec.loader.exec_module(_dependency)
sys.path.insert(0, str(_dependency.verify()))
from collections import deque
import queue, ctypes
import fcntl, json, re, sqlite3, stat, threading, time, uuid
from decrypt_copy import chacha8_call, unwrap_record, CALL_LIMIT
from file_layout import read_footer, RecoveryError
FICLONE = 0x40049409
TEMP = re.compile(r'^\..+\.inplace-[0-9a-f]{16}$')

def read_key():
    line = sys.stdin.buffer.readline(128).strip()
    if len(line) != 102 or not line.startswith(b'KEY48:'): raise ValueError('Expected KEY48 stdin')
    return bytes.fromhex(line[6:].decode())

def ident(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]

def atomic(path, value):
    tmp = str(path)+'.tmp'
    with open(tmp, 'w') as f:
        json.dump(value, f, ensure_ascii=False); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def append(path, rows, durable=False):
    with open(path, 'a') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False)+'\n')
        f.flush()
        if durable:os.fsync(f.fileno())

MAGIC_PREFIXES = {
    '.jpg': (b'\xff\xd8\xff',), '.jpeg': (b'\xff\xd8\xff',),
    '.png': (b'\x89PNG',), '.pdf': (b'%PDF',),
    '.zip': (b'PK\x03\x04',), '.docx': (b'PK\x03\x04',), '.xlsx': (b'PK\x03\x04',), '.pptx': (b'PK\x03\x04',),
    '.psd': (b'8BPS',), '.gif': (b'GIF8',), '.rar': (b'Rar!',), '.7z': (b'7z\xbc\xaf',),
}
for _extension in ('.tif', '.tiff', '.cr2', '.nef', '.arw', '.dng'):
    MAGIC_PREFIXES[_extension] = (b'II*\x00', b'MM\x00*')
MAGIC_EXTENSIONS = set(MAGIC_PREFIXES) | {'.mp4', '.mov'}
class MagicMismatch(Exception): pass

def recognized_format(head):
    known = [('appledouble',(bytes.fromhex('0005160700020000'),bytes.fromhex('0005160700010000'))), ('applesingle',(bytes.fromhex('0005160000020000'),bytes.fromhex('0005160000010000'))), ('jpeg',(b'\xff\xd8\xff',)), ('png',(b'\x89PNG\r\n\x1a\n',)),
             ('pdf',(b'%PDF',)), ('zip',(b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')),
             ('psd',(b'8BPS',)), ('tiff',(b'II*\0',b'MM\0*',b'II+\0',b'MM\0+')),
             ('gif',(b'GIF87a',b'GIF89a')), ('rar',(b'Rar!',)), ('7z',(b'7z\xbc\xaf',)),
             ('ole-compound',(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',)),
             ('bmp',(b'BM',)), ('gzip',(b'\x1f\x8b\x08',)), ('jpeg2000',(b'\0\0\0\x0cjP  \r\n\x87\n',))]
    for name,prefixes in known:
        if any(head.startswith(prefix) for prefix in prefixes):return name
    if len(head)>=8 and head[4:8] in (b'ftyp',b'moov',b'mdat',b'wide',b'free',b'skip',b'pnot'):
        return 'iso-bmff' if head[4:8]==b'ftyp' else 'quicktime-legacy'
    if len(head)>=12 and head[:4]==b'RIFF' and head[8:12] in (b'WEBP',b'AVI ',b'WAVE'):return 'riff-'+head[8:12].decode().strip().lower()
    return None

def office_owner_format(target,head,size):
    # Supported fixed-size Office owner variants. Validate both
    # name copies; a short file or a readable username alone is insufficient.
    if not Path(target).name.startswith('~$') or size not in (162,165) or len(head)<size:return False
    length=head[0]
    if not 0<length<=52:return False
    marker,start=(54,56) if size==162 else (55,57)
    if not set(head[1+length:marker])<={0,32} or head[marker+1]!=0:return False
    ansi=bytes(head[1:1+length])
    for encoding in ('ascii','utf-8','cp936','cp950','cp1252','mac_roman'):
        try:text=ansi.decode(encoding);utf=text.encode('utf-16-le')
        except (UnicodeError,LookupError):continue
        if not text or not all(c.isprintable() for c in text):continue
        if head[marker]!=len(utf)//2 or head[start:start+len(utf)]!=utf:continue
        # Word's 162-byte variant has extra tail metadata; Excel's 165-byte
        # variant observed here has only zero/space padding after the name.
        if size==162 or set(head[start+len(utf):])<={0,32}:return True
    return False

def magic_matches(target, head, size=None):
    if recognized_format(head):return True
    if office_owner_format(target,head,size):return True
    return False if Path(target).suffix.lower() in MAGIC_EXTENSIONS else None

def patch(fd, footer, master, marker, space_check=lambda: None, magic_target=None):
    # Use the reviewed layout parser on the complete clone, keeping counters across segments.
    with os.fdopen(os.dup(fd), 'rb') as f:
        _, size, mode, percent, segments = read_footer(f, os.fstat(fd).st_size, marker)
    key, nonce = unwrap_record(footer, master); counter = 0; touched = 0
    header_size=min(size,size if magic_target and Path(magic_target).name.startswith('~$') and size in (162,165) else 16)
    head=bytearray()
    for offset, length in segments:
        pos = offset
        while length:
            space_check()
            amount = min(length, CALL_LIMIT); block = os.pread(fd, amount, pos)
            if len(block) != amount: raise IOError('short read')
            plain, counter = chacha8_call(block, key, nonce, counter)
            if pos==0:head=bytearray(plain[:header_size])
            elif pos<len(head):head[pos:min(len(head),pos+len(plain))]=plain[:len(head)-pos]
            if os.pwrite(fd, plain, pos) != amount: raise IOError('short write')
            pos += amount; length -= amount; touched += amount
    if magic_target is not None:
        # Small/zero-length partial ranges may not cover the complete header.
        if len(head)<header_size:head=bytearray(os.pread(fd,header_size,0))
        if magic_matches(magic_target,bytes(head),size) is False:
            raise MagicMismatch('magic-mismatch: extension '+Path(magic_target).suffix.lower()+' head16='+bytes(head[:16]).hex())
    os.ftruncate(fd, size)
    return size, touched

class LowSpace(Exception): pass

class Recovery:
    def __init__(self, state, roots, master, reserve, marker, suffix='.L0CK3D', exclude_prefixes=(), threads=8):
        if not isinstance(marker, bytes) or len(marker) != 4:
            raise ValueError('marker must be exactly four bytes')
        if not suffix or '/' in suffix or '\0' in suffix:
            raise ValueError('suffix must be a nonempty filename suffix')
        if not roots or reserve < 0 or not 1 <= threads <= 16:
            raise ValueError('roots, nonnegative reserve and 1..16 threads required')
        self.marker = marker; self.suffix = suffix
        self.exclude_prefixes = tuple(exclude_prefixes); self.default_threads = threads
        roots = [str(Path(r).absolute()) for r in roots]
        state_path = Path(state).absolute()
        for root in roots:
            path = Path(root)
            if path.resolve() != path or not path.is_dir():
                raise ValueError('root must be an existing directory without symlink components')
            if state_path == path or path in state_path.parents:
                raise ValueError('state must be outside source roots')
        for i, root in enumerate(roots):
            for other in roots[i+1:]:
                if root == other or Path(root) in Path(other).parents or Path(other) in Path(root).parents:
                    raise ValueError('source roots must not overlap')
        self.state = Path(state); self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.lock = open(self.state/'controller.lock', 'a')
            fcntl.flock(self.lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.roots = roots; self.master = master; self.reserve = reserve
            if any(os.stat(r).st_dev != self.state.stat().st_dev for r in roots):
                raise ValueError('state and roots must share a filesystem')
            self.runid = uuid.uuid4().hex[:16]
            config = dict(roots=roots, marker=marker.hex(), suffix=suffix, exclude_prefixes=list(exclude_prefixes))
            config_path = self.state/'config.json'
            if config_path.exists():
                if json.loads(config_path.read_text()) != config:
                    raise ValueError('resume configuration differs from existing state')
            else:
                atomic(config_path, config)
            self.started = time.time(); self.status = dict(state='starting', pid=os.getpid(), runid=self.runid, started=self.started, files=0, bytes=0, touched_bytes=0, conflicts=0, skipped=0, errors=0, magic_mismatch=0, magic_checked=0, magic_unchecked=0, roots_done=0, threads=8, root=None, revision='0.3.0', batch_limit=256, batch_seconds=10, syncfs_calls=0, drain_syncfs_calls=0, installed_pending_files=0, installed_pending_bytes=0)
            self.stop = threading.Event(); self.mu = threading.RLock(); self.session_bytes = 0; self.last_sample=(time.time(),0); self.samples=deque([(self.started,0)])
            self.volume_fd=os.open(str(self.state),os.O_RDONLY|os.O_DIRECTORY)
            libc=ctypes.CDLL(None,use_errno=True);self._syncfs=libc.syncfs;self._syncfs.argtypes=[ctypes.c_int];self._syncfs.restype=ctypes.c_int
            self.db_mu=threading.RLock();self.pending_done=[]
            self.db = sqlite3.connect(str(self.state/'resume-index.sqlite'),check_same_thread=False)
            self.db.execute('pragma synchronous=OFF')
            self.db.execute('create table if not exists archive (source text primary key, record text)')
            self.db.execute('create table if not exists done (source text primary key)')
            self.db.execute('delete from archive');self.db.execute('delete from done')
            # Journals are authoritative. Truncate only an interrupted final JSON line.
            for name in ('footer-archive.jsonl','completed.jsonl'):
                path=self.state/name
                if not path.exists(): path.touch(mode=0o600)
                if not path.stat().st_size: continue
                with open(path,'rb+') as f:
                    good=0
                    while True:
                        raw=f.readline()
                        if not raw: break
                        try: r=json.loads(raw)
                        except ValueError:
                            if f.read(1): raise RuntimeError('Corrupt non-final journal line')
                            f.truncate(good); break
                        if not raw.endswith(b'\n'):
                            f.write(b'\n');f.flush()
                        good=f.tell()
                        if name.startswith('footer'):
                            self.db.execute('insert or replace into archive values (?,?)',(r['source'],json.dumps(r)))
                        else:
                            self.db.execute('insert or ignore into done values (?)',(r['source'],))
                            self.status['files']+=1; self.status['bytes']+=r['bytes']; self.status['touched_bytes']+=r.get('touched',0)
                            self.status['magic_checked']+=int(r.get('magic_checked',False))
                            self.status['magic_unchecked']+=int(not r.get('magic_checked',False))
            self.mismatch_paths=set()
            events=self.state/'events.jsonl'
            if events.exists():
                for raw in events.open():
                    try: event=json.loads(raw)
                    except ValueError: continue
                    kind=event.get('kind')
                    if kind in ('conflicts','skipped','errors','magic_mismatch'):
                        self.status[kind]+=1
                        if kind=='magic_mismatch':self.status['skipped']+=1;self.mismatch_paths.add(event['source'])
            self.db.commit()
            self.mismatch_paths={p for p in self.mismatch_paths if not self.db.execute('select 1 from done where source=?',(p,)).fetchone()}
            self.status['magic_mismatch_unresolved']=len(self.mismatch_paths)
            (self.state/'root-done').mkdir(exist_ok=True)
        except BaseException:
            if hasattr(self, 'db'): self.db.close()
            if hasattr(self, 'volume_fd'): os.close(self.volume_fd)
            if hasattr(self, 'lock'): self.lock.close()
            raise

    def space(self):
        s=os.statvfs(str(self.state)); available=s.f_bavail*s.f_frsize
        if available < self.reserve: raise LowSpace('free bytes %d below reserve %d'%(available,self.reserve))
        return available

    def record(self, kind, source, reason):
        with self.mu:
            self.status[kind]+=1
            if kind == 'magic_mismatch':
                self.status['skipped']+=1;self.mismatch_paths.add(source);self.status['magic_mismatch_unresolved']=len(self.mismatch_paths)
            append(self.state/'events.jsonl',[dict(at=time.time(),kind=kind,source=source,reason=reason)])

    def publish(self):
        with self.mu:
            now=time.time(); self.samples.append((now,self.session_bytes))
            while len(self.samples)>2 and self.samples[1][0]<now-60: self.samples.popleft()
            before,b=self.samples[0]
            self.status.update(at=now,elapsed_s=now-self.started,speed_Bps=(self.session_bytes-b)/max(.001,now-before),average_Bps=self.session_bytes/max(.001,now-self.started),loadavg=os.getloadavg())
            self.last_sample=(now,self.session_bytes)
            try: self.status['free_bytes']=self.space()
            except LowSpace as e: self.status['free_bytes']=os.statvfs(str(self.state)).f_bavail*os.statvfs(str(self.state)).f_frsize
            atomic(self.state/'status.json', self.status)

    def ticker(self):
        while not self.stop.wait(5): self.publish()

    def prepare(self, source):
        tmp=None
        try:
            st=os.lstat(source)
            if st.st_dev != os.fstat(self.volume_fd).st_dev:
                return ('skipped',source,'source crosses state filesystem boundary')
            if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size<588:
                return ('skipped',source,'not independent regular file or too short')
            fd=os.open(source, os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NOATIME',0))
            try:
                if ident(st)!=ident(os.fstat(fd)): raise IOError('source changed before open')
                with os.fdopen(os.dup(fd),'rb') as f: footer,size,mode,percent,segments=read_footer(f,st.st_size,self.marker)
                unwrap_record(footer,self.master)
                target=source[:-len(self.suffix)]
                # Resume archive lookups are supplied by the main thread.
                old=self.lookup_archive(source)
                if os.path.lexists(target) and not old: return ('conflicts',source,'target already exists without archive')
                if old and (old['identity']!=ident(st) or old['footer']!=footer.hex()):
                    return ('conflicts',source,'source differs from archived identity/footer')
                self.space(); tmp=os.path.join(os.path.dirname(source),'.'+os.path.basename(target)+'.inplace-'+self.runid)
                dfd=os.open(tmp,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:
                    fcntl.ioctl(dfd,FICLONE,fd)
                    size,touched=patch(dfd,footer,self.master,self.marker,self.space,magic_target=target)
                    os.fchown(dfd,st.st_uid,st.st_gid);os.fchmod(dfd,stat.S_IMODE(st.st_mode))
                    os.utime(dfd,ns=(st.st_atime_ns,st.st_mtime_ns))
                    ti=ident(os.fstat(dfd))
                finally: os.close(dfd)
                if ident(st)!=ident(os.lstat(source)): raise IOError('source identity changed during patch')
                if os.path.lexists(target):
                    if not self.equal(tmp,target):
                        os.unlink(tmp); return ('conflicts',source,'archived target differs from regenerated plaintext')
                    ti=ident(os.lstat(target))
                r=dict(source=source,relative_path=os.path.relpath(source,self.status['root']),identity=ident(st),footer=footer.hex(),target=target,tmp=tmp,tmp_identity=ti,bytes=size,touched=touched,mode=mode,percent=percent,at=time.time(),root=self.status['root'],magic_checked=Path(target).suffix.lower() in MAGIC_EXTENSIONS)
                return ('ready',r)
            finally: os.close(fd)
        except LowSpace as e:
            if tmp and os.path.lexists(tmp): os.unlink(tmp)
            return ('space',source,str(e))
        except MagicMismatch as e:
            if tmp and os.path.lexists(tmp): os.unlink(tmp)
            return ('magic_mismatch',source,str(e))
        except RecoveryError as e:
            if tmp and os.path.lexists(tmp): os.unlink(tmp)
            return ('skipped',source,str(e))
        except Exception as e:
            if tmp and os.path.lexists(tmp): os.unlink(tmp)
            return ('errors',source,type(e).__name__+': '+str(e))

    @staticmethod
    def equal(a,b):
        fa=os.open(a,os.O_RDONLY|os.O_NOFOLLOW);fb=os.open(b,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(fb).st_mode) or os.fstat(fa).st_size!=os.fstat(fb).st_size:return False
            while True:
                x=os.read(fa,8<<20);y=os.read(fb,8<<20)
                if x!=y:return False
                if not x:return True
        finally:os.close(fa);os.close(fb)

    def lookup_archive(self,source):
        with self.db_mu:
            row=self.db.execute('select record from archive where source=?',(source,)).fetchone()
        return json.loads(row[0]) if row else None

    def sync_volume(self,drain=False):
        if self._syncfs(self.volume_fd)!=0:
            error=ctypes.get_errno();raise OSError(error,os.strerror(error))
        with self.mu:
            self.status['syncfs_calls']+=1
            if drain:self.status['drain_syncfs_calls']+=1

    def log_completed(self,done):
        if not done:return
        append(self.state/'completed.jsonl',done)
        with self.db_mu:
            for r in done:self.db.execute('insert or ignore into done values (?)',(r['source'],))
            self.db.commit()
        with self.mu:
            for r in done:
                self.status['files']+=1;self.status['bytes']+=r['bytes'];self.status['touched_bytes']+=r.get('touched',0);self.session_bytes+=r['bytes']
                self.status['magic_checked']+=int(r.get('magic_checked',False));self.status['magic_unchecked']+=int(not r.get('magic_checked',False))
                self.mismatch_paths.discard(r['source'])
            self.status['magic_mismatch_unresolved']=len(self.mismatch_paths)

    def commit(self,batch):
        if not batch:return
        # Exactly one filesystem barrier: archive N and persist the previous install.
        append(self.state/'footer-archive.jsonl',batch)
        started=time.time();self.sync_volume()
        with self.db_mu:
            for r in batch:self.db.execute('insert or replace into archive values (?,?)',(r['source'],json.dumps(r)))
            self.db.commit()
        installed=[]
        for r in batch:
            try:
                if ident(os.lstat(r['source']))!=r['identity']:raise IOError('source identity changed before commit')
                if os.path.lexists(r['target']):
                    if not self.equal(r['tmp'],r['target']):raise IOError('target changed before resume commit')
                else:os.link(r['tmp'],r['target'],follow_symlinks=False)
                os.unlink(r['tmp'])
                if ident(os.lstat(r['source']))!=r['identity']:raise IOError('source changed before unlink')
                os.unlink(r['source'])
                installed.append(dict(source=r['source'],bytes=r['bytes'],touched=r['touched'],root=r['root'],at=time.time(),magic_checked=r.get('magic_checked',False)))
            except Exception as e:
                self.record('errors',r['source'],str(e))
                if os.path.lexists(r['tmp']):os.unlink(r['tmp'])
        previous=self.pending_done
        self.log_completed(previous)
        self.pending_done=installed
        with self.mu:
            self.status.update(installed_pending_files=len(installed),installed_pending_bytes=sum(r['bytes'] for r in installed),last_batch_files=len(batch),last_commit_seconds=time.time()-started)
        self.status['committed_batches']=self.status.get('committed_batches',0)+1
        self.publish()

    def flush_pending(self):
        # A root boundary, STOP or EOF has no N+1; drain the last install once.
        if self.pending_done:
            self.sync_volume(drain=True);self.log_completed(self.pending_done);self.pending_done=[]
            self.status.update(installed_pending_files=0,installed_pending_bytes=0)
        self.publish()

    def reconcile(self):
        done=[]
        for source,raw in self.db.execute('select source,record from archive where source not in (select source from done)'):
            r=json.loads(raw)
            if os.path.lexists(source):continue
            try:
                t=os.lstat(r['target'])
                if [t.st_dev,t.st_ino,t.st_size]!=r['tmp_identity'][:3]:raise IOError('missing source and target identity mismatch')
                done.append(dict(source=source,bytes=r['bytes'],touched=r.get('touched',0),root=r['root'],at=time.time(),reconciled=True,magic_checked=r.get('magic_checked',False)))
            except Exception as e:self.record('errors',source,str(e))
        if done:
            self.sync_volume();append(self.state/'completed.jsonl',done)
            for r in done:
                self.db.execute('insert or ignore into done values (?)',(r['source'],));self.status['files']+=1;self.status['bytes']+=r['bytes'];self.status['touched_bytes']+=r['touched'];self.status['magic_checked']+=int(r.get('magic_checked',False));self.status['magic_unchecked']+=int(not r.get('magic_checked',False))
            self.db.commit()

    def scan_unordered(self,root):
        def walk_error(e):self.record('errors',e.filename,str(e))
        for directory,dirs,files in os.walk(root,topdown=True,followlinks=False,onerror=walk_error):
            dirs[:]=sorted(d for d in dirs if not self.excluded_name(d) and not os.path.islink(os.path.join(directory,d)))
            for name in sorted(files):
                if self.excluded_name(name):continue
                source=os.path.join(directory,name)
                if os.path.islink(source):continue
                if TEMP.fullmatch(name):os.unlink(source);continue
                if name.endswith(self.suffix):yield source

    def excluded_name(self, name):
        return bool(self.exclude_prefixes) and name.startswith(self.exclude_prefixes)

    def scan(self, root):
        # Roots follow the caller's order; children use lexical order.
        yield from self.scan_unordered(root)

    def desired_threads(self):
        try:return max(1,min(16,int((self.state/'THREADS').read_text().strip())))
        except (OSError,ValueError):return self.default_threads

    def add_outstanding(self,amount):
        with self.condition:
            self.outstanding+=amount
            self.status['outstanding_files']=self.outstanding
            self.condition.notify_all()

    def scanning(self):
        try:
            while not self.shutdown.is_set():
                try:root,done=self.scan_requests.get(timeout=.5)
                except queue.Empty:continue
                try:
                    for source in self.scan(root):
                        if self.halt_scan.is_set():break
                        self.add_outstanding(1);enqueued=False
                        try:
                            while not self.halt_scan.is_set():
                                try:self.work.put(source,timeout=.5);enqueued=True;break
                                except queue.Full:pass
                        finally:
                            if not enqueued:self.add_outstanding(-1)
                        if not enqueued:break
                finally:done.set()
        except BaseException as e:self.fail_pipeline(e)

    def working(self,slot):
        try:
            while not self.shutdown.is_set():
                if slot>=self.worker_limit:
                    self.shutdown.wait(.25);continue
                try:source=self.work.get(timeout=.5)
                except queue.Empty:continue
                while True:
                    result=self.prepare(source)
                    if result[0]!='space':break
                    self.status.update(state='paused-low-space',reason=result[2])
                    if self.halt_scan.wait(2):result=('cancelled',source,result[2]);break
                while not self.shutdown.is_set():
                    try:self.results.put(result,timeout=.5);break
                    except queue.Full:pass
        except BaseException as e:self.fail_pipeline(e)

    def fail_pipeline(self,error):
        with self.mu:
            self.status.update(state='failed',reason=type(error).__name__+': '+str(error))
        self.fatal.set();self.halt_scan.set()

    def committing(self):
        batch=[];deadline=time.monotonic()+10
        try:
            while not self.shutdown.is_set():
                try:result=self.results.get(timeout=max(.05,min(1,deadline-time.monotonic())))
                except queue.Empty:result=None
                if result is not None:
                    kind=result[0]
                    if kind=='flush':
                        if batch:self.commit(batch);self.add_outstanding(-len(batch));batch=[]
                        self.flush_pending();result[1].set();deadline=time.monotonic()+10;continue
                    if kind=='ready':batch.append(result[1])
                    else:
                        if kind!='cancelled':self.record(*result)
                        self.add_outstanding(-1)
                if batch and (len(batch)>=256 or time.monotonic()>=deadline):
                    self.commit(batch);self.add_outstanding(-len(batch));batch=[];deadline=time.monotonic()+10
                elif not batch and time.monotonic()>=deadline:deadline=time.monotonic()+10
        except BaseException as e:self.fail_pipeline(e)

    def root_summary(self,index,root,before):
        totals={k:self.status[k]-before[k] for k in before};totals['files']=0;totals['bytes']=0
        with self.db_mu:
            for (raw,) in self.db.execute('select record from archive where source in (select source from done)'):
                r=json.loads(raw)
                if r['root']==root:totals['files']+=1;totals['bytes']+=r['bytes']
        atomic(self.state/'root-done'/('%02d.json'%index),dict(totals,root=root,index=index,completed_at=time.time(),revision='0.3.0'))

    def run(self):
        self.reconcile();self.status['state']='running';self.publish()
        self.worker_limit=self.desired_threads();self.status['threads']=self.worker_limit
        self.shutdown=threading.Event();self.halt_scan=threading.Event();self.fatal=threading.Event()
        self.condition=threading.Condition();self.outstanding=0
        self.work=queue.Queue(self.desired_threads()*4);self.results=queue.Queue(self.desired_threads()*4);self.scan_requests=queue.Queue(1)
        background=[threading.Thread(target=self.ticker,daemon=True,name='status'),threading.Thread(target=self.scanning,daemon=True,name='scan'),threading.Thread(target=self.committing,daemon=True,name='commit')]
        background += [threading.Thread(target=self.working,args=(i,),daemon=True,name='prepare-%d'%i) for i in range(16)]
        for thread in background:thread.start()
        try:
            for index,root in enumerate(self.roots,1):
                self.status.update(root=root,root_index=index)
                before={k:self.status[k] for k in ('files','bytes','conflicts','skipped','errors','magic_mismatch')}
                if not os.path.isdir(root) or os.path.islink(root):self.record('skipped',root,'root missing or symlink');continue
                scanned=threading.Event();self.scan_requests.put((root,scanned))
                while not scanned.is_set() or self.outstanding:
                    if self.fatal.is_set():raise RuntimeError(self.status.get('reason','pipeline thread failed'))
                    if (self.state/'STOP_REQUESTED').exists():self.halt_scan.set()
                    wanted=self.desired_threads();self.worker_limit=wanted;self.status['threads']=wanted
                    for q in (self.work,self.results):
                        with q.mutex:q.maxsize=wanted*4;q.not_full.notify_all()
                    self.status.update(scan_queue_files=self.work.qsize(),commit_queue_files=self.results.qsize())
                    with self.condition:self.condition.wait(.5)
                flushed=threading.Event();self.results.put(('flush',flushed))
                while not flushed.wait(.5):
                    if self.fatal.is_set():raise RuntimeError(self.status.get('reason','commit thread failed'))
                if self.halt_scan.is_set() or (self.state/'STOP_REQUESTED').exists():
                    self.status.update(state='stopped',reason='STOP_REQUESTED');return
                self.root_summary(index,root,before);self.status['roots_done']=index;self.publish()
            self.status['state']='completed'
        except BaseException as e:
            self.status.update(state='failed',reason=type(e).__name__+': '+str(e));raise
        finally:
            self.halt_scan.set();self.shutdown.set();self.stop.set()
            for thread in background:thread.join(timeout=3)
            self.publish();self.db.close();os.close(self.volume_fd);self.volume_fd=-1

def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', required=True)
    p.add_argument('--reserve-gb', type=float, required=True, help='Decimal GB left free; do not set to zero for real data')
    p.add_argument('--marker', required=True, help='Explicit eight hex digits for this session')
    p.add_argument('--suffix', default='.L0CK3D')
    p.add_argument('--exclude-prefix', action='append', default=[], help='Exclude file/directory name prefix; repeat as needed')
    p.add_argument('--threads', type=int, default=8)
    p.add_argument('--execute', action='store_true', help='Create plaintext and remove ciphertext after durable footer archive')
    p.add_argument('roots', nargs='+', help='Nonoverlapping roots, processed in the given order')
    a = p.parse_args()
    if not re.fullmatch(r'[0-9a-fA-F]{8}', a.marker):
        p.error('--marker must be exactly eight hex digits')
    if not a.execute:
        p.error('--execute is required; see docs/IN-PLACE.md')
    Recovery(a.state, a.roots, read_key(), int(a.reserve_gb*1e9), bytes.fromhex(a.marker),
             a.suffix, a.exclude_prefix, a.threads).run()


if __name__ == '__main__':
    main()
