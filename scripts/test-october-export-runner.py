#!/usr/bin/env python3
"""Temporary local exports only: known ciphertext, no incident data or network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
spec=importlib.util.spec_from_file_location('octexport',Path(__file__).with_name('october-export-runner.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
MASTER=bytes(range(48));KEY=bytes(reversed(range(32)));NONCE=bytes.fromhex('01030507090b0d0f');MARKER=bytes.fromhex('a1b2c3d4')

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.base=self.root/'volume2';self.month=self.base/'ExampleShare'/'店A'/'2026'/'10月';self.month.mkdir(parents=True)
        self.mount=self.root/'usb';self.mount.mkdir();self.target=self.mount/'Recovery_October2026';self.state=self.root/'control'
        self.proposal=dict(jobs=[dict(store='店A',source=str(self.month),output_relative=str(self.month.relative_to(self.base)))],destination=dict(proposed_mount=str(self.mount),proposed_root=self.target.name,filesystem='NTFS',expected_usb='fixture',last_free_bytes=10**12,last_observed_at=1234,reserve_bytes=50*10**9,metadata_budget_bytes=10*10**9))
        info=self.mount.stat();v=os.statvfs(self.mount)
        self.identity=dict(mount=str(self.mount),source='/dev/fixture',uuid='fixture-uuid',filesystem='fixture',st_dev=info.st_dev,root_ino=info.st_ino,total_bytes=v.f_blocks*v.f_frsize,block_bytes=10**12,model='fixture',usb_id='0000:0000')
        self.expected={}
    def clear(self,name='clear.jpg',data=b'known clear image'):
        source=self.month/name;source.write_bytes(data);self.expected[str(source)]=data;return source
    def cipher(self,name='cipher.jpg',size=10003):
        plain=(bytes(range(251))*(size//251+1))[:size];body=bytearray(plain);counter=0
        for offset,length in m.a.encrypted_segments(size,0x25,10):
            cursor=offset
            while length:
                amount=min(length,m.a.CALL_LIMIT);out,counter=m.a.chacha8_call(bytes(body[cursor:cursor+amount]),KEY,NONCE,counter);body[cursor:cursor+amount]=out;cursor+=amount;length-=amount
        footer=bytearray(588);encryptor=Cipher(algorithms.AES(MASTER[16:]),modes.CBC(MASTER[:16])).encryptor();footer[:48]=encryptor.update(KEY+NONCE+NONCE)+encryptor.finalize();footer[568:572]=MARKER;footer[572:576]=bytes((0x25,10,0x20,0));struct.pack_into('<I',footer,576,240002);struct.pack_into('<Q',footer,580,size)
        source=self.month/(name+'.L0CK3D');source.write_bytes(body+footer);self.expected[str(source)]=plain;return source
    def prepare(self):self.bundle=m.pre.make_manifest(self.proposal,self.base,self.target,now=5678);self.sha=self.bundle['hashes']['manifest'];return self.bundle
    def runner(self,**kwargs):
        kwargs.setdefault('identity_probe',lambda mount:self.identity);kwargs.setdefault('free_probe',lambda:10**12)
        return m.Export(self.bundle,self.identity,self.state,self.sha,MASTER,MARKER,**kwargs)
    def rows(self):return [json.loads(line) for line in (self.state/'completion.jsonl').read_text().splitlines()]
    def fork_exit(self,point):
        pid=os.fork()
        if pid==0:
            try:self.runner(fault=lambda p:os._exit(77) if p==point else None).run(True)
            except BaseException:os._exit(78)
            os._exit(79)
        self.assertEqual(os.waitpid(pid,0)[1],77<<8)
    def test_default_has_no_writes_and_execute_copy_decrypt_resume(self):
        self.clear();self.cipher();self.prepare();before={e['source']:Path(e['source']).read_bytes() for e in self.bundle['manifest']['entries']}
        self.assertEqual(self.runner().run()['state'],'preflight-only');self.assertFalse(self.state.exists());self.assertFalse(self.target.exists())
        result=self.runner().run(True);self.assertEqual(result['state'],'completed-manifest');self.assertEqual(result['completed_files'],2)
        self.assertEqual(result['stores']['店A']['copy_files'],1);self.assertEqual(result['stores']['店A']['decrypt_files'],1)
        for entry in self.bundle['manifest']['entries']:
            self.assertEqual(Path(entry['output']).read_bytes(),self.expected[entry['source']]);self.assertEqual(Path(entry['source']).read_bytes(),before[entry['source']])
        completions=[x for x in self.rows() if x['kind']=='complete'];self.assertEqual(len(completions),2)
        self.assertTrue(next(x for x in completions if x['operation']=='decrypt')['source_attestation']['sha256'])
        self.assertEqual(self.runner().run(True)['completed_files'],2);self.assertEqual(len([x for x in self.rows() if x['kind']=='complete']),2)
    def test_real_fork_complete_orphan_proved_by_redecrypt_and_clear_hash(self):
        for cipher in (False,True):
            with self.subTest(cipher=cipher):
                if cipher:
                    # Separate control and target are required for the second immutable manifest.
                    self.state=self.root/'control2';self.target=self.mount/'Second';self.proposal['destination']['proposed_root']='Second'
                    for p in self.month.iterdir():p.unlink()
                    self.cipher()
                else:self.clear()
                self.prepare();self.fork_exit('verified-output-before-record')
                self.assertEqual(len([x for x in self.rows() if x['kind']=='complete']),0)
                self.assertEqual(self.runner().run(True)['state'],'completed-manifest')
                row=next(x for x in self.rows() if x['kind']=='complete');self.assertTrue(row['orphan_adopted']);self.assertTrue(Path(row['source']).exists())
                if cipher:self.assertEqual(row['source_attestation']['kind'],'verified-redecrypt-v1')
    def test_partial_or_wrong_orphan_preserved_and_source_untouched(self):
        source=self.clear(data=b'correct');self.prepare();self.fork_exit('creation-intent-durable');entry=self.bundle['manifest']['entries'][0];output=Path(entry['output']);output.parent.mkdir(parents=True)
        for data in (b'bad',b'WRONG!!'):
            output.write_bytes(data)
            with self.assertRaises(m.r.Refused):self.runner().run(True)
            self.assertEqual(output.read_bytes(),data);self.assertEqual(source.read_bytes(),b'correct')
    def test_live_identity_capacity_and_collision_block_without_overwrite(self):
        self.clear();self.prepare()
        with self.assertRaises(m.r.Refused):self.runner(identity_probe=lambda mount:dict(self.identity,uuid='different'))
        with self.assertRaises(m.r.Refused):self.runner(free_probe=lambda:60*10**9).run(True)
        entry=self.bundle['manifest']['entries'][0];out=Path(entry['output']);out.parent.mkdir(parents=True);out.write_bytes(b'existing')
        with self.assertRaises(m.r.Refused):self.runner().run(True)
        self.assertEqual(out.read_bytes(),b'existing')
    def test_mutated_completed_output_rejected_and_partial_log_tail_reconciled(self):
        self.clear();self.prepare();self.runner().run(True)
        with (self.state/'completion.jsonl').open('ab') as log:log.write(b'{"incomplete":')
        self.assertEqual(self.runner().run(True)['state'],'completed-manifest')
        entry=self.bundle['manifest']['entries'][0];out=Path(entry['output']);out.write_bytes(b'corrupt')
        with self.assertRaises(m.r.Refused):self.runner().run(True)
        self.assertEqual(out.read_bytes(),b'corrupt');self.assertTrue(Path(entry['source']).exists())
    def test_stop_request_before_submit_and_during_work_drains(self):
        self.clear();self.cipher();self.prepare();self.state.mkdir(mode=0o700);(self.state/'STOP_REQUESTED').touch()
        self.assertEqual(self.runner().run(True)['state'],'paused');self.assertFalse(self.target.exists())
        (self.state/'STOP_REQUESTED').unlink();fired=[]
        def stop(point):
            if point=='verified-output-before-record' and not fired:fired.append(True);(self.state/'STOP_REQUESTED').touch()
        result=self.runner(fault=stop).run(True);self.assertEqual(result['state'],'paused');self.assertEqual(result['completed_files'],2)
        self.assertEqual(len([x for x in self.rows() if x['kind']=='complete']),2)
    def test_changed_manifest_source_and_wrong_key_leave_sources(self):
        source=self.cipher();self.prepare();original=source.read_bytes()
        runner=self.runner();runner.master=bytes(48)
        with self.assertRaises(m.a.RecoveryError):runner.run(True)
        self.assertEqual(source.read_bytes(),original)
        source.write_bytes(original+b'changed')
        with self.assertRaises(m.r.Refused):self.runner().run(True)

if __name__=='__main__':unittest.main(verbosity=2)
