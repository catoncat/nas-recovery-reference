#!/usr/bin/env python3
"""Space, coverage, root totals and native backend regression fixtures.

Ported from the source-tool adaptive-space, root-boundary and coverage tests.
Temporary files only; clone/sync are emulated. No production access.
"""
import importlib.util
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('inplace_fixture',HERE/'test-inplace-recover.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
m=f.m
from recovery_space import SpaceBudget, parse_usage
from chacha8_native import load_cipher
from decrypt_copy import chacha8_call as python_call
from file_layout import PARTIAL_FACTORS

class Improvements(f.InplaceTests):
    # Only the new methods are selected below; inherited cases run in their own suite.
    def test_adaptive_fullwrite_and_clone_all_layouts(self):
        for strategy in ('clone','full_write'):
            job=self.recovery(state=strategy)
            job.write_strategy=lambda *args:(strategy,'forced-synthetic')
            cases=[(0x24,0,0),(0x24,0,65),(0x24,0,m.CALL_LIMIT+65),(0x26,0,4098),(0x26,0,(1<<20)+17)]
            cases += [(0x25,p,8199) for p in PARTIAL_FACTORS]
            cases += [(0x25,50,(61<<20)+123)]
            batch=[];expected=[]
            for index,(mode,percent,size) in enumerate(cases):
                source,sha,_=self.cipher(strategy+'/%d.bin'%index,os.urandom(size),mode,percent)
                record=self.prepare(job,source)
                self.assertEqual(record['write_strategy'],strategy)
                self.assertEqual(hashlib.sha256(Path(record['tmp']).read_bytes()).hexdigest(),sha)
                batch.append(record);expected.append((Path(record['target']),sha))
            job.commit(batch);job.flush_pending()
            self.assertEqual(job.status[strategy+'_files'],len(cases))
            for path,sha in expected:self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),sha)
            job.db.close();job.lock.close()
            resumed=self.recovery(state=strategy)
            self.assertEqual(resumed.status[strategy+'_files'],len(cases))
            self.assertEqual(resumed.root_totals.get(str(self.inputs))['files'],len(cases))

    def test_minimum_parser_reservations_and_failed_sample(self):
        text='Device unallocated: 2000\nFree (estimated): 2500 (min: 1500)\nData,single: Size:10000, Used:9500\nMetadata,DUP: Size:200, Used:1\n'
        row=parse_usage(text);self.assertEqual(row['conservative_bytes'],1500)
        budget=SpaceBudget('/',sampler=lambda:row)
        self.assertTrue(budget.acquire('a',1000,200));self.assertFalse(budget.acquire('b',301,200))
        budget.release('a');self.assertEqual(budget.snapshot()['available_bytes'],500)
        self.assertEqual(budget.snapshot(force=True)['available_bytes'],1500)
        budget.sampler=lambda:(_ for _ in ()).throw(OSError('synthetic'))
        self.assertEqual(budget.snapshot(force=True)['available_bytes'],0)
        with self.assertRaises(ValueError):parse_usage(text.replace('Data,single','Data+Metadata,single'))
        budget=SpaceBudget('/',sampler=lambda:row)
        barrier=threading.Barrier(8);results=[]
        def reserve(i):barrier.wait();results.append(budget.acquire(str(i),300,200))
        threads=[threading.Thread(target=reserve,args=(i,)) for i in range(8)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(sum(results),4)

    def test_policy_low_space_failure_and_reservation_cleanup(self):
        job=self.recovery();job.write_strategy=m.Recovery.write_strategy.__get__(job)
        job.small_bytes=1000;job.clone_above=800000;job.safety=16000;job.reserve=200000
        amount=[2000000];job.space_budget=SpaceBudget('/',sampler=lambda:dict(conservative_bytes=amount[0]))
        self.assertEqual(job.write_strategy(1000,0x26,1)[0],'full_write')
        self.assertEqual(job.write_strategy(4000,0x26,1000)[0],'full_write')
        self.assertEqual(job.write_strategy(4001,0x26,1000)[0],'clone')
        amount[0]=700000;job.space_budget.snapshot(force=True)
        self.assertEqual(job.write_strategy(100000,0x25,10000)[0],'full_write')
        source=self.cipher('low.bin',os.urandom(8199),0x25,10)[0];before=m.ident(source.stat())
        amount[0]=200000;job.space_budget.snapshot(force=True)
        self.assertEqual(job.prepare(str(source))[0],'space');self.assertEqual(m.ident(source.stat()),before)
        amount[0]=2000000;job.space_budget.snapshot(force=True)
        with patch.object(m,'patch',side_effect=OSError('injected write failure')):
            self.assertEqual(job.prepare(str(source))[0],'errors')
        self.assertFalse(job.space_budget.pending);self.assertTrue(source.exists())
        self.assertFalse(list(self.inputs.glob('.*.inplace-*')))

    def test_precise_exclusions_recycle_users_and_tools(self):
        names=['#files','#backup','#recycle','@user','.history','#snapshot-custom','@eaDir-custom']
        job=self.recovery(exclude_names=m.SYSTEM_DIRS|{'private-tools'})
        retained=[]
        for name in names:self.cipher(name+'/one.bin',b'plain')
        for name in m.SYSTEM_DIRS|{'private-tools'}:retained.append(self.cipher(name+'/keep.bin',b'cipher')[0])
        job.run()
        for name in names:self.assertEqual((self.inputs/name/'one.bin').read_bytes(),b'plain')
        for path in retained:self.assertTrue(path.exists())
        self.assertEqual(job.status['files'],len(names))

    def test_root_summary_no_sql_replay_reconcile_and_empty(self):
        job=self.recovery()
        a,b=[self.cipher('%d.bin'%i,b'x'*(i+1))[0] for i in range(2)]
        job.commit([self.prepare(job,a)]);job.flush_pending()
        record=self.prepare(job,b);m.append(job.state/'footer-archive.jsonl',[record])
        os.link(record['tmp'],record['target']);os.unlink(record['tmp']);b.unlink()
        job.db.close();job.lock.close()
        resumed=self.recovery();resumed.reconcile()
        self.assertEqual(resumed.root_totals.get(str(self.inputs)),dict(files=2,bytes=3))
        resumed.db.set_authorizer(lambda *args:sqlite3.SQLITE_DENY)
        before={k:0 for k in ('files','bytes','errors','skipped','conflicts','magic_mismatch')}
        resumed.root_summary(1,str(self.inputs),before)
        resumed.root_summary(2,str(self.inputs/'empty'),before)
        import json
        self.assertEqual(json.loads((resumed.state/'root-done/01.json').read_text())['files'],2)
        self.assertEqual(json.loads((resumed.state/'root-done/02.json').read_text())['bytes'],0)

    def test_year_streaming_and_thread_hot_range(self):
        job=self.recovery(newest_year=2026);job.halt_scan=threading.Event()
        paths=['/synthetic/2020/a','/synthetic/2026/z','/synthetic/2025/b','/synthetic/2026/y'];seen=[]
        def scanner(root):
            for path in paths:seen.append(path);yield path
        job.scan_unordered=scanner;iterator=job.scan(str(self.inputs))
        self.assertEqual(next(iterator),paths[1]);self.assertEqual(len(seen),2)
        self.assertEqual(list(iterator),[paths[3],paths[2],paths[0]])
        for raw,want in [('24',24),('99',24),('0',1),('bad',8)]:
            (job.state/'THREADS').write_text(raw);self.assertEqual(job.desired_threads(),want)

    def test_fullwrite_identity_drift_and_magic_guard(self):
        job=self.recovery();job.write_strategy=lambda *args:('full_write','guard')
        source=self.cipher('drift.bin',b'abc')[0];original=m.patch
        def changed(*args,**kwargs):
            result=original(*args,**kwargs)
            with source.open('ab') as stream:stream.write(b'x')
            return result
        with patch.object(m,'patch',changed):self.assertEqual(job.prepare(str(source))[0],'errors')
        self.assertTrue(source.exists());self.assertFalse(job.space_budget.pending)
        bad=self.cipher('bad.jpg',b'unknown bytes')[0]
        self.assertEqual(job.prepare(str(bad))[0],'magic_mismatch');self.assertTrue(bad.exists())
        self.assertFalse(job.space_budget.pending)

class NativeTests(unittest.TestCase):
    def test_compile_differential_counter_boundaries_and_fallback(self):
        with tempfile.TemporaryDirectory(prefix='cipher-test-') as temp:
            library=Path(temp)/'libchacha8.so'
            subprocess.run(['cc','-O3','-shared','-fPIC',str(HERE/'chacha8_native.c'),'-o',str(library)],check=True)
            call,status=load_cipher(python_call,library)
            self.assertTrue(status['cipher_backend'].startswith('c-'),status)
            for size,counter in [(0,0),(1,0),(63,1),(64,1),(65,1),(511,(1<<32)-2),(65,(1<<64)-2),(m.CALL_LIMIT,2)]:
                data=os.urandom(size);key=os.urandom(32);nonce=os.urandom(8)
                self.assertEqual(call(data,key,nonce,counter),python_call(data,key,nonce,counter))
            for args in [(b'x',bytes(31),bytes(8),0),(b'x',bytes(32),bytes(8),1<<64)]:
                with self.assertRaises(Exception):call(*args)
            fallback,info=load_cipher(python_call,Path(temp)/'missing.so')
            self.assertIs(fallback,python_call);self.assertEqual(info['cipher_backend'],'numpy')

if __name__=='__main__':
    suite=unittest.TestSuite()
    for name in Improvements.__dict__:
        if name.startswith('test_'):suite.addTest(Improvements(name))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
