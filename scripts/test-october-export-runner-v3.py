#!/usr/bin/env python3
"""Offline v3 invariants and syscall counts; no NAS or throughput benchmark."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import threading
import unittest
from unittest.mock import patch
from concurrent.futures import wait as real_wait, ALL_COMPLETED

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

m=load('october_v3','october-export-runner-v3.py');fixtures=load('october_original_fixtures','test-october-export-runner.py');fixtures.m=m

class V3Tests(fixtures.ExportTests):
    def test_explicit_non_october_root_requires_caller_scope_and_resumes(self):
        self.month=self.base/'ExampleBranch'/'ExampleProject';self.month.mkdir(parents=True)
        self.clear();self.cipher()
        self.proposal['jobs']=[dict(store=self.month.name,source=str(self.month),output_relative=str(self.month.relative_to(self.base)))]
        with self.assertRaises(m.pre.Refused):m.pre.make_manifest(self.proposal,self.base,self.target)
        self.bundle=m.pre.make_manifest(self.proposal,self.base,self.target,approved_source_root=self.month)
        self.sha=self.bundle['hashes']['manifest']
        with self.assertRaises(m.r.Refused):self.runner()
        with self.assertRaises(m.r.Refused):self.runner(approved_source_root=self.base/'other')
        self.assertEqual(self.runner(approved_source_root=self.month).run(True)['completed_files'],2)
        self.assertEqual(self.runner(approved_source_root=self.month).run(True)['completed_files'],2)

    def test_existing_parents_do_not_attempt_mkdir(self):
        self.clear();self.prepare();runner=self.runner()
        output=Path(self.bundle['manifest']['entries'][0]['output'])
        output.parent.mkdir(parents=True)
        with patch.object(m.os,'mkdir',side_effect=AssertionError('redundant mkdir')):
            runner.ensure_parent(output)

    def test_parent_creation_race_syncs_and_reopens(self):
        self.clear();self.prepare();runner=self.runner()
        output=Path(self.bundle['manifest']['entries'][0]['output'])
        real_mkdir=os.mkdir;real_sync=os.fsync;created=[];synced=[]
        def competitor(name,*args,**kwargs):
            real_mkdir(name,*args,**kwargs);created.append(name)
            raise FileExistsError('competing creator won')
        def sync(fd):synced.append(fd);return real_sync(fd)
        with patch.object(m.os,'mkdir',competitor),patch.object(m.os,'fsync',sync):
            runner.ensure_parent(output)
        self.assertTrue(output.parent.is_dir())
        self.assertEqual(len(created),len(output.parent.relative_to(self.mount).parts))
        self.assertEqual(len(synced),len(created))

    def test_parent_symlink_replacement_is_rejected(self):
        self.clear();self.prepare();runner=self.runner()
        output=Path(self.bundle['manifest']['entries'][0]['output'])
        output.parent.mkdir(parents=True);runner.ensure_parent(output)
        held=output.parent.with_name('original-parent');output.parent.rename(held)
        output.parent.symlink_to(held,target_is_directory=True)
        with self.assertRaises((OSError,m.r.Refused)):runner.ensure_parent(output)
        self.assertFalse(output.exists())

    def fill(self,count=8):
        for index in range(count):
            if index%2:self.cipher('cipher'+str(index)+'.jpg')
            else:self.clear('clear'+str(index)+'.jpg',b'data'+bytes([index]))
        self.prepare()
    def all_ready(self,pending,timeout=None,return_when=None):return real_wait(pending,timeout=5,return_when=ALL_COMPLETED)
    def test_default_producer_api_never_calls_timing_clock(self):
        source=self.cipher();self.prepare();output=Path(self.bundle['manifest']['entries'][0]['output']);output.parent.mkdir(parents=True)
        with patch.object(m.a.time,'perf_counter',side_effect=AssertionError('default timing clock used')):
            result=m.a.attest(source,output,self.base,self.target,fixtures.MASTER,fixtures.MARKER)
            with m.r.parent_fd(output) as (parent,name):m.a.read_output(parent,name,result['bytes'],result['output_sha256'],lambda point:None)
        self.assertEqual(output.read_bytes(),self.expected[str(source)])

    def test_intent_group_durable_before_any_submit_and_timing_spans(self):
        self.fill();runner=self.runner();original=runner.one;seen=[]
        def one(entry):
            self.assertEqual(len(runner.intents),8);seen.append(entry['id']);return original(entry)
        runner.one=one
        with patch.object(m,'wait',self.all_ready):result=runner.run(True)
        self.assertEqual(len(seen),8);self.assertEqual(result['timing_summary']['log_batches'],dict(intent=1,completion=1))
        rows=[json.loads(line) for line in (self.state/'timings-v3.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows),8)
        for row in rows:
            self.assertEqual(row['intent_log_shared']['size'],8);self.assertEqual(row['completion_log_shared']['size'],8)
            for name in ['prepare_metadata_seconds','recover_copy_seconds','output_fsync_seconds','readback_hash_seconds','worker_wall_seconds','worker_unclassified_seconds','source_read_seconds','decrypt_seconds','source_hash_seconds','plaintext_hash_seconds','output_write_seconds','footer_parse_key_unwrap_seconds']:
                self.assertGreaterEqual(row['timings'][name],0)
            self.assertEqual(row['scheduler_wait_shared']['size'],8)
            timing=row['timings'];children=sum(timing[key] for key in ['source_read_seconds','decrypt_seconds','source_hash_seconds','plaintext_hash_seconds','output_write_seconds'])
            self.assertLessEqual(children,timing['recover_copy_seconds'])
            top=sum(timing.get(key,0.0) for key in ['prepare_metadata_seconds','footer_parse_key_unwrap_seconds','recover_copy_seconds','output_fsync_seconds','readback_hash_seconds','orphan_output_hash_seconds','final_metadata_seconds','worker_unclassified_seconds'])
            self.assertAlmostEqual(top,timing['worker_wall_seconds'],places=7)
    def test_intent_append_failure_creates_no_output_or_ram_intents(self):
        self.fill();runner=self.runner();original=runner.append
        def fail(rows):
            if rows[0]['kind']=='intent':raise OSError('intent fsync failure')
            return original(rows)
        runner.append=fail
        with self.assertRaisesRegex(OSError,'intent fsync failure'):runner.run(True)
        self.assertFalse(self.target.exists());self.assertEqual(runner.intents,set());self.assertEqual(runner.records,{})
    def test_completion_torn_append_has_no_ram_done_and_orphans_reproved(self):
        self.fill();runner=self.runner();original=runner.append
        def fail(rows):
            if rows[0]['kind']=='complete':
                data=m.pre.encode(rows[0]);os.write(runner.log,data[:len(data)//2]);raise OSError('completion fsync failure')
            return original(rows)
        runner.append=fail
        with patch.object(m,'wait',self.all_ready):
            with self.assertRaisesRegex(OSError,'completion fsync failure'):runner.run(True)
        self.assertEqual(runner.records,{})
        self.assertEqual(self.runner().run(True)['completed_files'],8)
        for row in self.rows():
            if row['kind']=='complete':self.assertTrue(row['orphan_adopted']);self.assertTrue(Path(row['source']).exists())
    def test_real_fork_batch_boundaries_and_unlogged_complete_outputs(self):
        self.fill();self.fork_exit('intent-batch-durable');self.assertFalse(self.target.exists())
        self.assertEqual(len([row for row in self.rows() if row['kind']=='intent']),8)
        pid=os.fork()
        if pid==0:
            try:
                m.wait=self.all_ready
                self.runner(fault=lambda point:os._exit(77) if point=='verified-batch-before-log' else None).run(True)
            except BaseException:os._exit(78)
            os._exit(79)
        self.assertEqual(os.waitpid(pid,0)[1],77<<8)
        self.assertEqual(len([row for row in self.rows() if row['kind']=='complete']),0)
        self.assertEqual(self.runner().run(True)['completed_files'],8)
        self.assertTrue(all(row['orphan_adopted'] for row in self.rows() if row['kind']=='complete'))
    def test_full_clear_orphan_gets_file_parent_sync_before_completion(self):
        source=self.clear(data=b'full bytes but crash before fsync');self.prepare();self.fork_exit('copy-block')
        output=Path(self.bundle['manifest']['entries'][0]['output']);events=[];real_fsync=os.fsync
        def sync(fd):
            info=os.fstat(fd)
            if (info.st_dev,info.st_ino)==(output.stat().st_dev,output.stat().st_ino):events.append('output-file-sync')
            if (info.st_dev,info.st_ino)==(output.parent.stat().st_dev,output.parent.stat().st_ino):events.append('output-parent-sync')
            return real_fsync(fd)
        runner=self.runner();original=runner.append
        def append(rows):
            if rows[0]['kind']=='complete':
                self.assertIn('output-file-sync',events);self.assertIn('output-parent-sync',events);events.append('completion')
            return original(rows)
        runner.append=append
        with patch.object(os,'fsync',sync):runner.run(True)
        self.assertLess(events.index('output-file-sync'),events.index('completion'));self.assertLess(events.index('output-parent-sync'),events.index('completion'));self.assertTrue(source.exists())
    def test_default_wait_asynchronous_refill_has_once_only_durable_completion(self):
        self.fill(12);runner=self.runner();entries=self.bundle['manifest']['entries']
        positions={entry['id']:index for index,entry in enumerate(entries)}
        entered=[threading.Event() for _ in entries];release=[threading.Event() for _ in entries];durable=[threading.Event() for _ in entries]
        original_one=runner.one;original_append=runner.append;batches=[];failures=[]
        def one(entry):
            index=positions[entry['id']];self.assertIn(entry['id'],runner.intents);entered[index].set()
            if not release[index].wait(5):raise RuntimeError('fixture release timeout')
            return original_one(entry)
        def append(rows):
            if rows[0]['kind']=='complete':
                for row in rows:self.assertNotIn(row['entry_id'],runner.records)
                batches.append(len(rows))
            result=original_append(rows)
            if rows[0]['kind']=='complete':
                for row in rows:durable[positions[row['entry_id']]].set()
            return result
        def control():
            for index in range(len(entries)):
                if not entered[index].wait(5):failures.append('worker did not enter');break
                release[index].set()
                if not durable[index].wait(5):failures.append('completion not durable');break
            for event in release:event.set()
        runner.one=one;runner.append=append;thread=threading.Thread(target=control);thread.start()
        try:result=runner.run(True)
        finally:
            for event in release:event.set()
            thread.join(5)
        self.assertFalse(failures);self.assertFalse(thread.is_alive());self.assertEqual(result['completed_files'],12)
        complete=[row for row in self.rows() if row['kind']=='complete'];self.assertEqual(len(complete),12);self.assertEqual(len({row['entry_id'] for row in complete}),12)
        self.assertTrue(all(1<=size<=8 for size in batches));self.assertEqual(sum(batches),12)
        self.assertEqual(result['timing_summary']['log_batches']['intent'],1)
        print('default asynchronous completion batch sizes: '+str(batches))

    def test_exact_fsync_counts_for_eight_new_mixed_files(self):
        self.fill();output_parent=Path(self.bundle['manifest']['entries'][0]['output']).parent;output_parent.mkdir(parents=True)
        counts={};real_fsync=os.fsync
        def run_count(export_type,control):
            counter=dict(output_file=0,output_parent=0,journal=0,readback=0);parent_identity=(output_parent.stat().st_dev,output_parent.stat().st_ino)
            runner=export_type(self.bundle,self.identity,control,self.sha,fixtures.MASTER,fixtures.MARKER,identity_probe=lambda mount:self.identity,free_probe=lambda:10**12)
            def sync(fd):
                info=os.fstat(fd);identity=(info.st_dev,info.st_ino)
                if identity==parent_identity:counter['output_parent']+=1
                elif stat.S_ISREG(info.st_mode):
                    journal=control/'completion.jsonl'
                    if journal.exists() and identity==(journal.stat().st_dev,journal.stat().st_ino):counter['journal']+=1
                    else:
                        for entry in self.bundle['manifest']['entries']:
                            output=Path(entry['output'])
                            if output.exists() and identity==(output.stat().st_dev,output.stat().st_ino):counter['output_file']+=1;break
                return real_fsync(fd)
            original=m.a.read_output
            def read(*args,**kwargs):counter['readback']+=1;return original(*args,**kwargs)
            with patch.object(os,'fsync',sync),patch.object(m.a,'read_output',read):runner.run(True)
            return counter
        # Force one eight-result ready group, not a synthetic throughput test.
        with patch.object(m,'wait',self.all_ready):counts['v3']=run_count(m.Export,self.state)
        for entry in self.bundle['manifest']['entries']:Path(entry['output']).unlink()
        with patch.object(m.base,'wait',self.all_ready):counts['baseline']=run_count(m.base.Export,self.root/'baseline-control')
        self.assertEqual(counts['baseline'],dict(output_file=16,output_parent=16,journal=17,readback=8))
        self.assertEqual(counts['v3'],dict(output_file=8,output_parent=8,journal=3,readback=8))
        print('local syscall counts (journal includes initial header): '+json.dumps(counts,sort_keys=True))

    def test_cached_parent_avoids_repeat_open_walk_but_rejects_ancestor_replacement(self):
        self.clear();self.prepare();runner=self.runner()
        output=Path(self.bundle['manifest']['entries'][0]['output'])
        runner.ensure_parent(output)
        with patch.object(runner,'_prepare_parent_uncached',side_effect=AssertionError('repeated creation walk')):
            runner.ensure_parent(output)
        ancestor=output.parent.parent
        renamed=ancestor.with_name(ancestor.name+'-moved');ancestor.rename(renamed)
        ancestor.symlink_to(renamed,target_is_directory=True)
        with self.assertRaises((OSError,m.r.Refused)):runner.ensure_parent(output)

    def test_status_never_enumerates_completed_records_and_resume_totals_match(self):
        self.fill(12);runner=self.runner();original_status=runner.status
        def status(*args,**kwargs):
            with patch.object(runner.records,'values',side_effect=AssertionError('status scanned completed records')):
                return original_status(*args,**kwargs)
        runner.status=status
        result=runner.run(True);resumed=self.runner().run(True)
        self.assertEqual(result['completed_bytes'],sum(e['expected_output_bytes'] for e in self.bundle['manifest']['entries']))
        self.assertEqual(result['completed_bytes'],resumed['completed_bytes'])
        self.assertEqual(result['stores'],resumed['stores'])

    def test_directory_concurrency_is_bounded_and_all_entries_are_delivered(self):
        import time
        for directory in range(5):
            (self.month/str(directory)).mkdir()
            for index in range(3):self.clear(str(directory)+'/'+str(index)+'.jpg')
        self.prepare();runner=self.runner();original=runner.one
        lock=threading.Lock();active={};peak=[]
        def one(entry):
            directory=str(Path(entry['source']).parent)
            with lock:
                active[directory]=active.get(directory,0)+1;peak.append(len(active))
            try:
                time.sleep(0.01)
                return original(entry)
            finally:
                with lock:
                    active[directory]-=1
                    if not active[directory]:del active[directory]
        runner.one=one;result=runner.run(True)
        self.assertEqual(result['completed_files'],15);self.assertLessEqual(max(peak),2)
        self.assertEqual(len([row for row in self.rows() if row['kind']=='complete']),15)
        for entry in self.bundle['manifest']['entries']:
            self.assertEqual(Path(entry['output']).read_bytes(),self.expected[entry['source']])

    def test_cached_preparation_reduces_metadata_calls(self):
        from contextlib import ExitStack
        self.clear();self.prepare();runner=self.runner()
        output=Path(self.bundle['manifest']['entries'][0]['output']);runner.ensure_parent(output)
        def count(call):
            counters={name:0 for name in ('open','close','fstat','stat')}
            with ExitStack() as stack:
                for name in counters:
                    original=getattr(os,name)
                    def wrapped(*args,_name=name,_original=original,**kwargs):
                        counters[_name]+=1;return _original(*args,**kwargs)
                    stack.enter_context(patch.object(os,name,wrapped))
                call(output)
            return counters
        uncached=count(runner._prepare_parent_uncached);cached=count(runner.ensure_parent)
        self.assertEqual(cached['open'],0);self.assertEqual(cached['fstat'],0)
        self.assertLess(sum(cached.values()),sum(uncached.values()))
        print('directory preparation syscall counts: '+json.dumps(dict(uncached=uncached,cached=cached)))

    def test_lookahead_intents_do_not_create_outputs_when_stopped_before_submit(self):
        self.fill(40)
        def stop(point):
            if point=='intent-batch-durable':raise RuntimeError('interrupt before submission')
        runner=self.runner(fault=stop)
        with self.assertRaisesRegex(RuntimeError,'interrupt before submission'):runner.run(True)
        self.assertEqual(len([row for row in self.rows() if row['kind']=='intent']),32)
        self.assertFalse(self.target.exists())
        resumed=self.runner().run(True)
        self.assertEqual(resumed['completed_files'],40)
        self.assertEqual(len([row for row in self.rows() if row['kind']=='complete']),40)

if __name__=='__main__':unittest.main(verbosity=2)
