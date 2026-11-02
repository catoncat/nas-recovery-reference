"""Bounded, cancellable scandir traversal within one ordered recovery root."""
import os
import queue
import threading
import time

def parallel_scan(root, excluded, temporary, runid, halt, on_error, metrics, workers=4, directory_limit=512, file_limit=128, suffix='.L0CK3D'):
    directories=queue.Queue(directory_limit);files=queue.Queue(file_limit)
    directories.put(root)
    cancel=threading.Event();finished=threading.Event();lock=threading.Lock()
    pending=[1];failures=[]
    def change_pending(amount):
        with lock:
            pending[0]+=amount
            if pending[0]==0:finished.set()
    def stopped():return cancel.is_set() or halt.is_set()
    def worker():
        local=[]
        try:
            while not stopped():
                if local:directory=local.pop()
                else:
                    try:directory=directories.get(timeout=.1)
                    except queue.Empty:
                        if finished.is_set():break
                        continue
                began=time.perf_counter()
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if stopped():break
                            if excluded(entry.name):continue
                            try:
                                if entry.is_symlink():continue
                                if entry.is_dir(follow_symlinks=False):
                                    change_pending(1)
                                    try:directories.put_nowait(entry.path)
                                    except queue.Full:local.append(entry.path)
                                    continue
                                if temporary.fullmatch(entry.name):
                                    # A streaming iterator can see files just created by
                                    # our preparers. Only orphaned older run IDs may go.
                                    if not entry.name.endswith('.inplace-'+runid):
                                        try:os.unlink(entry.path)
                                        except FileNotFoundError:pass
                                    continue
                                if not entry.name.endswith(suffix):continue
                                if not entry.is_file(follow_symlinks=False):continue
                                while not stopped():
                                    try:metrics.call('scan_file_queue_put',files.put,entry.path,timeout=.1);break
                                    except queue.Full:pass
                            except FileNotFoundError:continue  # concurrently completed source
                            except OSError as error:on_error(error)
                except OSError as error:on_error(error)
                finally:
                    metrics.observe('scan_directory',time.perf_counter()-began)
                    change_pending(-1)
        except BaseException as error:
            with lock:failures.append(error)
            cancel.set()
    threads=[threading.Thread(target=worker,name='scandir-%d'%i) for i in range(workers)]
    for thread in threads:thread.start()
    try:
        while not stopped():
            try:yield files.get(timeout=.1)
            except queue.Empty:
                if finished.is_set() and files.empty():break
        if failures:raise failures[0]
    finally:
        cancel.set()
        for thread in threads:thread.join()
