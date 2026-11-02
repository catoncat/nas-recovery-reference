"""Bounded, thread-safe five-minute stage metrics; never captures arguments or data."""
from collections import Counter, deque
from contextlib import contextmanager
import math
import threading
import time

class StageMetrics:
    WINDOW_SECONDS = 300
    BUCKET_SECONDS = 5
    RELATIVE_BIN_WIDTH = .02
    BASE_SECONDS = 1e-6
    LOG_FACTOR = math.log1p(RELATIVE_BIN_WIDTH)

    def __init__(self, enabled=True, clock=time.monotonic):
        self.enabled=enabled;self.clock=clock;self.lock=threading.Lock();self.stages={}

    def observe(self,name,seconds):
        if not self.enabled:return
        seconds=max(0.,float(seconds));now=self.clock();slot=int(now/self.BUCKET_SECONDS)
        index=0 if seconds<=self.BASE_SECONDS else int(math.ceil(math.log(seconds/self.BASE_SECONDS)/self.LOG_FACTOR))
        with self.lock:
            s=self.stages.setdefault(name,{'count':0,'seconds':0.,'buckets':deque()})
            s['count']+=1;s['seconds']+=seconds;b=s['buckets']
            while b and (b[0][0]+1)*self.BUCKET_SECONDS<=now-self.WINDOW_SECONDS:b.popleft()
            if not b or b[-1][0]!=slot:b.append([slot,0,0.,Counter()])
            b[-1][1]+=1;b[-1][2]+=seconds;b[-1][3][index]+=1

    @contextmanager
    def time(self,name):
        if not self.enabled:
            yield;return
        start=time.perf_counter()
        try:yield
        finally:self.observe(name,time.perf_counter()-start)

    def call(self,name,function,*args,**kwargs):
        with self.time(name):return function(*args,**kwargs)

    def snapshot(self):
        now=self.clock();result={}
        with self.lock:
            for name,s in self.stages.items():
                b=s['buckets']
                while b and (b[0][0]+1)*self.BUCKET_SECONDS<=now-self.WINDOW_SECONDS:b.popleft()
                count=sum(x[1] for x in b);total=sum(x[2] for x in b);hist=Counter()
                for x in b:hist.update(x[3])
                threshold=max(1,math.ceil(count*.95));seen=0;p95=None
                for index,n in sorted(hist.items()):
                    seen+=n
                    if seen>=threshold:p95=self.BASE_SECONDS*math.exp(index*self.LOG_FACTOR)*1000;break
                result[name]={'count':count,'total_ms':total*1000,'mean_ms':total*1000/count if count else None,
                              'p95_ms':p95,'lifetime_count':s['count'],'lifetime_total_ms':s['seconds']*1000}
        return {'enabled':self.enabled,'window_seconds':self.WINDOW_SECONDS,'bucket_seconds':self.BUCKET_SECONDS,
                'p95_method':'log-histogram upper bin edge','p95_relative_bin_width':self.RELATIVE_BIN_WIDTH,'p95_absolute_floor_us':1,
                'parallel_stage_totals_are_not_wall_time':True,'stages':result}
