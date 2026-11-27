"""Thread-safe, process-local limits for outbound repository scans."""
from collections import OrderedDict, deque
from threading import Lock
from time import monotonic

class ScanGate:
    def __init__(self, *, ttl=120, max_entries=32, max_bytes=524288,
                 max_active=2, max_starts=8, window=60, clock=monotonic):
        self.ttl, self.max_entries, self.max_bytes = ttl,max_entries,max_bytes
        self.max_active,self.max_starts,self.window = max_active,max_starts,window
        self.clock=clock
        self.lock=Lock()
        self.cache=OrderedDict()
        self.active=set()
        self.starts=deque()

    def begin(self,key):
        """Return a cached byte response or reserve capacity for a new scan."""
        with self.lock:
            now=self.clock()
            for cached_key,(expires,_) in list(self.cache.items()):
                if expires<=now:
                    del self.cache[cached_key]
            if key in self.cache:
                self.cache.move_to_end(key)
                return 'hit',self.cache[key][1]
            while self.starts and self.starts[0]<=now-self.window:
                self.starts.popleft()
            if key in self.active:
                return 'busy',None
            if len(self.active)>=self.max_active:
                return 'busy',None
            if len(self.starts)>=self.max_starts:
                return 'limited',None
            self.starts.append(now)
            self.active.add(key)
            return 'start',None

    def finish(self,key,payload=None):
        with self.lock:
            self.active.discard(key)
            if payload is not None and len(payload)<=self.max_bytes:
                self.cache[key]=(self.clock()+self.ttl,payload)
                self.cache.move_to_end(key)
                while len(self.cache)>self.max_entries:
                    self.cache.popitem(last=False)

def cacheable(report):
    """Do not cache incomplete or failed analyses as fresh successful reports."""
    sections=('languages','inventory','ci','npm_dependencies','python_dependencies','npm_lockfile','advisories','static_python','practices')
    return (isinstance(report.get('scanned_at'),str)
            and all(isinstance(report.get(key),dict)
                    and report[key].get('status') in ('ok','not_found','not_applicable','not_analyzed')
                    for key in sections))
