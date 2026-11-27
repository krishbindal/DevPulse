import unittest
from devpulse.scan_gate import ScanGate,cacheable

class GateTests(unittest.TestCase):
    def setUp(self):
        self.now=0
        self.gate=ScanGate(clock=lambda:self.now,ttl=10,max_entries=2,max_bytes=5,max_active=2,max_starts=3,window=60)
    def test_hit_and_expiry(self):
        self.assertEqual(self.gate.begin('a'),('start',None))
        self.gate.finish('a',b'yes')
        self.assertEqual(self.gate.begin('a'),('hit',b'yes'))
        self.now=10
        self.assertEqual(self.gate.begin('a'),('start',None))
    def test_duplicate_and_concurrency(self):
        self.gate.begin('a')
        self.assertEqual(self.gate.begin('a')[0],'busy')
        self.assertEqual(self.gate.begin('b')[0],'start')
        self.assertEqual(self.gate.begin('c')[0],'busy')
        self.gate.finish('a')
        self.assertEqual(self.gate.begin('c')[0],'start')
    def test_rate_window(self):
        for key in 'abc':
            self.gate.begin(key)
            self.gate.finish(key)
        self.assertEqual(self.gate.begin('d')[0],'limited')
        self.now=60
        self.assertEqual(self.gate.begin('d')[0],'start')
    def test_lru(self):
        for key in 'ab':
            self.gate.begin(key)
            self.gate.finish(key,b'yes')
        self.gate.begin('a')
        self.gate.begin('c')
        self.gate.finish('c',b'yes')
        self.assertEqual(list(self.gate.cache),['a','c'])
    def test_oversize_and_failures_not_cached(self):
        self.gate.begin('a')
        self.gate.finish('a',b'123456')
        self.assertEqual(self.gate.begin('a')[0],'start')
        self.gate.finish('a')
        self.assertEqual(self.gate.begin('a')[0],'start')
    def test_partial_report_not_cacheable(self):
        r={'scanned_at':'time'}
        for key in ('languages','inventory','ci','npm_dependencies','python_dependencies','npm_lockfile','advisories','static_python','practices'):
            r[key]={'status':'ok'}
        self.assertTrue(cacheable(r))
        r['advisories']['status']='partial'
        self.assertFalse(cacheable(r))
        self.assertFalse(cacheable({}))
