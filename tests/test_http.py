import http.client
import json
import threading
import unittest
from unittest.mock import patch
from devpulse.server import Handler, DevPulseServer
from devpulse.scan_gate import ScanGate
from devpulse.scanner import ScanError

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=DevPulseServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
    def setUp(self):
        self.server.scan_gate=ScanGate()
    def get(self,path):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        try:
            conn.request('GET',path)
            res=conn.getresponse()
            return res.status,dict(res.getheaders()),res.read()
        finally:
            conn.close()
    def test_health_headers(self):
        status,headers,body=self.get('/health')
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body),{'status':'ok'})
        self.assertEqual(headers['Cache-Control'],'no-store')
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
    def test_dashboard(self):
        status,headers,body=self.get('/')
        self.assertEqual(status,200)
        self.assertIn(b'DevPulse',body)
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
    def test_scan_options(self):
        with patch('devpulse.server.scan',return_value={'full_name':'a/b'}) as scanner:
            status,_,body=self.get('/api/scan?repo=a%2Fb')
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body),{'full_name':'a/b'})
            scanner.assert_called_once_with('a/b',include_languages=True,include_inventory=True,include_ci=True,include_dependencies=True)
    def test_advisory_opt_in(self):
        with patch('devpulse.server.scan',return_value={'full_name':'a/b'}) as scanner:
            self.assertEqual(self.get('/api/scan?repo=a%2Fb&advisories=1')[0],200)
            scanner.assert_called_once_with('a/b',include_languages=True,include_inventory=True,include_ci=True,include_dependencies=True,include_advisories=True)
    def test_cache_and_advisory_separation(self):
        report={'full_name':'a/b','scanned_at':'original timestamp'}
        for key in ('languages','inventory','ci','npm_dependencies','python_dependencies','npm_lockfile','advisories','static_python','practices'):
            report[key]={'status':'ok'}
        with patch('devpulse.server.scan',return_value=report) as scanner:
            self.assertEqual(self.get('/api/scan?repo=A%2FB')[1]['X-DevPulse-Cache'],'MISS')
            status,headers,body=self.get('/api/scan?repo=a%2Fb')
            self.assertEqual(status,200)
            self.assertEqual(headers['X-DevPulse-Cache'],'HIT')
            self.assertEqual(json.loads(body)['scanned_at'],'original timestamp')
            self.assertEqual(self.get('/api/scan?repo=a%2Fb&advisories=1')[1]['X-DevPulse-Cache'],'MISS')
            self.assertEqual(scanner.call_count,2)
    def test_busy_returns_429(self):
        self.server.scan_gate.begin(('a/b',False,False))
        status,headers,_=self.get('/api/scan?repo=a%2Fb')
        self.assertEqual(status,429)
        self.assertEqual(headers['Retry-After'],'5')
    def test_static_opt_in_and_cache_isolation(self):
        report={'full_name':'a/b','scanned_at':'time'}
        for key in ('languages','inventory','ci','npm_dependencies','python_dependencies','npm_lockfile','advisories','static_python','practices'):
            report[key]={'status':'ok'}
        with patch('devpulse.server.scan',return_value=report) as scanner:
            self.assertEqual(self.get('/api/scan?repo=a/b')[1]['X-DevPulse-Cache'],'MISS')
            self.assertEqual(self.get('/api/scan?repo=a/b&static=1')[1]['X-DevPulse-Cache'],'MISS')
            scanner.assert_called_with('a/b',include_languages=True,include_inventory=True,include_ci=True,include_dependencies=True,include_static=True)
            self.assertEqual(self.get('/api/scan?repo=a/b&static=1')[1]['X-DevPulse-Cache'],'HIT')
            self.assertEqual(scanner.call_count,2)
        self.assertEqual(self.get('/api/scan?repo=a/b&static=2')[0],400)
    def test_invalid(self):
        self.assertEqual(self.get('/api/scan?repo=invalid')[0],400)
        self.assertEqual(self.get('/api/scan?repo='+'x'*2050)[0],400)
        self.assertEqual(self.get('/missing')[0],404)
        self.assertEqual(self.get('/api/scan?repo=a/b&repo=c/d')[0],400)
        self.assertEqual(self.get('/api/scan?repo=a/b&advisories=2')[0],400)
    def test_upstream_error(self):
        with patch('devpulse.server.scan',side_effect=ScanError('Unavailable')):
            status,_,body=self.get('/api/scan?repo=a%2Fb')
            self.assertEqual(status,502)
            self.assertEqual(json.loads(body),{'error':'Unavailable'})
        with patch('devpulse.server.scan',return_value={'full_name':'a/b'}):
            self.assertEqual(self.get('/api/scan?repo=a%2Fb')[0],200)
