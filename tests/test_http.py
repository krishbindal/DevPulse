import http.client
import json
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from devpulse.server import Handler
from devpulse.scanner import ScanError

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
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
            scanner.assert_called_once_with('a/b',include_languages=True,include_inventory=True,include_ci=True)
    def test_invalid(self):
        self.assertEqual(self.get('/api/scan?repo=invalid')[0],400)
        self.assertEqual(self.get('/api/scan?repo='+'x'*2050)[0],400)
        self.assertEqual(self.get('/missing')[0],404)
    def test_upstream_error(self):
        with patch('devpulse.server.scan',side_effect=ScanError('Unavailable')):
            status,_,body=self.get('/api/scan?repo=a%2Fb')
            self.assertEqual(status,502)
            self.assertEqual(json.loads(body),{'error':'Unavailable'})
