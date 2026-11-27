import base64
import io
import json
import unittest
from devpulse.dependencies import summarize_manifest
from devpulse.scanner import scan

SHA='a'*40
def blob(data):
    raw=json.dumps(data).encode()
    return {'sha':SHA,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}

class DependencyTests(unittest.TestCase):
    def test_declarations_and_redaction(self):
        result=summarize_manifest(blob({'dependencies':{'react':'^19.0.0','private':'https://example.com/token'},'devDependencies':{'vite':'~6.0.0'}}),SHA)
        self.assertEqual(result['total_declarations'],3)
        self.assertEqual(result['declared_counts']['dependencies'],2)
        by_name={x['name']:x for x in result['entries']}
        self.assertEqual(by_name['react']['declared_spec'],'^19.0.0')
        self.assertIsNone(by_name['private']['declared_spec'])
    def test_empty(self):
        self.assertEqual(summarize_manifest(blob({}),SHA)['total_declarations'],0)
    def test_cap(self):
        r=summarize_manifest(blob({'dependencies':{f'pkg{i}':'1.0.0' for i in range(201)}}),SHA)
        self.assertEqual(r['total_declarations'],201)
        self.assertEqual(len(r['entries']),200)
        self.assertTrue(r['entries_truncated'])
    def test_invalid(self):
        for value in ({},blob({'dependencies':[]}),blob({'dependencies':{'a':1}}),dict(blob({}),size=999999),dict(blob({}),sha='wrong'),dict(blob({}),content='!')):
            with self.subTest(value=value),self.assertRaises(ValueError):
                summarize_manifest(value,SHA)
    def test_scan_pinned_blob(self):
        payload=blob({'dependencies':{'react':'^19.0.0'}})
        def fake(req,timeout):
            if '/git/trees/' in req.full_url:
                data={'sha':'tree','truncated':False,'tree':[{'path':'package.json','type':'blob','mode':'100644','sha':SHA,'size':payload['size']}]}
            elif '/git/blobs/' in req.full_url:
                self.assertTrue(req.full_url.endswith(SHA))
                data=payload
            else:
                data={'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(data).encode())
        r=scan('a/b',fake,include_inventory=True,include_dependencies=True)
        self.assertEqual(r['npm_dependencies']['entries'][0]['name'],'react')
        self.assertIsNone(r['security_findings'])
    def test_partial_vs_absent(self):
        def fake(truncated):
            def get(req,timeout):
                data={'sha':'tree','truncated':truncated,'tree':[]} if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'main'}
                return io.BytesIO(json.dumps(data).encode())
            return get
        self.assertEqual(scan('a/b',fake(False),include_inventory=True,include_dependencies=True)['npm_dependencies']['status'],'not_found')
        self.assertEqual(scan('a/b',fake(True),include_inventory=True,include_dependencies=True)['npm_dependencies']['status'],'unavailable')
