import base64
import io
import json
import unittest
from devpulse.lockfile import summarize_lockfile
from devpulse.scanner import scan

SHA='c'*40
def blob(data):
    raw=json.dumps(data).encode()
    return {'sha':SHA,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}
def lock(packages,version=3):
    return blob({'lockfileVersion':version,'packages':packages})

class LockfileTests(unittest.TestCase):
    def test_nested_scoped_and_duplicate_versions(self):
        result=summarize_lockfile(lock({'':{'version':'1.0.0'},'node_modules/a':{'version':'2.0.0'},
            'node_modules/b/node_modules/a':{'version':'2.0.0'},'node_modules/@scope/pkg':{'version':'1.2.3'}},2),SHA)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['observed_package_records'],3)
        self.assertEqual(result['unique_name_versions'],2)
        self.assertEqual(result['entries'][1],{'name':'a','locked_version':'2.0.0','occurrences':2})
    def test_skipped_and_redacted(self):
        result=summarize_lockfile(lock({'node_modules/link':{'link':True,'resolved':'private'},
            'workspace/a':{'version':'1.2.3'},'node_modules/foo':{'version':'git+secret'},
            'node_modules/alias':{'name':'actual','version':'1.0.0','resolved':'https://secret.example'}}),SHA)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['excluded_records'],3)
        self.assertEqual(result['entries'][0]['name'],'actual')
        self.assertNotIn('secret',json.dumps(result))
    def test_unsupported_format(self):
        for data in (lock({},1),lock({},True),blob({'lockfileVersion':3,'packages':[]}),dict(lock({}),sha='wrong')):
            with self.subTest(data=data),self.assertRaises(ValueError):
                summarize_lockfile(data,SHA)
    def test_cap(self):
        result=summarize_lockfile(lock({f'node_modules/pkg{i}':{'version':'1.2.3'} for i in range(301)}),SHA)
        self.assertEqual(result['unique_name_versions'],301)
        self.assertEqual(len(result['entries']),300)
        self.assertTrue(result['entries_truncated'])
        self.assertEqual(result['status'],'partial')
    def test_empty(self):
        self.assertEqual(summarize_lockfile(lock({'':{}}),SHA)['recognized_records'],0)
    def test_pinned_blob(self):
        payload=lock({'node_modules/a':{'version':'1.2.3'}})
        def fake(req,timeout):
            if '/git/trees/' in req.full_url:
                data={'sha':'tree','truncated':False,'tree':[{'path':'package-lock.json','type':'blob','mode':'100644','sha':SHA,'size':payload['size']}]}
            elif '/git/blobs/' in req.full_url:
                self.assertTrue(req.full_url.endswith(SHA))
                data=payload
            else:
                data={'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(data).encode())
        result=scan('a/b',fake,include_inventory=True,include_dependencies=True)
        self.assertEqual(result['npm_lockfile']['entries'][0]['locked_version'],'1.2.3')
        self.assertEqual(result['advisories']['status'],'not_analyzed')
    def test_partial_tree_and_missing(self):
        def fetch(truncated):
            def fake(req,timeout):
                data={'sha':'tree','truncated':truncated,'tree':[]} if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'main'}
                return io.BytesIO(json.dumps(data).encode())
            return fake
        for partial,expected in ((True,'unavailable'),(False,'not_found')):
            self.assertEqual(scan('a/b',fetch(partial),include_inventory=True,include_dependencies=True)['npm_lockfile']['status'],expected)
    def test_oversized_lockfile_no_fetch(self):
        def fake(req,timeout):
            if '/git/blobs/' in req.full_url:
                self.fail('oversized blob must not be fetched')
            data={'sha':'tree','truncated':False,'tree':[{'path':'package-lock.json','type':'blob','mode':'100644','sha':SHA,'size':1000001}]} if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(data).encode())
        self.assertEqual(scan('a/b',fake,include_inventory=True,include_dependencies=True)['npm_lockfile']['status'],'unavailable')
