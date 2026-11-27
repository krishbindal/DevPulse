import base64
import io
import json
import unittest
from devpulse.static_python import inspect_source,review_sample
from devpulse.inventory import summarize_tree
from devpulse.scanner import scan

SHA='d'*40
def blob(source):
    raw=source.encode()
    return {'sha':SHA,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}

def inventory(count=1,truncated=False):
    return summarize_tree({'sha':'tree','truncated':truncated,'tree':[
        {'path':f'f{i}.py','type':'blob','mode':'100644','sha':SHA,'size':50} for i in range(count)]})

class StaticTests(unittest.TestCase):
    def test_patterns_and_lines(self):
        source='eval(user_input)\nsubprocess.run(command,shell=True)\npickle.loads(data)\ntry:\n    pass\nexcept:\n    pass\n'
        self.assertEqual([(m['rule'],m['line']) for m in inspect_source(source)],[('PY001',1),('PY002',2),('PY003',3),('PY004',6)])
    def test_comments_and_safe_forms(self):
        self.assertEqual(inspect_source('# eval(x)\ntext="pickle.loads(x)"\nsubprocess.run(["ls"],shell=False)\ntry:\n    pass\nexcept ValueError:\n    pass'),[])
    def test_source_never_executed(self):
        result=inspect_source('raise RuntimeError("not executed")\nexec(source)')
        self.assertEqual(result[0]['rule'],'PY001')
    def test_sample_bounds(self):
        inv=inventory(7)
        self.assertEqual(inv['python_sources']['observed_count'],7)
        self.assertEqual(len(inv['python_sources']['sample']),5)
        r=review_sample(inv,lambda sha:blob('eval(x)'))
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['analyzed_files'],5)
        self.assertEqual(r['observed_findings'],5)
        self.assertEqual(r['findings'][0]['blob_sha'],SHA)
    def test_failed_source_not_clean(self):
        r=review_sample(inventory(),lambda sha:blob('def :'))
        self.assertEqual(r['status'],'unavailable')
        self.assertEqual(r['analyzed_files'],0)
        self.assertEqual(len(r['failed_files']),1)
    def test_no_files_and_truncated(self):
        self.assertEqual(review_sample(inventory(0),None)['status'],'not_applicable')
        self.assertEqual(review_sample(inventory(0,True),None)['status'],'partial')
    def test_finding_cap(self):
        r=review_sample(inventory(),lambda sha:blob('eval(x)\n'*101))
        self.assertEqual(r['observed_findings'],101)
        self.assertEqual(len(r['findings']),100)
        self.assertTrue(r['findings_truncated'])
        self.assertEqual(r['status'],'partial')
    def test_scan_pinned_and_opt_in(self):
        seen=[]
        def fake(req,timeout):
            seen.append(req.full_url)
            if '/git/trees/' in req.full_url:
                payload={'sha':'tree','truncated':False,'tree':[{'path':'a.py','type':'blob','mode':'100644','sha':SHA,'size':10}]}
            elif '/git/blobs/' in req.full_url:
                self.assertTrue(req.full_url.endswith(SHA))
                payload=blob('eval(x)')
            else:
                payload={'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(payload).encode())
        self.assertEqual(scan('a/b',fake,include_inventory=True)['static_python']['status'],'not_analyzed')
        self.assertFalse(any('/git/blobs/' in url for url in seen))
        r=scan('a/b',fake,include_inventory=True,include_static=True)
        self.assertEqual(r['static_python']['findings'][0]['path'],'a.py')
        self.assertIsNone(r['security_findings'])
    def test_oversized_and_symlink_excluded(self):
        inv=summarize_tree({'sha':'tree','truncated':False,'tree':[
            {'path':'big.py','type':'blob','mode':'100644','sha':SHA,'size':64001},
            {'path':'link.py','type':'blob','mode':'120000','sha':SHA,'size':10}]})
        self.assertEqual(inv['python_sources']['observed_count'],1)
        self.assertEqual(inv['python_sources']['eligible_count'],0)
        self.assertEqual(review_sample(inv,None)['status'],'partial')
