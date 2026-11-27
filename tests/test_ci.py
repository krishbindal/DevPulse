import io
import json
import unittest
from devpulse.ci import summarize_runs
from devpulse.scanner import scan

def run(status='completed', conclusion='success'):
    return {'id':12,'name':'Tests','status':status,'conclusion':conclusion,
            'head_sha':'abc','event':'push','head_branch':'main'}

class CITests(unittest.TestCase):
    def test_success_is_latest_run_only(self):
        result=summarize_runs({'total_count':3,'workflow_runs':[run()]})
        self.assertEqual(result['latest_run']['conclusion'],'success')
        self.assertEqual(result['reported_run_count'],3)
    def test_pending(self):
        self.assertIsNone(summarize_runs({'total_count':1,'workflow_runs':[run('in_progress',None)]})['latest_run']['conclusion'])
    def test_empty(self):
        self.assertIsNone(summarize_runs({'total_count':0,'workflow_runs':[]})['latest_run'])
    def test_invalid(self):
        for payload in ({},{'total_count':True,'workflow_runs':[]},{'total_count':1,'workflow_runs':[]},{'total_count':0,'workflow_runs':[run()]},{'total_count':1,'workflow_runs':[{}]}):
            with self.subTest(payload=payload),self.assertRaises(ValueError):
                summarize_runs(payload)
    def test_scan(self):
        def fake(req,timeout):
            if '/actions/runs?' in req.full_url:
                self.assertTrue(req.full_url.endswith('branch=feature%2Fdemo&per_page=1'))
                payload={'total_count':1,'workflow_runs':[run()]}
            else:
                payload={'full_name':'a/b','default_branch':'feature/demo'}
            return io.BytesIO(json.dumps(payload).encode())
        result=scan('a/b',fake,include_ci=True)
        self.assertEqual(result['ci']['latest_run']['id'],12)
        self.assertIsNone(result['ci_status'])
        self.assertIsNone(result['test_coverage'])
    def test_failure_preserves_metadata(self):
        def fake(req,timeout):
            return io.BytesIO(json.dumps({} if '/actions/runs?' in req.full_url else {'full_name':'a/b','default_branch':'main'}).encode())
        result=scan('a/b',fake,include_ci=True)
        self.assertEqual(result['ci']['status'],'unavailable')
        self.assertEqual(result['full_name'],'a/b')
    def test_disabled_and_no_branch(self):
        fake=lambda *a,**k:io.BytesIO(b'{"full_name":"a/b"}')
        self.assertEqual(scan('a/b',fake)['ci']['status'],'not_analyzed')
        self.assertEqual(scan('a/b',fake,include_ci=True)['ci']['status'],'unavailable')
