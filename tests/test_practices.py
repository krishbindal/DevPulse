import io
import json
import unittest
from devpulse.inventory import summarize_tree
from devpulse.practices import assess_practices,document_kind
from devpulse.scanner import scan

def inventory(paths,truncated=False):
    return summarize_tree({'sha':'tree','truncated':truncated,'tree':[
        {'path':path,'type':'blob','mode':'100644'} for path in paths]})

class PracticeTests(unittest.TestCase):
    def test_root_and_supported_doc_locations(self):
        for path,key in [('README.md','readme'),('docs/security.md','security'),
                         ('.github/CONTRIBUTING.md','contributing'),('LICENSE','license')]:
            self.assertEqual(document_kind(path),key)
        for path in ('vendor/README.md','README_backup.md','src/security.py','LICENSE.json'):
            self.assertIsNone(document_kind(path))
    def test_observed_not_observed_and_run(self):
        inv=inventory(['README.md','LICENSE','tests/test_api.py','.github/workflows/test.yml','package.json'])
        r=assess_practices(inv,{'status':'ok','latest_run':{'status':'completed','conclusion':'failure','head_sha':'abc'}})
        by_id={c['id']:c for c in r['checks']}
        self.assertEqual(r['counts'],{'observed':6,'not_observed':2,'unknown':0})
        self.assertEqual(by_id['security']['state'],'not_observed')
        self.assertEqual(by_id['latest_run']['run']['conclusion'],'failure')
        self.assertNotIn('score',r)
    def test_partial_tree_does_not_imply_absence(self):
        r=assess_practices(inventory(['README.md'],True),{'status':'unavailable'})
        self.assertEqual(r['counts'],{'observed':1,'not_observed':0,'unknown':7})
        self.assertEqual(r['status'],'partial')
    def test_no_evidence_all_unknown(self):
        r=assess_practices({'status':'unavailable'},{'status':'unavailable'})
        self.assertEqual(r['counts']['unknown'],8)
    def test_complete_empty_and_no_runs(self):
        r=assess_practices(inventory([]),{'status':'ok','latest_run':None})
        self.assertEqual(r['counts']['not_observed'],8)
        self.assertEqual(r['status'],'ok')
    def test_examples_bounded(self):
        r=assess_practices(inventory([f'tests/test_{i}.py' for i in range(60)]),{'status':'ok','latest_run':None})
        c=next(c for c in r['checks'] if c['id']=='tests')
        self.assertEqual(c['observed_count'],60)
        self.assertEqual(len(c['examples']),5)
    def test_scanner_integration(self):
        def fake(req,timeout):
            if '/git/trees/' in req.full_url:
                payload={'sha':'tree','truncated':False,'tree':[{'path':'README.md','type':'blob','mode':'100644'}]}
            else:
                payload={'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(payload).encode())
        self.assertEqual(scan('a/b',fake)['practices']['status'],'not_analyzed')
        r=scan('a/b',fake,include_inventory=True)
        self.assertEqual(r['practices']['checks'][0]['state'],'observed')
        self.assertIsNone(r['code_quality'])
