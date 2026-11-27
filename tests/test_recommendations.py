import io
import json
import unittest
from devpulse.recommendations import recommend
from devpulse.scanner import scan

def advisory_entry(i=1):
    return {'ecosystem':'npm','name':f'pkg{i}','version':'1.0.0','advisory_ids':['GHSA-test'],
            'evidence':['lockfile']}

class RecommendationTests(unittest.TestCase):
    def test_advisory_grounding(self):
        r=recommend({'advisories':{'status':'ok','entries':[advisory_entry(),dict(advisory_entry(2),advisory_ids=[])]}})
        self.assertEqual(len(r['entries']),1)
        self.assertEqual(r['entries'][0]['evidence']['name'],'pkg1')
        self.assertEqual(r['entries'][0]['evidence']['advisory_ids'],['GHSA-test'])
        self.assertEqual(r['entries'][0]['evidence']['version_evidence'],['lockfile'])
    def test_ci_failure_not_success(self):
        ci={'status':'ok','latest_run':{'status':'completed','conclusion':'failure','id':12,'head_sha':'abc'}}
        self.assertEqual(recommend({'ci':ci})['entries'][0]['evidence']['run_id'],12)
        ci['latest_run']['conclusion']='success'
        self.assertEqual(recommend({'ci':ci})['entries'],[])
    def test_unknown_does_not_become_missing(self):
        r=recommend({'practices':{'status':'partial','checks':[{'id':'tests','state':'unknown'},{'id':'readme','state':'not_observed'}]}})
        self.assertEqual([e['evidence'].get('check_id') for e in r['entries'] if e['kind']=='practice'],['readme'])
        self.assertTrue(any(e['kind']=='coverage' for e in r['entries']))
    def test_static_provenance(self):
        r=recommend({'static_python':{'status':'partial','findings':[{'rule':'PY002','path':'a.py','line':5,'blob_sha':'abc'}]}})
        self.assertEqual(r['entries'][0]['evidence'],{'section':'static_python','rule':'PY002','path':'a.py','line':5,'blob_sha':'abc'})
    def test_unavailable_and_opt_in(self):
        r=recommend({'inventory':{'status':'unavailable'},'advisories':{'status':'not_analyzed'},'static_python':{'status':'not_analyzed'}})
        self.assertEqual(len(r['entries']),3)
        self.assertTrue(all(e['kind']=='coverage' for e in r['entries']))
    def test_cap_and_priority(self):
        data={'advisories':{'status':'partial','entries':[advisory_entry(i) for i in range(41)]},'inventory':{'status':'unavailable'}}
        r=recommend(data)
        self.assertEqual(r['observed_recommendations'],43)
        self.assertEqual(len(r['entries']),40)
        self.assertTrue(r['entries_truncated'])
        self.assertTrue(all(e['priority']=='review_first' for e in r['entries']))
    def test_empty_is_not_health_score(self):
        r=recommend({})
        self.assertEqual(r['entries'],[])
        self.assertNotIn('score',r)
        self.assertIn('No AI service',r['scope'])
    def test_scanner_integration(self):
        result=scan('a/b',lambda *a,**kw:io.BytesIO(json.dumps({'full_name':'a/b'}).encode()))
        self.assertEqual(result['recommendations']['method'],'deterministic-evidence-rules-v1')
        self.assertIsNone(result['code_quality'])
