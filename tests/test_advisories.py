import io
import json
import unittest
from urllib.error import URLError
from http.client import IncompleteRead
from devpulse.advisories import lookup_advisories, ENDPOINT
from devpulse.scanner import scan

def report():
    return {'python_dependencies':{'status':'ok','entries':[{'name':'django','declared_version':'3.0.0'},{'name':'unknown','declared_version':None}]},
            'npm_dependencies':{'status':'ok','entries':[{'name':'lodash','declared_spec':'4.17.20'},{'name':'react','declared_spec':'^19.0.0'}]}}
def fake(data):
    return lambda *a,**kw:io.BytesIO(json.dumps(data).encode())

class AdvisoryTests(unittest.TestCase):
    def test_batch_and_result(self):
        def fetch(req,timeout):
            self.assertEqual(req.full_url,ENDPOINT)
            self.assertEqual(req.method,'POST')
            self.assertEqual(json.loads(req.data),{'queries':[{'package':{'ecosystem':'PyPI','name':'django'},'version':'3.0.0'},{'package':{'ecosystem':'npm','name':'lodash'},'version':'4.17.20'}]})
            return io.BytesIO(b'{"results":[{"vulns":[{"id":"GHSA-test"}]},{}]}')
        r=lookup_advisories(report(),fetch)
        self.assertEqual(r['status'],'partial')
        self.assertTrue(r['coverage_limited'])
        self.assertEqual(r['coverage']['PyPI']['ineligible_observed_declarations'],1)
        self.assertEqual(r['coverage']['npm']['ineligible_observed_declarations'],1)
        self.assertEqual(r['queried_versions'],2)
        self.assertEqual(r['entries'][0]['advisory_ids'],['GHSA-test'])
        self.assertEqual(r['entries'][1]['advisory_ids'],[])
    def test_partial_pagination(self):
        r=lookup_advisories(report(),fake({'results':[{'next_page_token':'more'},{}]}))
        self.assertEqual(r['status'],'partial')
        self.assertTrue(r['entries'][0]['partial'])
    def test_invalid_shape(self):
        for data in ({},{'results':[{}]},{'results':[{'vulns':[{}]},{}]},{'results':[{'error':'bad'},{}]},{'results':[{'error':'bad','vulns':[]},{}]}):
            with self.subTest(data=data):
                self.assertEqual(lookup_advisories(report(),fake(data))['status'],'unavailable')
    def test_network_failure(self):
        def fetch(*a,**kw):
            raise URLError('offline')
        r=lookup_advisories(report(),fetch)
        self.assertEqual(r['status'],'unavailable')
        self.assertEqual(r['queried_versions'],0)
    def test_no_eligible(self):
        def fetch(*a,**kw):
            self.fail('unexpected network request')
        self.assertEqual(lookup_advisories({},fetch)['status'],'unavailable')
        self.assertEqual(lookup_advisories({'python_dependencies':{'status':'not_found'},'npm_dependencies':{'status':'not_found'}},fetch)['status'],'not_applicable')
        self.assertEqual(scan('a/b',fake({'full_name':'a/b'}),advisory_fetch=fetch)['advisories']['status'],'not_analyzed')
    def test_cap_and_dedup(self):
        data={'python_dependencies':{'entries':[{'name':f'pkg{i}','declared_version':'1.0'} for i in range(51)]+[{'name':'pkg0','declared_version':'1.0'}]}}
        r=lookup_advisories(data,fake({'results':[{}]*50}))
        self.assertEqual(r['eligible_unique_versions'],51)
        self.assertEqual(r['queried_versions'],50)
        self.assertEqual(r['status'],'partial')
    def test_large_response(self):
        r=lookup_advisories(report(),lambda *a,**kw:io.BytesIO(b'x'*1_000_001))
        self.assertEqual(r['status'],'unavailable')

    def test_complete_supported_manifest_scope(self):
        data={'python_dependencies':{'status':'not_found'},'npm_dependencies':{'status':'ok','entries':[{'name':'lodash','declared_spec':'4.17.20'}]}}
        r=lookup_advisories(data,fake({'results':[{}]}))
        self.assertEqual(r['status'],'ok')
        self.assertFalse(r['coverage_limited'])
        self.assertEqual(r['queried_versions'],1)
    def test_unavailable_manifest_limits_successful_lookup(self):
        data={'python_dependencies':{'status':'unavailable'},'npm_dependencies':{'status':'ok','entries':[{'name':'lodash','declared_spec':'4.17.20'}]}}
        r=lookup_advisories(data,fake({'results':[{}]}))
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['coverage']['PyPI']['manifest_status'],'unavailable')
    def test_no_eligible_but_unsupported(self):
        data={'python_dependencies':{'status':'partial','entries':[],'counts':{'unsupported_lines':2}},'npm_dependencies':{'status':'not_found'}}
        r=lookup_advisories(data,lambda *a,**k:self.fail('unexpected network request'))
        self.assertEqual(r['status'],'partial')
        self.assertEqual(r['queried_versions'],0)
        self.assertEqual(r['coverage']['PyPI']['unsupported_lines'],2)
    def test_truncation_limits_successful_lookup(self):
        data={'python_dependencies':{'status':'not_found'},'npm_dependencies':{'status':'ok','entries_truncated':True,'entries':[{'name':'lodash','declared_spec':'4.17.20'}]}}
        r=lookup_advisories(data,fake({'results':[{}]}))
        self.assertEqual(r['status'],'partial')
        self.assertTrue(r['coverage']['npm']['entries_truncated'])
    def test_interrupted_response_unavailable(self):
        def fetch(*a,**kw):
            raise IncompleteRead(b'{}')
        self.assertEqual(lookup_advisories(report(),fetch)['status'],'unavailable')
