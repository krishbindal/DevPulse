import base64
import io
import json
import unittest
from devpulse.python_requirements import summarize_requirements
from devpulse.scanner import scan

SHA='b'*40
def blob(text):
    raw=text.encode()
    return {'sha':SHA,'encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}

class PythonRequirementsTests(unittest.TestCase):
    def test_pins_and_bare_names(self):
        result=summarize_requirements(blob('Requests==2.32.3\nMy_Pkg # comment\n# skip\n'),SHA)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['counts'],{'exact_pins':1,'bare_names':1,'unsupported_lines':0})
        self.assertEqual(result['entries'],[{'name':'requests','declared_version':'2.32.3'},{'name':'my-pkg','declared_version':None}])
    def test_unsupported_redacted(self):
        result=summarize_requirements(blob('-r other.txt\nfoo>=1\nbar[extra]==2\nbaz==1.*\nfoo @ https://example.com/secret\nfoo==1; python_version>\"3\"\n'),SHA)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['counts']['unsupported_lines'],6)
        self.assertEqual(result['entries'],[])
        self.assertNotIn('secret',json.dumps(result))
    def test_cap(self):
        result=summarize_requirements(blob('\n'.join(f'pkg{i}==1.0' for i in range(201))),SHA)
        self.assertEqual(result['counts']['exact_pins'],201)
        self.assertEqual(len(result['entries']),200)
        self.assertEqual(result['status'],'partial')
    def test_empty(self):
        self.assertEqual(summarize_requirements(blob('# none\n'),SHA)['entries'],[])
    def test_invalid_blob(self):
        with self.assertRaises(ValueError):
            summarize_requirements(dict(blob('a==1'),sha='wrong'),SHA)
    def test_scan_pinned_blob(self):
        payload=blob('requests==2.32.3')
        def fake(req,timeout):
            if '/git/trees/' in req.full_url:
                data={'sha':'tree','truncated':False,'tree':[{'path':'requirements.txt','type':'blob','mode':'100644','sha':SHA,'size':payload['size']}]}
            elif '/git/blobs/' in req.full_url:
                self.assertTrue(req.full_url.endswith(SHA))
                data=payload
            else:
                data={'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(data).encode())
        r=scan('a/b',fake,include_inventory=True,include_dependencies=True)
        self.assertEqual(r['python_dependencies']['entries'][0]['name'],'requests')
        self.assertEqual(r['npm_dependencies']['status'],'not_found')
        self.assertIsNone(r['security_findings'])
    def test_partial_tree_absence_unknown(self):
        def fake(req,timeout):
            data={'sha':'tree','truncated':True,'tree':[]} if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(data).encode())
        self.assertEqual(scan('a/b',fake,include_inventory=True,include_dependencies=True)['python_dependencies']['status'],'unavailable')
