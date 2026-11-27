import io
import json
import unittest
from urllib.error import HTTPError
from http.client import IncompleteRead
from devpulse.scanner import parse_repository, scan, ScanError

class ScannerTests(unittest.TestCase):
    def test_valid_input(self):
        self.assertEqual(parse_repository('octocat/Hello-World'), ('octocat','Hello-World'))
        self.assertEqual(parse_repository('https://github.com/octocat/Hello-World.git'), ('octocat','Hello-World'))
    def test_invalid_inputs(self):
        for value in ('', 'https://evil.test/a/b','https://github.com@evil.test/a/b','https://github.com/a/b?x=1','a/..','a/.git','a/b/c','a/b%2f','http://github.com/a/b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_repository(value)
    def test_metadata_and_unknowns(self):
        def fake(req,timeout):
            self.assertEqual(req.full_url,'https://api.github.com/repos/a/b')
            self.assertEqual(timeout,12)
            return io.BytesIO(json.dumps({'full_name':'a/b','stargazers_count':0,'forks_count':3}).encode())
        result=scan('a/b',fake)
        self.assertEqual(result['stargazers_count'],0)
        self.assertEqual(result['forks_count'],3)
        self.assertIsNone(result['security_findings'])
        self.assertIsNone(result['test_coverage'])
        self.assertIsNone(result['open_issues_count'])
    def test_rate_limit(self):
        def fake(req,timeout):
            raise HTTPError(req.full_url,429,'rate limit',{},None)
        with self.assertRaisesRegex(ScanError,'rate limited'):
            scan('a/b',fake)
    def test_not_found(self):
        def fake(req,timeout):
            raise HTTPError(req.full_url,404,'not found',{},None)
        with self.assertRaisesRegex(ScanError,'not found'):
            scan('a/b',fake)
    def test_invalid_json(self):
        with self.assertRaises(ScanError):
            scan('a/b',lambda *a,**k:io.BytesIO(b'not json'))
    def test_unexpected_payload(self):
        with self.assertRaises(ScanError):
            scan('a/b',lambda *a,**k:io.BytesIO(b'[]'))
    def test_response_limit(self):
        with self.assertRaisesRegex(ScanError,'size limit'):
            scan('a/b',lambda *a,**k:io.BytesIO(b'x'*2_000_001))

    def test_interrupted_response(self):
        def fake(req,timeout):
            raise IncompleteRead(b'{}')
        with self.assertRaisesRegex(ScanError,'unavailable'):
            scan('a/b',fake)
    def test_deep_json_response(self):
        with self.assertRaisesRegex(ScanError,'invalid data'):
            scan('a/b',lambda *a,**kw:io.BytesIO(b'['*2000+b']'*2000))
