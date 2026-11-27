import io
import json
import unittest
from urllib.error import HTTPError
from devpulse.scanner import scan

class LanguageTests(unittest.TestCase):
    def fetcher(self, languages):
        def fetch(req, timeout):
            if req.full_url.endswith('/languages'):
                if isinstance(languages, Exception):
                    raise languages
                data = languages
            else:
                data = {'full_name': 'a/b', 'stargazers_count': 0}
            return io.BytesIO(json.dumps(data).encode())
        return fetch

    def test_breakdown(self):
        result = scan('a/b', self.fetcher({'Python': 300, 'HTML': 100}), include_languages=True)
        lang = result['languages']
        self.assertEqual(lang['status'], 'ok')
        self.assertEqual(lang['source'], 'https://api.github.com/repos/a/b/languages')
        self.assertEqual(lang['total_bytes'], 400)
        self.assertEqual(lang['entries'], [{'name':'Python','bytes':300,'percent':75.0},
                                           {'name':'HTML','bytes':100,'percent':25.0}])

    def test_empty(self):
        lang = scan('a/b', self.fetcher({}), include_languages=True)['languages']
        self.assertEqual((lang['status'],lang['total_bytes'],lang['entries']), ('ok',0,[]))

    def test_zero(self):
        lang = scan('a/b', self.fetcher({'Python':0}), include_languages=True)['languages']
        self.assertEqual(lang['entries'][0]['percent'],0)

    def test_bad_data(self):
        for value in ([], {'Python':-1}, {'Python':True}, {'Python':'5'}):
            with self.subTest(value=value):
                result = scan('a/b', self.fetcher(value), include_languages=True)
                self.assertEqual(result['languages']['status'],'unavailable')
                self.assertIsNone(result['languages']['entries'])
                self.assertEqual(result['full_name'],'a/b')

    def test_rate_limit_preserves_metadata(self):
        err = HTTPError('https://api.github.com/repos/a/b/languages',429,'rate limit',{},None)
        result = scan('a/b', self.fetcher(err), include_languages=True)
        self.assertEqual(result['stargazers_count'],0)
        self.assertEqual(result['languages']['status'],'unavailable')
        self.assertIn('rate limited',result['languages']['error'])

    def test_opt_out(self):
        result = scan('a/b', self.fetcher({}))
        self.assertEqual(result['languages']['status'],'not_analyzed')
