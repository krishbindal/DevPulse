import tempfile
import unittest
from pathlib import Path
from devpulse.compare import compare, read_report, MAX_REPORT_BYTES

class CompareTests(unittest.TestCase):
    def test_counts_and_provenance(self):
        a={'full_name':'a/b','stargazers_count':0,'scanned_at':'first','source':'fixture'}
        b={'full_name':'c/d','stargazers_count':3,'scanned_at':'second'}
        result=compare(a,b)
        self.assertEqual(result['metrics']['stargazers_count'],{'left':0,'right':3,'right_minus_left':3})
        self.assertEqual(result['left']['scanned_at'],'first')
        self.assertEqual(result['right']['scanned_at'],'second')
    def test_unknown_is_not_zero(self):
        result=compare({'full_name':'a/b','forks_count':True},{'full_name':'c/d','forks_count':0})
        self.assertIsNone(result['metrics']['forks_count']['left'])
        self.assertIsNone(result['metrics']['forks_count']['right_minus_left'])
    def test_coverage_preserved(self):
        result=compare({'full_name':'a/b','advisories':{'status':'partial'}},{'full_name':'c/d','advisories':{'status':'not_analyzed'}})
        self.assertEqual(result['coverage']['advisories'],{'left':'partial','right':'not_analyzed'})
        self.assertEqual(result['coverage']['ci']['left'],'unknown')
    def test_invalid_report(self):
        for value in (None, [], {}, {'full_name':42}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare(value,{'full_name':'a/b'})
    def test_bounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'report.json'
            path.write_bytes(b' '* (MAX_REPORT_BYTES+1))
            with self.assertRaises(ValueError):
                read_report(path)
            path.write_text('{"full_name":"a/b"}',encoding='utf-8')
            self.assertEqual(read_report(path),{'full_name':'a/b'})
