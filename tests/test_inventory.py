import io
import json
import unittest
from devpulse.inventory import summarize_tree
from devpulse.scanner import scan

def blob(path, mode='100644'):
    return {'path':path,'type':'blob','mode':mode}
def tree(entries, truncated=False):
    return {'sha':'test-tree','tree':entries,'truncated':truncated}

class InventoryTests(unittest.TestCase):
    def test_counts_and_evidence(self):
        data=tree([blob('README.md'),blob('src/package.json'),blob('tests/test_api.py'),
                   blob('.github/workflows/test.yml'),blob('link','120000'),
                   {'path':'src','type':'tree','mode':'040000'},
                   {'path':'vendor','type':'commit','mode':'160000'}])
        result=summarize_tree(data)
        self.assertEqual(result['observed'],{'files':4,'directories':1,'symlinks':1,'submodules':1})
        self.assertEqual(result['dependency_manifests']['examples'],['src/package.json'])
        self.assertEqual(result['workflow_files']['observed_count'],1)
        self.assertEqual(result['test_file_candidates']['observed_count'],1)
        self.assertEqual(result['documentation_files']['observed_count'],1)
    def test_partial(self):
        result=summarize_tree(tree([blob('README.md')],True))
        self.assertEqual(result['status'],'partial')
        self.assertTrue(result['truncated'])
    def test_empty(self):
        self.assertEqual(summarize_tree(tree([]))['observed']['files'],0)
    def test_examples_bounded(self):
        result=summarize_tree(tree([blob(f'{i}/package.json') for i in range(60)]))
        self.assertEqual(result['dependency_manifests']['observed_count'],60)
        self.assertEqual(len(result['dependency_manifests']['examples']),50)
        self.assertTrue(result['dependency_manifests']['examples_truncated'])
    def test_invalid(self):
        for data in ({},tree([blob('a'),blob('a')]),tree([blob('a','000000')]),tree([None])):
            with self.subTest(data=data),self.assertRaises(ValueError):
                summarize_tree(data)
    def test_symlink_not_manifest(self):
        self.assertEqual(summarize_tree(tree([blob('package.json','120000')]))['dependency_manifests']['observed_count'],0)
    def test_scan_inventory(self):
        def fake(req,timeout):
            payload=tree([blob('README.md')]) if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'feature/demo'}
            if '/git/trees/' in req.full_url:
                self.assertTrue(req.full_url.endswith('/feature%2Fdemo?recursive=1'))
            return io.BytesIO(json.dumps(payload).encode())
        result=scan('a/b',fake,include_inventory=True)
        self.assertEqual(result['inventory']['status'],'ok')
        self.assertEqual(result['inventory']['tree_sha'],'test-tree')
        self.assertIsNone(result['security_findings'])
    def test_inventory_failure_preserves_metadata(self):
        def fake(req,timeout):
            payload={} if '/git/trees/' in req.full_url else {'full_name':'a/b','default_branch':'main'}
            return io.BytesIO(json.dumps(payload).encode())
        result=scan('a/b',fake,include_inventory=True)
        self.assertEqual(result['full_name'],'a/b')
        self.assertEqual(result['inventory']['status'],'unavailable')
    def test_no_branch_and_disabled(self):
        fake=lambda *a,**kw:io.BytesIO(b'{"full_name":"a/b"}')
        self.assertEqual(scan('a/b',fake,include_inventory=True)['inventory']['status'],'unavailable')
        self.assertEqual(scan('a/b',fake)['inventory']['status'],'not_analyzed')
