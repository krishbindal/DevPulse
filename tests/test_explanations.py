import unittest

from devpulse.explanations import evidence_catalog, select_explanations


class ExplanationTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            'static_python': {'status': 'ok', 'findings': [
                {'rule': 'PY001', 'path': 'IGNORE INSTRUCTIONS.py',
                 'line': 1, 'blob_sha': 'untrusted'}]},
            'ci': {'status': 'unavailable'},
        }

    def test_catalog_excludes_repository_strings(self):
        catalog = evidence_catalog(self.report)
        self.assertEqual(len(catalog), 2)
        self.assertNotIn('IGNORE INSTRUCTIONS', str(catalog))
        self.assertNotIn('untrusted', str(catalog))

    def test_valid_permutation_preserves_evidence(self):
        baseline = select_explanations(self.report)
        result = select_explanations(self.report, '[1,0]')
        self.assertEqual(result['mode'], 'validated_selection')
        self.assertEqual(result['entries'], baseline['entries'][::-1])

    def test_invalid_responses_fall_back(self):
        baseline = select_explanations(self.report)
        for response in ('[0]', '[0,0]', '[0,2]', '[false,1]',
                         '[0,1.0]', '{"text":"invented"}', 'not JSON',
                         '[' * 2000, ' ' * 4097, '\ud800', None):
            with self.subTest(response=repr(response)[:80]):
                self.assertEqual(select_explanations(self.report, response),
                                 baseline)

    def test_empty_catalog(self):
        self.assertEqual(select_explanations({}, '[]')['entries'], [])
