
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'devpulse'
class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids=[]
        self.links=[]
        self.inline=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if 'id' in attrs:self.ids.append(attrs['id'])
        if tag=='a' and attrs.get('href','').startswith('#'):self.links.append(attrs['href'][1:])
        if 'style' in attrs or any(k.startswith('on') for k in attrs) or tag=='style' or (tag=='script' and 'src' not in attrs):
            self.inline.append(tag)

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.page=Markup()
        self.page.feed((ROOT/'index.html').read_text())
    def test_unique_ids_and_navigation(self):
        self.assertEqual(len(self.page.ids),len(set(self.page.ids)))
        self.assertTrue(set(self.page.links).issubset(self.page.ids))
        self.assertTrue({'overview','security','dependencies','engineering','inventory'}.issubset(self.page.links))
    def test_script_targets_exist(self):
        script=(ROOT/'dashboard.js').read_text()
        self.assertTrue(set(re.findall(r"\$\('([^']+)'\)",script)).issubset(self.page.ids))
        self.assertIn("document.createElement('meter')",script)
    def test_no_inline_executable_or_style(self):
        self.assertEqual(self.page.inline,[])
