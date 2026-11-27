"""Real Chromium interaction with a local HTTP server and deterministic scan fixtures."""
import json
import threading
import unittest
from unittest.mock import patch
from playwright.sync_api import sync_playwright, expect
from devpulse.server import DevPulseServer, Handler
from devpulse.scan_gate import ScanGate
from devpulse.scanner import ScanError
from devpulse.recommendations import recommend

MARKUP = '<img src=x onerror="window.injected=true">'

def fixture(*args,**kwargs):
    report={'full_name':'example/project','description':MARKUP,'stargazers_count':0,
            'forks_count':2,'open_issues_count':3,'language':'Python','default_branch':'main',
            'source':'fixture://metadata','scanned_at':'2026-01-01T00:00:00Z',
            'languages':{'status':'ok','entries':[{'name':'Python','bytes':75,'percent':75},{'name':'HTML','bytes':25,'percent':25}]},
            'inventory':{'status':'unavailable','error':'Fixture tree unavailable.'},
            'ci':{'status':'unavailable','error':'Fixture CI unavailable.'},
            'npm_dependencies':{'status':'not_found'},'npm_lockfile':{'status':'not_found'},
            'python_dependencies':{'status':'partial','counts':{'exact_pins':1,'bare_names':0,'unsupported_lines':1},
                                   'entries':[{'name':'example','declared_version':'1.0'}]},
            'static_python':{'status':'not_analyzed'},'advisories':{'status':'not_analyzed'},
            'practices':{'status':'partial','scope':'Fixture evidence only.',
                         'counts':{'observed':0,'not_observed':0,'unknown':1},
                         'checks':[{'label':'Tests','id':'tests','state':'unknown',
                                    'recommendation':'Verify coverage.','examples':[]}]}}
    if kwargs.get('include_advisories'):
        report['advisories']={'status':'partial','queried_versions':1,'entries':[
            {'ecosystem':'PyPI','name':'example','version':'1.0','evidence':['declaration'],
             'advisory_ids':['GHSA-fixture'],'partial':False}]}
    if kwargs.get('include_static'):
        report['static_python']={'status':'partial','analyzed_files':1,'observed_python_files':2,
                                 'observed_findings':1,'findings_truncated':False,'findings':[
            {'rule':'PY001','path':'a.py','line':3,'blob_sha':'fixture','message':'Review dynamic execution.'}]}
    report['recommendations']=recommend(report)
    return report

class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=DevPulseServer(('127.0.0.1',0),Handler)
        cls.worker=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.worker.start()
        cls.url=f'http://127.0.0.1:{cls.server.server_port}'
        cls.playwright=sync_playwright().start()
        cls.browser=cls.playwright.chromium.launch()
    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(2)
    def setUp(self):
        self.server.scan_gate=ScanGate()
        self.context=self.browser.new_context(accept_downloads=True,viewport={'width':1280,'height':800})
        self.addCleanup(self.context.close)
        self.page=self.context.new_page()
        self.errors=[]
        self.page.on('pageerror',lambda error:self.errors.append(str(error)))
        self.page.goto(self.url)
    def submit(self):
        self.page.locator('#repo').fill('example/project')
        self.page.locator('#submit').click()
    def test_report_and_literal_untrusted_markup(self):
        with patch('devpulse.server.scan',side_effect=fixture) as scanner:
            self.submit()
            expect(self.page.locator('#results')).to_be_visible()
            expect(self.page.locator('#name')).to_have_text('example/project')
            expect(self.page.locator('#name')).to_be_focused()
            expect(self.page.locator('#description')).to_have_text(MARKUP)
            self.assertEqual(self.page.locator('#description img').count(),0)
            self.assertFalse(self.page.evaluate('Boolean(window.injected)'))
            expect(self.page.locator('#languages meter')).to_have_count(2)
            expect(self.page.locator('#inventory-status')).to_contain_text('unavailable')
            expect(self.page.locator('#python-status')).to_contain_text('Partial analysis')
            expect(self.page.locator('#recommendations-list')).to_contain_text('Verify incomplete')
            self.assertFalse(scanner.call_args.kwargs.get('include_advisories',False))
            self.assertFalse(scanner.call_args.kwargs.get('include_static',False))
            self.assertEqual(self.errors,[])
    def test_opt_in_and_json_export(self):
        with patch('devpulse.server.scan',side_effect=fixture) as scanner:
            self.page.locator('#advisories-opt').check()
            self.page.locator('#static-opt').check()
            self.submit()
            expect(self.page.locator('#advisories-entries')).to_contain_text('GHSA-fixture')
            expect(self.page.locator('#static-findings')).to_contain_text('a.py:3')
            self.assertTrue(scanner.call_args.kwargs['include_advisories'])
            self.assertTrue(scanner.call_args.kwargs['include_static'])
            with self.page.expect_download() as downloaded:
                self.page.locator('#download').click()
            download=downloaded.value
            self.assertEqual(download.suggested_filename,'devpulse-report.json')
            with open(download.path(),encoding='utf-8') as f:
                report=json.load(f)
            self.assertEqual(report['full_name'],'example/project')
            self.assertEqual(report['advisories']['entries'][0]['advisory_ids'],['GHSA-fixture'])
            self.assertEqual(self.errors,[])
    def test_error_and_retry(self):
        with patch('devpulse.server.scan',side_effect=ScanError('Fixture upstream unavailable.')):
            self.submit()
            expect(self.page.locator('#status')).to_have_text('Fixture upstream unavailable.')
            expect(self.page.locator('#results')).to_be_hidden()
            expect(self.page.locator('#submit')).to_be_enabled()
        with patch('devpulse.server.scan',side_effect=fixture):
            self.submit()
            expect(self.page.locator('#results')).to_be_visible()
            expect(self.page.locator('#status')).to_contain_text('Fresh scan')
            self.assertEqual(self.errors,[])
    def test_mobile_navigation_and_no_horizontal_overflow(self):
        self.page.set_viewport_size({'width':375,'height':812})
        with patch('devpulse.server.scan',side_effect=fixture):
            self.submit()
            expect(self.page.locator('#results')).to_be_visible()
            self.page.get_by_role('link',name='Next steps',exact=True).click()
            expect(self.page).to_have_url(self.url+'/#recommendations')
            expect(self.page.locator('#recommendations-title')).to_be_in_viewport()
            self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'))
            self.assertEqual(self.errors,[])

    def test_local_comparison_and_invalid_retry(self):
        self.page.set_viewport_size({'width':375,'height':812})
        requests=[]
        self.page.on('request',lambda request:requests.append(request.url))
        def upload(selector, report):
            self.page.locator(selector).set_input_files({'name':'report.json','mimeType':'application/json','buffer':json.dumps(report).encode()})
        upload('#compare-left',{'full_name':MARKUP,'stargazers_count':0,'languages':{'status':'ok'}})
        upload('#compare-right',{'full_name':'example/right','stargazers_count':5})
        self.page.locator('#compare-submit').click()
        expect(self.page.locator('#compare-result')).to_be_visible()
        expect(self.page.locator('#compare-provenance')).to_contain_text(MARKUP)
        expect(self.page.locator('#compare-rows tr').first).to_have_text('Stars055')
        expect(self.page.locator('#compare-rows')).to_contain_text('Unknown')
        self.assertEqual(self.page.locator('#compare-provenance img').count(),0)
        self.assertEqual(requests,[])
        self.assertTrue(self.page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'))
        upload('#compare-right',{})
        self.page.locator('#compare-submit').click()
        expect(self.page.locator('#compare-result')).to_be_hidden()
        expect(self.page.locator('#compare-status')).to_contain_text('Expected a report')
        upload('#compare-right',{'full_name':'example/right'})
        self.page.locator('#compare-submit').click()
        expect(self.page.locator('#compare-result')).to_be_visible()
        self.assertEqual(self.errors,[])
