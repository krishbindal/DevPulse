import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .scanner import scan, ScanError, parse_repository
from .scan_gate import ScanGate, cacheable

PAGE = Path(__file__).with_name('index.html').read_bytes()
ASSETS = {'/assets/dashboard.css':(Path(__file__).with_name('dashboard.css').read_bytes(),'text/css; charset=utf-8'),
          '/assets/dashboard.js':(Path(__file__).with_name('dashboard.js').read_bytes(),'text/javascript; charset=utf-8')}
class DevPulseServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        self.scan_gate=ScanGate()
        super().__init__(address,handler)

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type, *, extra_headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        for name,value in (extra_headers or {}).items():
            self.send_header(name,value)
        self.end_headers()
        self.wfile.write(body)
    def json_reply(self, status, obj, *, extra_headers=None):
        self.reply(status, json.dumps(obj).encode(), 'application/json; charset=utf-8', extra_headers=extra_headers)
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == '/':
            return self.reply(200, PAGE, 'text/html; charset=utf-8')
        if url.path in ASSETS:
            body,content_type=ASSETS[url.path]
            return self.reply(200,body,content_type)
        if url.path == '/health':
            return self.json_reply(200, {'status':'ok'})
        if url.path != '/api/scan':
            return self.json_reply(404, {'error':'Not found'})
        if len(url.query) > 2048:
            return self.json_reply(400, {'error':'Query too long'})
        try:
            params = parse_qs(url.query, keep_blank_values=True, max_num_fields=8)
            if len(params.get('repo',[]))!=1 or any(flag in params and params[flag] not in (['0'],['1']) for flag in ('advisories','static')):
                raise ValueError('Supply one repository and optional advisory/static flags of 0 or 1.')
            owner,repo=parse_repository(params['repo'][0])
            value=owner.lower()+'/'+repo.lower()
            advisory=params.get('advisories')==['1']
            static=params.get('static')==['1']
            key=(value,advisory,static)
            gate=self.server.scan_gate
            state,cached=gate.begin(key)
            if state=='hit':
                return self.reply(200,cached,'application/json; charset=utf-8',extra_headers={'X-DevPulse-Cache':'HIT'})
            if state in ('busy','limited'):
                return self.json_reply(429,{'error':'Scan capacity reached. Retry shortly.'},
                                       extra_headers={'Retry-After':'5' if state=='busy' else '60'})
            payload=None
            try:
                options={'include_advisories':True} if advisory else {}
                if static:
                    options['include_static']=True
                report=scan(value,include_languages=True,include_inventory=True,include_ci=True,include_dependencies=True,**options)
                encoded=json.dumps(report).encode()
                if cacheable(report):
                    payload=encoded
            finally:
                gate.finish(key,payload)
            self.reply(200,encoded,'application/json; charset=utf-8',extra_headers={'X-DevPulse-Cache':'MISS'})
        except ValueError as exc:
            self.json_reply(400, {'error':str(exc)})
        except ScanError as exc:
            self.json_reply(502, {'error':str(exc)})

def parse_args(argv=None):
    parser=argparse.ArgumentParser(description='DevPulse local development server')
    parser.add_argument('--host',choices=('127.0.0.1','0.0.0.0'),default='127.0.0.1',
                        help='Use 0.0.0.0 only inside a local container or isolated network.')
    parser.add_argument('--port',type=int,default=8000)
    args=parser.parse_args(argv)
    if not 1<=args.port<=65535:
        parser.error('port must be between 1 and 65535')
    return args

def main():
    args=parse_args()
    if args.host=='0.0.0.0':
        print('Warning: local prototype; do not expose this listener publicly.',flush=True)
    with DevPulseServer((args.host,args.port),Handler) as server:
        print(f'DevPulse: http://{args.host}:{args.port}',flush=True)
        server.serve_forever()

if __name__ == '__main__':
    main()
