import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .scanner import scan, ScanError

PAGE = Path(__file__).with_name('index.html').read_bytes()
class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)
    def json_reply(self, status, obj):
        self.reply(status, json.dumps(obj).encode(), 'application/json; charset=utf-8')
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == '/':
            return self.reply(200, PAGE, 'text/html; charset=utf-8')
        if url.path == '/health':
            return self.json_reply(200, {'status':'ok'})
        if url.path != '/api/scan':
            return self.json_reply(404, {'error':'Not found'})
        if len(url.query) > 2048:
            return self.json_reply(400, {'error':'Query too long'})
        try:
            value = parse_qs(url.query).get('repo', [''])[0]
            self.json_reply(200, scan(value, include_languages=True, include_inventory=True, include_ci=True, include_dependencies=True))
        except ValueError as exc:
            self.json_reply(400, {'error':str(exc)})
        except ScanError as exc:
            self.json_reply(502, {'error':str(exc)})

if __name__ == '__main__':
    with ThreadingHTTPServer(('127.0.0.1', 8000), Handler) as server:
        print('DevPulse: http://127.0.0.1:8000', flush=True)
        server.serve_forever()
