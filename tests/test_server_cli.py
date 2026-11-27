import unittest
from contextlib import redirect_stderr
from io import StringIO
from devpulse.server import parse_args

class ServerCLITests(unittest.TestCase):
    def test_loopback_default(self):
        args=parse_args([])
        self.assertEqual((args.host,args.port),('127.0.0.1',8000))
    def test_explicit_container_bind(self):
        args=parse_args(['--host','0.0.0.0','--port','8080'])
        self.assertEqual((args.host,args.port),('0.0.0.0',8080))
    def test_invalid_bind_and_port(self):
        for argv in (['--host','example.com'],['--port','0'],['--port','65536']):
            with self.subTest(argv=argv),redirect_stderr(StringIO()),self.assertRaises(SystemExit):
                parse_args(argv)
