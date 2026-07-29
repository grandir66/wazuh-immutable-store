import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from status_server import build_handler

TOKEN = 'token-di-prova'


class TestStatusServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.state_path = Path(cls.tmp.name) / 'state.json'
        cls.state_path.write_text(json.dumps({'schema_version': 1, 'host': 'srv-test'}))
        handler = build_handler(cls.state_path, TOKEN)
        cls.server = HTTPServer(('127.0.0.1', 0), handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmp.cleanup()

    def _get(self, path, token=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
        if token:
            req.add_header('Authorization', f'Bearer {token}')
        return urllib.request.urlopen(req, timeout=5)

    def test_health_non_richiede_token(self):
        r = self._get('/health')
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.read())['status'], 'ok')

    def test_status_senza_token_e_negato(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get('/status')
        self.assertEqual(ctx.exception.code, 401)

    def test_status_con_token_sbagliato_e_negato(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get('/status', token='sbagliato')
        self.assertEqual(ctx.exception.code, 401)

    def test_status_con_token_giusto_ritorna_lo_stato(self):
        r = self._get('/status', token=TOKEN)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.read())['host'], 'srv-test')

    def test_percorso_sconosciuto_e_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get('/../etc/passwd', token=TOKEN)
        self.assertIn(ctx.exception.code, (400, 404))

    def test_post_non_e_ammesso(self):
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}/status', data=b'{}', method='POST')
        req.add_header('Authorization', f'Bearer {TOKEN}')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertIn(ctx.exception.code, (404, 405))


if __name__ == '__main__':
    unittest.main()
