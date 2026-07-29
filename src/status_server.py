"""
Server di sola lettura per il file di stato.

Deliberatamente stupido: non calcola nulla, non esegue comandi, non accede a
mount o log. Legge un file JSON e lo restituisce. Questo permette di eseguirlo
come utente non privilegiato su una macchina indurita.
"""
import hmac
import json
import logging
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

logger = logging.getLogger('wazuh-immutable-store.status-server')

MAX_BODY = 0  # nessun corpo accettato


def build_handler(state_path, token):
    # type: (Path, str) -> type
    """Fabbrica il gestore delle richieste legato a un file di stato e a un token."""

    class StatusHandler(BaseHTTPRequestHandler):
        server_version = 'wazuh-immutable-store-status'
        sys_version = ''

        def _json(self, code, payload):
            # type: (int, dict) -> None
            corpo = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(corpo)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(corpo)

        def _autorizzato(self):
            # type: () -> bool
            intestazione = self.headers.get('Authorization', '')
            if not intestazione.startswith('Bearer '):
                return False
            fornito = intestazione[len('Bearer '):].strip()
            # Confronto a tempo costante: evita di distinguere i token per tempistica.
            return hmac.compare_digest(fornito, token)

        def do_GET(self):  # noqa: N802 (nome imposto da BaseHTTPRequestHandler)
            if self.path == '/health':
                self._json(200, {'status': 'ok', 'schema_version': 1})
                return
            if self.path == '/status':
                if not self._autorizzato():
                    self._json(401, {'error': 'token mancante o non valido'})
                    return
                try:
                    with open(state_path, 'r', encoding='utf-8') as fh:
                        self._json(200, json.load(fh))
                except FileNotFoundError:
                    self._json(503, {'error': 'stato non ancora disponibile'})
                except Exception:
                    # Nessun dettaglio verso l'esterno: potrebbe rivelare percorsi.
                    logger.exception('Lettura dello stato fallita')
                    self._json(500, {'error': 'stato illeggibile'})
                return
            self._json(404, {'error': 'non trovato'})

        def _metodo_non_ammesso(self):
            # Qualsiasi metodo diverso da GET è respinto con lo stesso 404
            # generico usato per i percorsi sconosciuti: nessuna distinzione
            # che possa rivelare quali percorsi/metodi esistono davvero.
            self._json(404, {'error': 'non trovato'})

        do_POST = _metodo_non_ammesso
        do_PUT = _metodo_non_ammesso
        do_DELETE = _metodo_non_ammesso
        do_PATCH = _metodo_non_ammesso
        do_HEAD = _metodo_non_ammesso

        def log_message(self, format, *args):
            # Log essenziale su stdout (journald), senza intestazioni: il token
            # non deve mai finire nei log.
            logger.info('%s %s', self.command, self.path)

    return StatusHandler


def run_status_server(state_path, token, certfile, keyfile, host='0.0.0.0', port=9443):
    # type: (Path, str, str, str, str, int) -> None
    """Avvia il server HTTPS. Non ritorna."""
    if not token:
        raise ValueError('Token del server di stato non configurato')
    handler = build_handler(Path(state_path), token)
    httpd = HTTPServer((host, port), handler)
    contesto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contesto.load_cert_chain(certfile=certfile, keyfile=keyfile)
    contesto.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd.socket = contesto.wrap_socket(httpd.socket, server_side=True)
    logger.info("Server di stato in ascolto su https://%s:%s" % (host, port))
    httpd.serve_forever()
