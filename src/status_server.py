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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logger = logging.getLogger('wazuh-immutable-store.status-server')

MAX_BODY = 0  # nessun corpo accettato


def build_handler(state_path, token):
    # type: (Path, str) -> type
    """Fabbrica il gestore delle richieste legato a un file di stato e a un token."""

    class StatusHandler(BaseHTTPRequestHandler):
        server_version = 'wazuh-immutable-store-status'
        sys_version = ''

        # Anti-slowloris: se un client apre la connessione e non invia nulla,
        # BaseHTTPRequestHandler chiude dopo questo timeout invece di restare
        # bloccato per sempre (mono-thread o no).
        timeout = 10

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
            # Confronto a tempo costante su bytes: hmac.compare_digest su str
            # richiede ASCII puro e solleva TypeError su un token non-ASCII,
            # cosa che un chiamante esterno può innescare a piacere.
            return hmac.compare_digest(
                fornito.encode('utf-8', 'surrogateescape'),
                token.encode('utf-8'),
            )

        def _risolvi(self):
            # type: () -> tuple
            """Calcola (codice, payload) per la richiesta corrente. Condiviso
            fra GET e HEAD in modo che rispondano in modo identico (a parte
            il corpo)."""
            if self.path == '/health':
                return 200, {'status': 'ok', 'schema_version': 1}
            if self.path == '/status':
                if not self._autorizzato():
                    return 401, {'error': 'token mancante o non valido'}
                try:
                    with open(state_path, 'r', encoding='utf-8') as fh:
                        return 200, json.load(fh)
                except FileNotFoundError:
                    return 503, {'error': 'stato non ancora disponibile'}
                except Exception:
                    # Nessun dettaglio verso l'esterno: potrebbe rivelare percorsi.
                    logger.exception('Lettura dello stato fallita')
                    return 500, {'error': 'stato illeggibile'}
            return 404, {'error': 'non trovato'}

        def do_GET(self):  # noqa: N802 (nome imposto da BaseHTTPRequestHandler)
            codice, payload = self._risolvi()
            self._json(codice, payload)

        def do_HEAD(self):  # noqa: N802
            # Stessa risoluzione di GET, ma senza corpo (semantica HEAD).
            codice, payload = self._risolvi()
            corpo = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(codice)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(corpo)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()

        def _metodo_non_ammesso(self):
            # Qualsiasi metodo diverso da GET/HEAD è respinto con lo stesso
            # 404 generico usato per i percorsi sconosciuti: nessuna
            # distinzione che possa rivelare quali percorsi/metodi esistono
            # davvero (incluso il fatto che il server sia http.server/Python).
            self._json(404, {'error': 'non trovato'})

        def __getattr__(self, name):
            # BaseHTTPRequestHandler instrada con hasattr(self, 'do_'+VERBO):
            # se manca, risponde 501 con una pagina HTML che rivela il verbo
            # non supportato (e quindi quali sono supportati) e il fatto che
            # dietro c'è http.server/Python. Coprendo qui QUALSIASI 'do_*'
            # (OPTIONS, TRACE, CONNECT, verbi arbitrari) chiudiamo il canale
            # una volta per tutte, senza dover elencare i verbi a mano.
            if name.startswith('do_'):
                return self._metodo_non_ammesso
            raise AttributeError(name)

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
    # Threading: una connessione lenta/malevola (slowloris) non deve bloccare
    # le altre. Il timeout sul singolo handler (sopra) chiude comunque quelle
    # che non mandano nulla.
    httpd = ThreadingHTTPServer((host, port), handler)
    contesto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contesto.load_cert_chain(certfile=certfile, keyfile=keyfile)
    contesto.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd.socket = contesto.wrap_socket(httpd.socket, server_side=True)
    logger.info("Server di stato in ascolto su https://%s:%s" % (host, port))
    httpd.serve_forever()
