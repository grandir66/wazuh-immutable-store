"""
Stato osservabile del programma.

Scrive un unico file JSON che descrive l'ultimo esito di ogni ciclo e lo stato
vivo della destinazione. È l'unica cosa che il server di stato espone: per questo
la scrittura è atomica (nessun lettore deve mai vedere un file a metà) e nessuna
funzione qui dentro fa I/O di rete.
"""
import json
import logging
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger('wazuh-immutable-store.state')

STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_PATH = Path('/var/lib/wazuh-immutable-store/state.json')

_SEZIONI_RUN = ('archive', 'retention', 'verify')


def _now_iso():
    # type: () -> str
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def atomic_write_json(path, payload, tmp_prefix='.tmp-', chmod=None):
    # type: (Path, dict, str, Optional[int]) -> None
    """Scrive `payload` come JSON in `path` in modo atomico.

    Tecnica: file temporaneo nella STESSA directory di `path` (necessario
    perché `os.replace` è atomico solo sullo stesso filesystem), `fsync`
    prima del rename, poi `os.replace`. Nessun lettore concorrente vede mai
    un file a metà, e uno scrittore interrotto a metà lascia al più un file
    `.tmp` orfano accanto a `path`, mai `path` corrotto.

    Condivisa da `StateStore` (stato osservabile) e da qualunque altro
    registro locale con lo stesso bisogno (es. il ledger delle verifiche in
    `verify_ledger.py`): la tecnica è una sola, non va reinventata a ogni
    nuovo file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=tmp_prefix, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        if chmod is not None:
            os.chmod(path, chmod)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def empty_state(host=None):
    # type: (Optional[str]) -> dict
    """Scheletro dello stato: tutte le sezioni presenti, nessun dato."""
    return {
        'schema_version': STATE_SCHEMA_VERSION,
        'generated_at': _now_iso(),
        'host': host or socket.gethostname(),
        'backend': {},
        'local_disk': {},
        'runs': {nome: {'outcome': 'never'} for nome in _SEZIONI_RUN},
        'archives': {},
        'retention_policy': {},
        'schedule': {},
    }


def classify_archive_outcome(connected, created, uploaded, failed):
    # type: (bool, int, int, int) -> str
    """
    Esito reale di un ciclo di archiviazione.

    Nota: prima di questa funzione il comando usciva sempre con codice 0, anche
    con il backend irraggiungibile o con tutti gli upload falliti.
    """
    if not connected:
        return 'failed'
    if created == 0:
        return 'success'          # niente da archiviare non è un errore
    if failed > 0:
        return 'partial' if uploaded > 0 else 'failed'
    return 'success'


def creation_only_failure(records_created, creation_errors):
    # type: (int, int) -> bool
    """
    True quando il ciclo non ha prodotto NESSUN archivio a causa di errori di
    creazione, non perché non c'era nulla da archiviare.

    Prima di questa funzione, `run_archive_cycle` inghiottiva `ArchiveError`
    con un semplice `continue`: se TUTTE le creazioni fallivano (es. disco
    temporaneo pieno), il ciclo tornava una lista vuota indistinguibile dal
    caso "niente da fare", e il comando registrava/usciva come successo.
    """
    return records_created == 0 and creation_errors > 0


def registra_esito_archive_stato(state, dry_run, avviato_il, esito, creati,
                                  caricati, falliti, byte_caricati, errore):
    # type: (StateStore, bool, str, str, int, int, int, int, Optional[str]) -> None
    """Scrive nel file di stato l'esito del ciclo di archiviazione.

    In dry-run non scrive NULLA: il dry-run osserva soltanto, non deve alterare
    lo stato reale. Senza questa guardia, un operatore che lancia un dry-run
    dopo un ciclo fallito vero cancellerebbe l'allarme fino al ciclo reale
    successivo (l'esito 'success, uploaded: 0' del dry-run sovrascriverebbe
    quello 'failed' precedente).

    Estratta a livello di funzione di modulo (invece che come metodo dipendente
    da un'istanza App completa, che richiede config/yaml non sempre
    disponibili) per essere testabile in isolamento con una StateStore vera
    puntata su un path temporaneo.
    """
    if dry_run:
        logger.info("dry-run: stato archiviazione non aggiornato (nessuna modifica reale)")
        return
    try:
        state.update_section('archive', {
            'last_started_at': avviato_il,
            'last_finished_at': _now_iso(),
            'outcome': esito,
            'archives_created': creati,
            'uploaded': caricati,
            'failed': falliti,
            'bytes_uploaded': byte_caricati,
            'error': errore,
        })
    except Exception as e:
        # Lo stato è osservabilità: un suo problema non deve far fallire l'archiviazione.
        logger.warning("Impossibile aggiornare il file di stato: %s" % e)


class StateStore(object):
    """Legge e aggiorna il file di stato. Ogni scrittura è atomica."""

    def __init__(self, path=None):
        # type: (Optional[Path]) -> None
        if path is None:
            path = DEFAULT_STATE_PATH
        self.path = Path(path)

    def read(self):
        # type: () -> dict
        """Stato corrente; scheletro se il file manca o è illeggibile."""
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                stato = json.load(fh)
            if not isinstance(stato, dict) or 'runs' not in stato:
                raise ValueError('struttura inattesa')
            for nome in _SEZIONI_RUN:
                stato['runs'].setdefault(nome, {'outcome': 'never'})
            return stato
        except FileNotFoundError:
            return empty_state()
        except Exception as e:
            logger.warning("Stato illeggibile (%s); riparto da uno stato vuoto" % e)
            return empty_state()

    def update_section(self, section, payload):
        # type: (str, dict) -> None
        """Aggiorna una sezione di `runs` lasciando intatte le altre."""
        stato = self.read()
        stato['runs'][section] = payload
        self._write(stato)

    def update_live(self, backend, local_disk, archives, schedule):
        # type: (dict, dict, dict, dict) -> None
        """Aggiorna le parti che cambiano fra un ciclo e l'altro."""
        stato = self.read()
        stato['backend'] = backend
        stato['local_disk'] = local_disk
        stato['archives'] = archives
        stato['schedule'] = schedule
        self._write(stato)

    def update_retention_policy(self, policy):
        # type: (dict) -> None
        stato = self.read()
        stato['retention_policy'] = policy
        self._write(stato)

    def _write(self, stato):
        # type: (dict) -> None
        stato['schema_version'] = STATE_SCHEMA_VERSION
        stato['generated_at'] = _now_iso()
        atomic_write_json(self.path, stato, tmp_prefix='.state-', chmod=0o640)
