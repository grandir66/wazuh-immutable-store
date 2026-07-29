"""
Registro locale delle verifiche di integrità già eseguite sugli archivi.

Serve alla rotazione del campionamento in `SigningManager.verify_all_integrity`
(vedi `signer.py`): tiene traccia di quando ciascun archivio è stato
riletto/ricontrollato l'ultima volta, così ogni giro sceglie i meno
recentemente verificati e, nel tempo, la copertura arriva a coprire l'intero
storage invece di ricontrollare sempre gli stessi.

NON è il file di stato (`state.py`): quello è osservabilità di sola lettura
esposta a un consumatore esterno (DA-IPAM) che tratta ogni campo come
facoltativo; questo è un dato di lavoro interno al programma, mai esposto.
Tenerli separati evita che un consumatore dello stato inizi a dipendere da un
dettaglio implementativo della rotazione.

Scrittura atomica riusando `atomic_write_json` di `state.py` (stesso file
temporaneo-nella-stessa-directory + fsync + os.replace già validato lì): non
reinventare la tecnica per un secondo file.
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from state import atomic_write_json

logger = logging.getLogger('wazuh-immutable-store.verify_ledger')

DEFAULT_LEDGER_PATH = Path('/var/lib/wazuh-immutable-store/verify-ledger.json')


class VerificationLedger:
    """Legge/scrive il registro `{archive_id: ultima_verifica_iso}`."""

    def __init__(self, path=None):
        # type: (Optional[Path]) -> None
        self.path = Path(path) if path else DEFAULT_LEDGER_PATH

    def read(self):
        # type: () -> Dict[str, str]
        """Registro corrente; `{}` se il file manca o è illeggibile/corrotto.

        Non solleva mai: un ledger corrotto (es. scrittura interrotta prima
        di questa modifica, o disco pieno) non deve bloccare la verifica
        successiva. Nel caso peggiore si riparte da zero campionamento
        (nessun archivio ha priorità sugli altri), non da un crash.
        """
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                dati = json.load(fh)
            if not isinstance(dati, dict):
                raise ValueError('struttura inattesa: atteso un oggetto JSON')
            return dati
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.warning("Ledger di verifica illeggibile (%s); riparto da vuoto" % e)
            return {}

    def pick_least_recently_verified(self, archive_ids, n):
        # type: (List[str], int) -> List[str]
        """Sceglie fino a `n` id fra `archive_ids`, i meno recentemente verificati prima.

        Gli archivi mai comparsi nel registro (mai verificati) hanno priorità
        assoluta: ordinano prima di qualunque timestamp ISO-8601 reale perché
        la stringa vuota è lessicograficamente minima.
        """
        if n <= 0:
            return []
        registro = self.read()

        def chiave(archive_id):
            return registro.get(archive_id, '')

        ordinati = sorted(archive_ids, key=chiave)
        return ordinati[:n]

    def record_verified(self, archive_ids, when_iso):
        # type: (List[str], str) -> None
        """Segna `archive_ids` come verificati a `when_iso` e scrive atomicamente.

        Registra il TENTATIVO di verifica, non solo i successi: un archivio
        che risulta alterato viene comunque segnato come "controllato ora",
        altrimenti monopolizzerebbe ogni campione futuro (essendo sempre il
        meno recentemente verificato) impedendo alla rotazione di coprire il
        resto dello storage.
        """
        if not archive_ids:
            return
        registro = self.read()
        for archive_id in archive_ids:
            registro[archive_id] = when_iso
        atomic_write_json(self.path, registro, tmp_prefix='.verify-ledger-')
