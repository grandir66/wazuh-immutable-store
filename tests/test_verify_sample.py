"""
Verifica reale del campione di archivi in SigningManager.verify_all_integrity.

Prima di questa modifica la funzione validava SOLO la catena dei manifest
(TODO mai chiuso in signer.py: "Could also verify each archive file if paths
are accessible"): un archivio manomesso direttamente sullo storage (l'export
NFS consente creazione/modifica/cancellazione anche nel sottoalbero degli
archivi) non veniva mai scoperto. Questi test coprono il campionamento a
rotazione aggiunto per chiudere quel TODO.

Nessuna rete/NFS reale: le "letture dal backend" sono file su una directory
temporanea, il backend è un doppio scritto a mano (duck-typing: il codice
sotto test chiama solo `list_archives()`).
"""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from models import GPGConfig, IntegrityConfig
from signer import SigningManager
from verify_ledger import VerificationLedger


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


class FakeBackend:
    """Doppio minimale: implementa solo ciò che _verify_sample usa."""

    def __init__(self, items, list_fails=False):
        self._items = items
        self.list_fails = list_fails

    def list_archives(self, year=None, month=None):
        if self.list_fails:
            raise RuntimeError("enumerazione fallita (simulato)")
        return list(self._items)


class FakeGPGSigner:
    """Sostituisce GPGSigner nei test: nessun binario gpg reale invocato."""

    def __init__(self, invalid_for=()):
        self.enabled = True
        self._invalid_for = set(invalid_for)

    def verify_signature(self, file_path: Path, signature_path: Path) -> bool:
        return file_path.name not in self._invalid_for


def _make_signing_manager(manifest_dir: Path, sample_per_run: int = 10) -> SigningManager:
    gpg_config = GPGConfig(enabled=False)  # niente subprocess gpg in __init__
    integrity_config = IntegrityConfig(sample_per_run=sample_per_run)
    return SigningManager(gpg_config, integrity_config, manifest_dir)


def _make_archives(base_dir: Path, count: int):
    """Crea `count` coppie (archivio, .sha256) integre e ritorna le voci
    nel formato restituito da StorageBackend.list_archives()."""
    items = []
    for i in range(count):
        name = f"wazuh-logs-2026-01-{i + 1:02d}.tar.gz"
        path = base_dir / name
        path.write_bytes(f"contenuto-archivio-{i}".encode())
        checksum_path = path.with_suffix(path.suffix + '.sha256')
        checksum_path.write_text(f"{_sha256_of(path)}  {name}\n")
        items.append({
            "name": name,
            "locator": str(path),
            "size": path.stat().st_size,
            "modified": None,
            "has_signature": False,
            "has_checksum": True,
        })
    return items


class TestCampioneTuttoIntegro(unittest.TestCase):
    """1. Campione con tutti gli archivi integri -> checked==valid==N, esito valido."""

    def test_tutti_integri(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 5)
            sm = _make_signing_manager(base / 'manifests', sample_per_run=5)
            backend = FakeBackend(items)

            valid, results = sm.verify_all_integrity(backend=backend, ledger=None)

            self.assertTrue(valid)
            self.assertEqual(results['archives_checked'], 5)
            self.assertEqual(results['archives_valid'], 5)
            self.assertEqual(results['archive_errors'], [])


class TestContenutoAlterato(unittest.TestCase):
    """2. Un archivio il cui contenuto non corrisponde più al .sha256 ->
    esito non valido, l'archivio citato in archive_errors."""

    def test_contenuto_alterato_rilevato(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 4)
            # Manomissione diretta sullo storage: il contenuto cambia DOPO che
            # il .sha256 accanto era già stato scritto con l'hash originale.
            manomesso = Path(items[1]['locator'])
            manomesso.write_bytes(b"contenuto sostituito senza aggiornare il .sha256")

            sm = _make_signing_manager(base / 'manifests', sample_per_run=4)
            backend = FakeBackend(items)

            valid, results = sm.verify_all_integrity(backend=backend, ledger=None)

            self.assertFalse(valid)
            self.assertEqual(results['archives_checked'], 4)
            self.assertEqual(results['archives_valid'], 3)
            self.assertTrue(
                any(manomesso.name in err for err in results['archive_errors']),
                results['archive_errors'],
            )


class TestFirmaNonVerificabile(unittest.TestCase):
    """3. Una firma .sig non verificabile -> esito non valido, la verifica
    PROSEGUE sugli altri archivi del campione."""

    def test_firma_non_valida_non_blocca_il_giro(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 3)
            for item in items:
                sig_path = Path(item['locator']).with_suffix(
                    Path(item['locator']).suffix + '.sig'
                )
                sig_path.write_text("firma-fittizia")
                item['has_signature'] = True

            bersaglio = Path(items[0]['locator']).name

            sm = _make_signing_manager(base / 'manifests', sample_per_run=3)
            sm.gpg_signer = FakeGPGSigner(invalid_for={bersaglio})
            backend = FakeBackend(items)

            valid, results = sm.verify_all_integrity(backend=backend, ledger=None)

            self.assertFalse(valid)
            # Il giro prosegue: TUTTI e 3 sono stati controllati, non solo il primo.
            self.assertEqual(results['archives_checked'], 3)
            self.assertEqual(results['archives_valid'], 2)
            self.assertTrue(any(bersaglio in err for err in results['archive_errors']))


class TestArchivioIrraggiungibile(unittest.TestCase):
    """4. Un archivio irraggiungibile (errore di lettura dal backend) ->
    registrato in archive_errors senza interrompere il giro."""

    def test_file_assente_non_blocca_il_giro(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 3)
            # Simula "NFS che non risponde per questo file": il locator punta
            # a un file mai scritto/scomparso.
            items[2]['locator'] = str(base / 'wazuh-logs-fantasma.tar.gz')

            sm = _make_signing_manager(base / 'manifests', sample_per_run=3)
            backend = FakeBackend(items)

            valid, results = sm.verify_all_integrity(backend=backend, ledger=None)

            self.assertFalse(valid)
            self.assertEqual(results['archives_checked'], 3)
            self.assertEqual(results['archives_valid'], 2)
            self.assertTrue(any('non trovato' in err for err in results['archive_errors']))


class TestCampionamentoDisattivato(unittest.TestCase):
    """5. sample_per_run: 0 -> solo catena, archives_checked == 0, esito
    dipende dalla sola catena (comportamento preservato)."""

    def test_zero_disattiva_il_campionamento(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 5)
            # Anche con un archivio manomesso, con sample_per_run=0 non deve
            # essere nemmeno guardato.
            Path(items[0]['locator']).write_bytes(b"manomesso")

            sm = _make_signing_manager(base / 'manifests', sample_per_run=0)
            backend = FakeBackend(items)

            valid, results = sm.verify_all_integrity(backend=backend, ledger=None)

            self.assertEqual(results['archives_checked'], 0)
            self.assertEqual(results['archives_valid'], 0)
            self.assertEqual(results['archive_errors'], [])
            # Manifest assente => catena vuota => valida di default.
            self.assertTrue(valid)


class TestRotazione(unittest.TestCase):
    """6. Rotazione: due giri consecutivi con N minore del totale controllano
    archivi diversi."""

    def test_due_giri_controllano_archivi_diversi(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            items = _make_archives(base, 6)
            ledger = VerificationLedger(base / 'verify-ledger.json')

            sm1 = _make_signing_manager(base / 'manifests', sample_per_run=2)
            backend = FakeBackend(items)
            sm1.verify_all_integrity(backend=backend, ledger=ledger)
            primo_giro = set(ledger.read().keys())
            self.assertEqual(len(primo_giro), 2)

            sm2 = _make_signing_manager(base / 'manifests', sample_per_run=2)
            sm2.verify_all_integrity(backend=backend, ledger=ledger)
            dopo_secondo_giro = set(ledger.read().keys())

            secondo_giro = dopo_secondo_giro - primo_giro
            self.assertEqual(len(secondo_giro), 2, dopo_secondo_giro)
            self.assertTrue(primo_giro.isdisjoint(secondo_giro))


class TestBackendMancanteConCampioneRichiesto(unittest.TestCase):
    """Se sample_per_run > 0 ma non c'è un backend, non si finge un successo:
    va registrato come impossibilità di campionare."""

    def test_nessun_backend_e_campione_richiesto_e_esito_non_valido(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sm = _make_signing_manager(base / 'manifests', sample_per_run=5)
            valid, results = sm.verify_all_integrity(backend=None, ledger=None)
            self.assertFalse(valid)
            self.assertTrue(results['archive_errors'])


if __name__ == '__main__':
    unittest.main()
