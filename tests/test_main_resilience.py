"""
Controprova end-to-end (Important 3 della review): un fallimento REALE nella
replica del manifest o nella scrittura del registro di verifica non deve far
fallire il ciclo chiamante (run_archive / verify_integrity in main.py).

test_manifest_replication.py prova solo il backend in isolamento, che da sé
non solleva mai (replicate_manifest cattura OSError e ritorna False). Qui i
doppi SOLLEVANO davvero, per esercitare i try/except di main.py stesso
(WazuhImmutableStore._replicate_manifest_chain e la chiamata a
verify_all_integrity dentro verify_integrity), non solo quelli dei backend.
"""
import hashlib
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

# Stesso stub di test_schedule_intervals.py: PyYAML è una dipendenza di
# produzione reale (requirements.txt), assente sul Python di sistema di
# questo Mac di sviluppo. Nessun percorso qui sotto chiama yaml.*.
try:
    import yaml  # noqa: F401
except ImportError:
    _yaml_stub = types.ModuleType('yaml')
    _yaml_stub.safe_load = lambda *a, **k: {}
    sys.modules['yaml'] = _yaml_stub

import main as main_module
from main import WazuhImmutableStore
from models import ArchiveConfig, GPGConfig, IntegrityConfig, RetentionConfig, StorageConfig
from state import StateStore


def _bare_app(base: Path) -> WazuhImmutableStore:
    """WazuhImmutableStore senza passare da load_config() (niente file di
    config.yaml da leggere): imposta a mano solo ciò che i metodi sotto test
    usano davvero."""
    app = WazuhImmutableStore.__new__(WazuhImmutableStore)
    app.config_path = None
    app.config = {}
    app.models = {
        'archive': ArchiveConfig(temp_dir=base / 'archive-temp'),
        'gpg': GPGConfig(enabled=False),
        'integrity': IntegrityConfig(sample_per_run=5),
        'storage': StorageConfig(type='qnap-nfs', qnap_nfs=None),
        'retention': RetentionConfig(),
    }
    app.state = StateStore(base / 'state.json')
    return app


class BackendCheSolleva:
    """replicate_manifest solleva DAVVERO (non torna solo False): esercita
    il try/except di _replicate_manifest_chain in main.py."""

    type_name = "fake"

    def replicate_manifest(self, manifest_path):
        raise OSError("NFS irraggiungibile (simulato)")


class TestReplicaManifestNonBloccaIlChiamante(unittest.TestCase):
    def test_backend_che_solleva_non_propaga(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = _bare_app(base)
            manifest = base / 'manifest.log'
            manifest.write_text("riga-1\n")

            try:
                app._replicate_manifest_chain(BackendCheSolleva(), manifest)
            except Exception as e:  # pragma: no cover - non deve accadere
                self.fail(f"_replicate_manifest_chain ha propagato: {e}")


class FakeBackendUnArchivio:
    """Un solo archivio integro, per far arrivare _verify_sample fino alla
    scrittura sul ledger."""

    type_name = "fake"

    def __init__(self, item):
        self._item = item

    def list_archives(self, year=None, month=None):
        return [self._item]


class LedgerCheSolleva:
    def pick_least_recently_verified(self, archive_ids, n):
        return list(archive_ids)[:n]

    def record_verified(self, archive_ids, when_iso):
        raise OSError("disco pieno su /var/lib/wazuh-immutable-store (simulato)")


class TestVerifyIntegritySopravviveAFallimentoLedger(unittest.TestCase):
    """Il ledger è osservabilità per la rotazione, non il dato: un suo
    fallimento non deve impedire a verify_integrity() di scrivere l'esito
    calcolato nello stato (l'evidenza di una verifica riuscita/fallita non
    deve andare persa)."""

    def test_fallimento_scrittura_ledger_non_impedisce_lo_stato_verify(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            app = _bare_app(base)

            name = 'wazuh-logs-2026-01-01.tar.gz'
            archive_path = base / name
            archive_path.write_bytes(b"contenuto-integro")
            checksum = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            (base / f"{name}.sha256").write_text(f"{checksum}  {name}\n")
            item = {
                'name': name, 'locator': str(archive_path), 'size': archive_path.stat().st_size,
                'modified': None, 'has_signature': False, 'has_checksum': True,
            }

            get_backend_originale = main_module.get_backend
            ledger_cls_originale = main_module.VerificationLedger
            main_module.get_backend = lambda storage, retention: FakeBackendUnArchivio(item)
            main_module.VerificationLedger = lambda *a, **k: LedgerCheSolleva()
            try:
                valid = app.verify_integrity()
            except Exception as e:  # pragma: no cover - non deve accadere
                self.fail(f"verify_integrity() ha propagato: {e}")
            finally:
                main_module.get_backend = get_backend_originale
                main_module.VerificationLedger = ledger_cls_originale

            self.assertTrue(valid)  # archivio integro, manifest vuoto -> valido
            stato = app.state.read()
            self.assertEqual(stato['runs']['verify']['outcome'], 'success')
            self.assertEqual(stato['runs']['verify']['archives_checked'], 1)
            self.assertEqual(stato['runs']['verify']['archives_valid'], 1)


if __name__ == '__main__':
    unittest.main()
