"""
IntegrityManager.get_manifest_entries(): un manifest illeggibile/corrotto
deve essere un caso DISTINTO da "manifest vuoto/assente".

Prima di questa modifica un errore di parsing su una riga (bit rot,
scrittura interrotta) veniva inghiottito internamente e la funzione tornava
la lista PARZIALE raccolta fino a quel punto -- [] se l'errore era sulla
prima riga, indistinguibile da "il manifest è vergine, mai scritto nulla".
Il chiamante che usa questa funzione come prova di "quanti archivi
dovrebbero esserci" (SigningManager._verify_sample, vedi
test_verify_sample.py) trattava quindi un manifest corrotto come vergine.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from models import IntegrityConfig
from signer import IntegrityManager, ManifestCorruptedError


def _manager(base: Path) -> IntegrityManager:
    return IntegrityManager(IntegrityConfig(), base / 'manifests')


class TestGetManifestEntriesCasiSani(unittest.TestCase):
    def test_file_assente_ritorna_vuoto_senza_sollevare(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            self.assertFalse(mgr.manifest_file.exists())
            self.assertEqual(mgr.get_manifest_entries(), [])

    def test_file_esistente_ma_vuoto_ritorna_vuoto_senza_sollevare(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text("")
            self.assertEqual(mgr.get_manifest_entries(), [])

    def test_righe_valide_vengono_interpretate(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text(
                "deadbeef  wazuh-logs-2026-01-01.tar.gz  100  "
                "2026-01-01T00:00:00+00:00  PREV:GENESIS\n"
            )
            entries = mgr.get_manifest_entries()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].size, 100)


class TestGetManifestEntriesCasiCorrotti(unittest.TestCase):
    def test_size_non_numerico_solleva_manifest_corrupted_error(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text(
                "deadbeef  wazuh-logs-2026-01-01.tar.gz  NOTANUMBER  "
                "2026-01-01T00:00:00+00:00  PREV:GENESIS\n"
            )
            with self.assertRaises(ManifestCorruptedError):
                mgr.get_manifest_entries()

    def test_data_non_iso_solleva_manifest_corrupted_error(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text(
                "deadbeef  wazuh-logs-2026-01-01.tar.gz  100  "
                "non-e-una-data  PREV:GENESIS\n"
            )
            with self.assertRaises(ManifestCorruptedError):
                mgr.get_manifest_entries()

    def test_riga_con_troppi_pochi_campi_solleva_manifest_corrupted_error(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text("riga-troncata-a-meta\n")
            with self.assertRaises(ManifestCorruptedError):
                mgr.get_manifest_entries()

    def test_errore_sulla_seconda_riga_non_torna_silenziosamente_la_prima(self):
        with _TmpDir() as tmp:
            mgr = _manager(tmp)
            mgr.manifest_file.write_text(
                "deadbeef  wazuh-logs-2026-01-01.tar.gz  100  "
                "2026-01-01T00:00:00+00:00  PREV:GENESIS\n"
                "cafebabe  wazuh-logs-2026-01-02.tar.gz  NOTANUMBER  "
                "2026-01-02T00:00:00+00:00  PREV:deadbeef\n"
            )
            with self.assertRaises(ManifestCorruptedError):
                mgr.get_manifest_entries()


class _TmpDir:
    """Piccolo helper: crea/pulisce una directory temporanea e ritorna la
    sua Path (evita di importare tempfile.TemporaryDirectory in ogni test)."""

    def __enter__(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        return Path(self._tmp.name)

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False


if __name__ == '__main__':
    unittest.main()
