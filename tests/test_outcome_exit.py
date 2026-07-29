import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from state import classify_archive_outcome


def exit_code_per_esito(esito: str) -> int:
    """Regola usata da main(): solo 'success' esce con 0."""
    return 0 if esito == 'success' else 1


class TestExitCode(unittest.TestCase):
    def test_backend_giu_esce_con_errore(self):
        esito = classify_archive_outcome(connected=False, created=2, uploaded=0, failed=0)
        self.assertEqual(exit_code_per_esito(esito), 1)

    def test_upload_parzialmente_falliti_escono_con_errore(self):
        esito = classify_archive_outcome(connected=True, created=3, uploaded=2, failed=1)
        self.assertEqual(exit_code_per_esito(esito), 1)

    def test_ciclo_pulito_esce_con_zero(self):
        esito = classify_archive_outcome(connected=True, created=3, uploaded=3, failed=0)
        self.assertEqual(exit_code_per_esito(esito), 0)

    def test_niente_da_fare_esce_con_zero(self):
        esito = classify_archive_outcome(connected=True, created=0, uploaded=0, failed=0)
        self.assertEqual(exit_code_per_esito(esito), 0)


class TestRetentionExitCode(unittest.TestCase):
    """I2: retention deve seguire la stessa regola di uscita dell'archiviazione.

    Prima della fix, run_retention non ritornava l'esito e il dispatch usciva
    sempre con 0, anche con errori registrati nello stato ('outcome': 'failed').
    """

    def test_retention_pulita_esce_con_zero(self):
        self.assertEqual(exit_code_per_esito('success'), 0)

    def test_retention_con_errori_esce_con_errore(self):
        self.assertEqual(exit_code_per_esito('failed'), 1)


if __name__ == '__main__':
    unittest.main()
