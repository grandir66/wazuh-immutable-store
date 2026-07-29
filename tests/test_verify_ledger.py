"""
VerificationLedger: registro locale di rotazione per il campionamento della
verifica reale (vedi signer.py::_verify_sample).

7. Il registro delle verifiche deve sopravvivere a una scrittura interrotta:
   nessun file corrotto deve mai essere letto/propagare un'eccezione al giro
   successivo.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from verify_ledger import VerificationLedger


class TestVerificationLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'verify-ledger.json'
        self.ledger = VerificationLedger(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_su_file_assente_ritorna_vuoto(self):
        self.assertEqual(self.ledger.read(), {})

    def test_scrittura_interrotta_non_produce_un_file_illeggibile(self):
        """Simula una scrittura interrotta: contenuto a metà/corrotto sul
        percorso reale del ledger (non nel file temporaneo, che con la
        tecnica atomica non diventa mai il file finale se il processo muore
        prima dell'os.replace). Il giro successivo non deve sollevare né
        leggere dati inventati."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text('{"wazuh-logs-2026-01-01.tar.gz": "2026-01-0')  # troncato

        registro = self.ledger.read()

        self.assertEqual(registro, {})

    def test_pick_dopo_corruzione_riparte_da_zero_priorita(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text('non e json valido')

        scelti = self.ledger.pick_least_recently_verified(
            ['a.tar.gz', 'b.tar.gz', 'c.tar.gz'], 2
        )
        self.assertEqual(len(scelti), 2)

    def test_record_verified_scrive_atomicamente_senza_residui(self):
        self.ledger.record_verified(['a.tar.gz', 'b.tar.gz'], '2026-07-29T00:00:00Z')
        residui = [p.name for p in self.path.parent.iterdir() if p.name != self.path.name]
        self.assertEqual(residui, [])
        stato = json.loads(self.path.read_text())
        self.assertEqual(stato['a.tar.gz'], '2026-07-29T00:00:00Z')

    def test_mai_verificati_hanno_priorita_sui_gia_verificati(self):
        self.ledger.record_verified(['a.tar.gz'], '2026-07-01T00:00:00Z')
        scelti = self.ledger.pick_least_recently_verified(
            ['a.tar.gz', 'b.tar.gz'], 1
        )
        self.assertEqual(scelti, ['b.tar.gz'])

    def test_record_verified_con_lista_vuota_non_scrive_nulla(self):
        self.ledger.record_verified([], '2026-07-29T00:00:00Z')
        self.assertFalse(self.path.exists())

    def test_pick_con_n_zero_o_negativo_ritorna_vuoto(self):
        self.assertEqual(self.ledger.pick_least_recently_verified(['a', 'b'], 0), [])
        self.assertEqual(self.ledger.pick_least_recently_verified(['a', 'b'], -1), [])


if __name__ == '__main__':
    unittest.main()
