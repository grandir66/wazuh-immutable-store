import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from state import (
    STATE_SCHEMA_VERSION, StateStore, classify_archive_outcome, empty_state,
)


class TestClassifyOutcome(unittest.TestCase):
    def test_backend_irraggiungibile(self):
        self.assertEqual(classify_archive_outcome(False, 3, 0, 0), 'failed')

    def test_nulla_da_archiviare(self):
        self.assertEqual(classify_archive_outcome(True, 0, 0, 0), 'success')

    def test_tutto_riuscito(self):
        self.assertEqual(classify_archive_outcome(True, 3, 3, 0), 'success')

    def test_parziale(self):
        self.assertEqual(classify_archive_outcome(True, 3, 2, 1), 'partial')

    def test_tutti_falliti(self):
        self.assertEqual(classify_archive_outcome(True, 3, 0, 3), 'failed')


class TestStateStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.json'
        self.store = StateStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_su_file_assente_ritorna_scheletro(self):
        stato = self.store.read()
        self.assertEqual(stato['schema_version'], STATE_SCHEMA_VERSION)
        self.assertEqual(stato['runs']['archive']['outcome'], 'never')

    def test_read_su_file_corrotto_non_solleva(self):
        self.path.write_text('{ questo non è json')
        stato = self.store.read()
        self.assertEqual(stato['runs']['archive']['outcome'], 'never')

    def test_update_section_persiste_e_non_perde_il_resto(self):
        self.store.update_section('archive', {'outcome': 'success', 'uploaded': 2})
        self.store.update_section('verify', {'outcome': 'success'})
        stato = json.loads(self.path.read_text())
        self.assertEqual(stato['runs']['archive']['uploaded'], 2)
        self.assertEqual(stato['runs']['verify']['outcome'], 'success')

    def test_scrittura_atomica_niente_file_temporanei_residui(self):
        self.store.update_section('archive', {'outcome': 'success'})
        residui = [p.name for p in self.path.parent.iterdir() if p.name != 'state.json']
        self.assertEqual(residui, [])

    def test_update_live_scrive_le_sezioni_vive(self):
        self.store.update_live(
            backend={'type': 'qnap-nfs', 'reachable': True},
            local_disk={'use_percent': 57},
            archives={'total': 512},
            schedule={'archive_interval': 'hourly'},
        )
        stato = self.store.read()
        self.assertTrue(stato['backend']['reachable'])
        self.assertEqual(stato['local_disk']['use_percent'], 57)
        self.assertEqual(stato['archives']['total'], 512)

    def test_generated_at_viene_aggiornato(self):
        self.store.update_section('archive', {'outcome': 'success'})
        stato = self.store.read()
        self.assertTrue(stato['generated_at'].endswith('Z'))

    def test_empty_state_contiene_le_tre_sezioni_run(self):
        stato = empty_state('srv-test')
        self.assertEqual(set(stato['runs'].keys()), {'archive', 'retention', 'verify'})
        self.assertEqual(stato['host'], 'srv-test')


if __name__ == '__main__':
    unittest.main()
