import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from state import (
    STATE_SCHEMA_VERSION, StateStore, classify_archive_outcome, empty_state,
    creation_only_failure, registra_esito_archive_stato,
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


class TestCreationOnlyFailure(unittest.TestCase):
    """I1: creazione archivi fallita con lista risultati vuota -> esito failed.

    Prima della fix, run_archive_cycle inghiottiva ArchiveError con un
    `continue`: con TUTTE le creazioni fallite il ciclo tornava [] uguale al
    caso "niente da archiviare", e il comando usciva/registrava 'success'.
    """

    def test_creazione_fallita_senza_record_e_un_errore(self):
        self.assertTrue(creation_only_failure(0, 3))

    def test_niente_da_archiviare_non_e_un_errore(self):
        self.assertFalse(creation_only_failure(0, 0))

    def test_almeno_un_record_creato_non_e_una_creation_only_failure(self):
        # Con almeno un archivio creato l'esito lo decide classify_archive_outcome
        # (via upload falliti/parziali), non questa funzione.
        self.assertFalse(creation_only_failure(2, 1))


class TestRegistraEsitoArchiveStatoDryRun(unittest.TestCase):
    """I3: --dry-run non deve alterare lo stato reale."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.json'
        self.store = StateStore(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_non_altera_uno_stato_failed_precedente(self):
        # Un ciclo reale precedente è fallito: lo stato lo dice.
        self.store.update_section('archive', {
            'outcome': 'failed', 'uploaded': 0, 'error': 'NAS irraggiungibile',
        })
        prima = self.path.read_text()

        # Un operatore lancia un dry-run: non deve cancellare l'allarme.
        registra_esito_archive_stato(
            self.store, True, '2026-07-29T00:00:00Z', 'success', 3, 0, 0, 0, None,
        )

        dopo = self.path.read_text()
        self.assertEqual(prima, dopo, "il dry-run ha modificato il file di stato")
        stato = json.loads(dopo)
        self.assertEqual(stato['runs']['archive']['outcome'], 'failed')

    def test_senza_dry_run_scrive_normalmente(self):
        registra_esito_archive_stato(
            self.store, False, '2026-07-29T00:00:00Z', 'success', 3, 3, 0, 1024, None,
        )
        stato = self.store.read()
        self.assertEqual(stato['runs']['archive']['outcome'], 'success')
        self.assertEqual(stato['runs']['archive']['uploaded'], 3)


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
