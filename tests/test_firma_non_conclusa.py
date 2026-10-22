"""
Una verifica GPG che va oltre il tempo non è una firma non valida.

DTS, 22/10/2026: la verify settimanale ha segnato 21 archivi su 50 come «firma GPG non
valida». Erano tutti timeout: gpg aveva 60 secondi fissi per archivi da 2,8-4,3 GB riletti
dal QNAP via NFS, e il timeout tornava False come una firma sbagliata. I checksum dei 50
archivi erano tutti giusti. Chi legge «non valida» pensa a una manomissione.

Due regole: il tempo concesso a gpg cresce con la dimensione del file; un timeout è un
terzo esito («non conclusa»), che resta un errore della verifica ma non dice il falso.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from models import GPGConfig
import signer
from signer import GPGSigner


def _firmatario():
    with mock.patch.object(GPGSigner, '_verify_gpg_setup'):
        return GPGSigner(GPGConfig(enabled=True, key_id='ABCDEF', gpg_home=None))


class TestFirmaNonConclusa(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.archivio = Path(self.tmp.name) / 'wazuh-logs.tar.gz'
        self.archivio.write_bytes(b'x' * 10)
        self.firma = Path(self.tmp.name) / 'wazuh-logs.tar.gz.sig'
        self.firma.write_bytes(b'sig')

    def tearDown(self):
        self.tmp.cleanup()

    def test_un_timeout_e_non_conclusa_non_non_valida(self):
        g = _firmatario()
        with mock.patch.object(signer.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired(cmd='gpg', timeout=1)):
            self.assertEqual(g.verify_signature_esito(self.archivio, self.firma), 'non conclusa')
            self.assertFalse(g.verify_signature(self.archivio, self.firma))

    def test_firma_sbagliata_resta_non_valida(self):
        g = _firmatario()
        fallita = subprocess.CompletedProcess(args=[], returncode=1, stdout='', stderr='BAD signature')
        with mock.patch.object(signer.subprocess, 'run', return_value=fallita):
            self.assertEqual(g.verify_signature_esito(self.archivio, self.firma), 'non valida')

    def test_il_tempo_cresce_con_la_dimensione(self):
        quattro_gb = 4 * 1024 ** 3
        self.assertGreaterEqual(signer.tempo_verifica_gpg(quattro_gb), 480)
        self.assertGreaterEqual(signer.tempo_verifica_gpg(10), 300)

    def test_il_campione_dice_non_conclusa(self):
        """Il messaggio nello stato della verify distingue il timeout."""
        g = _firmatario()
        manager = signer.SigningManager.__new__(signer.SigningManager)
        manager.gpg_signer = g
        manager.integrity_manager = mock.Mock(algorithm='sha256')
        manager.integrity_manager.verify_checksum_file.return_value = True
        Path(str(self.archivio) + '.sha256').write_text('x')
        with mock.patch.object(signer.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired(cmd='gpg', timeout=1)):
            ok, errori = manager._verify_single_archive({'locator': str(self.archivio)})
        self.assertFalse(ok)
        self.assertEqual(len(errori), 1)
        self.assertIn('non conclusa', errori[0])
        self.assertNotIn('non valida', errori[0])


if __name__ == '__main__':
    unittest.main()
