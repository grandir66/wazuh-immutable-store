"""
C1: le unit systemd che girano da timer devono poter scrivere lo stato.

Con ProtectSystem=strict, senza ReadWritePaths=/var/lib/wazuh-immutable-store
StateStore._write fallisce con filesystem in sola lettura; l'eccezione viene
inghiottita come semplice warning da _registra_esito_archive (e analoghi), e
runs.archive/retention/verify restano per sempre 'never' mentre il timer di
refresh (non sandboxato) continua ad aggiornare generated_at, mascherando la
stalezza. Una prova manuale da shell non lo scoprirebbe: fuori dalla sandbox
funziona sempre.

Questo test non può verificare il comportamento reale di systemd (serve una
macchina con systemd), ma impedisce la regressione più probabile: che qualcuno
tolga di nuovo la riga ReadWritePaths.
"""
import unittest
from pathlib import Path

SYSTEMD_DIR = Path(__file__).resolve().parent.parent / 'systemd'
STATE_DIR = '/var/lib/wazuh-immutable-store'

# Le tre unit oneshot che il codice usa per scrivere runs.archive/retention/verify.
# wazuh-immutable-store-refresh.service NON è sandboxato (nessun ProtectSystem)
# e wazuh-immutable-store-status.service è il server di lettura: non incluse.
UNIT_CHE_SCRIVONO_LO_STATO = [
    'wazuh-immutable-store.service',
    'wazuh-immutable-store-retention.service',
    'wazuh-immutable-store-verify.service',
]


class TestSystemdReadWritePaths(unittest.TestCase):
    def test_le_tre_unit_consentono_la_scrittura_dello_stato(self):
        for nome in UNIT_CHE_SCRIVONO_LO_STATO:
            testo = (SYSTEMD_DIR / nome).read_text()
            self.assertIn(
                'ReadWritePaths=%s' % STATE_DIR,
                testo,
                "%s non consente la scrittura di %s: con ProtectSystem=strict "
                "lo StateStore fallisce silenziosamente quando il ciclo gira "
                "da systemd (timer)." % (nome, STATE_DIR)
            )

    def test_le_unit_mantengono_ancora_protectsystem_strict(self):
        # Verifica di non aver rotto l'hardening esistente aggiungendo la riga.
        for nome in UNIT_CHE_SCRIVONO_LO_STATO:
            testo = (SYSTEMD_DIR / nome).read_text()
            self.assertIn('ProtectSystem=strict', testo)

    def test_le_tre_unit_possono_scrivere_nella_home_di_gpg(self):
        """DTS, 18/10/2026: la verifica settimanale falliva con «GPG key not found» dal 20/09.

        Con ProtectHome=read-only e /root/.gnupg non scrivibile, gpg non crea il file di lock né
        il socket dell'agente: «can't connect to the gpg-agent: Read-only file system», la chiave
        segreta non si vede e SigningManager si ferma. Sul server un drop-in metteva perfino
        ReadOnlyPaths=/root/.gnupg, che vince sul ReadWritePaths. Da shell funziona sempre.
        """
        for nome in UNIT_CHE_SCRIVONO_LO_STATO:
            testo = (SYSTEMD_DIR / nome).read_text()
            self.assertIn('ReadWritePaths=/root/.gnupg', testo,
                          "%s: gpg non può avviare l'agente in /root/.gnupg" % nome)
            self.assertNotIn('ReadOnlyPaths=/root/.gnupg', testo,
                             "%s: ReadOnlyPaths su /root/.gnupg vince sul ReadWritePaths" % nome)


if __name__ == '__main__':
    unittest.main()
