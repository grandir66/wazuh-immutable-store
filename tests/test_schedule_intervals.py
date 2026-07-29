"""
verify_interval / retention_interval nello stato osservabile.

Chi osserva lo stato (DA-IPAM) deve poter distinguere "verifica in ritardo"
da "non è ancora il suo turno": senza la cadenza dichiarata deve indovinare.
Stesso formato di archive_interval (già esistente): una stringa, presa dal
modello di config del rispettivo ciclo (IntegrityConfig per verify,
RetentionConfig per retention), non dal cron di systemd.

Il consumatore tratta i campi nuovi come facoltativi: qui si verifica solo
che vengano prodotti con il default giusto quando l'operatore non li
configura esplicitamente, e che restino sovrascrivibili da config.yaml.
"""
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

# PyYAML è una dipendenza di produzione reale (requirements.txt), installata
# sull'host; su questo Mac di sviluppo il Python di sistema non ce l'ha. Il
# codice sotto test (ConfigLoader.to_models) non chiama mai yaml.*: uno stub
# minimo basta a soddisfare il solo `import yaml` in cima a main.py senza
# installare nulla nell'ambiente.
try:
    import yaml  # noqa: F401
except ImportError:
    _yaml_stub = types.ModuleType('yaml')
    _yaml_stub.safe_load = lambda *a, **k: {}
    sys.modules['yaml'] = _yaml_stub

from main import ConfigLoader
from models import IntegrityConfig, RetentionConfig


class TestModelDefaults(unittest.TestCase):
    def test_integrity_config_ha_interval_di_default(self):
        self.assertEqual(IntegrityConfig().interval, 'weekly')

    def test_retention_config_ha_interval_di_default(self):
        self.assertEqual(RetentionConfig().interval, 'daily')

    def test_integrity_config_sample_per_run_di_default_e_10(self):
        self.assertEqual(IntegrityConfig().sample_per_run, 10)


class TestConfigLoaderToModels(unittest.TestCase):
    def _config_minimo(self):
        return {
            'wazuh': {'logs_path': '/var/ossec/logs/archives'},
            'qnap': {'host': 'q', 'export_path': '/e', 'mount_point': '/mnt/q'},
            'archive': {'interval': 'hourly'},
            'gpg': {'enabled': False},
        }

    def test_default_quando_non_configurato(self):
        models = ConfigLoader.to_models(self._config_minimo())
        self.assertEqual(models['integrity'].interval, 'weekly')
        self.assertEqual(models['retention'].interval, 'daily')
        self.assertEqual(models['integrity'].sample_per_run, 10)

    def test_valori_espliciti_in_config_yaml_vengono_rispettati(self):
        config = self._config_minimo()
        config['integrity'] = {'interval': 'every_3_days', 'sample_per_run': 0}
        config['retention'] = {'interval': 'weekly'}

        models = ConfigLoader.to_models(config)

        self.assertEqual(models['integrity'].interval, 'every_3_days')
        self.assertEqual(models['integrity'].sample_per_run, 0)
        self.assertEqual(models['retention'].interval, 'weekly')

    def test_archive_interval_non_cambia_formato(self):
        # Non-regressione: l'aggiunta dei due nuovi campi non deve toccare
        # come viene letto/valorizzato archive.interval.
        models = ConfigLoader.to_models(self._config_minimo())
        self.assertEqual(models['archive'].interval.value, 'hourly')


if __name__ == '__main__':
    unittest.main()
