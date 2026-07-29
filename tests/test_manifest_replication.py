"""
Replica del manifest.log sullo storage immutabile (StorageBackend.replicate_manifest).

La catena dei manifest vive oggi SOLO su disco locale (temp_dir), fuori dallo
storage immutabile: una pulizia di quella directory cancella l'unica prova di
integrità esistente (è già successo). Dopo un ciclo di archiviazione riuscito
il manifest va copiato sullo storage tramite il backend, sovrascrivendo solo
quel file dedicato.

Niente NFS reale: si inietta un doppio al posto di `NFSManager` (stessa idea
usata per i backend nel resto della suite: mount_point è una directory
temporanea, is_mounted() sempre True).
"""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from models import GenericNFSConfig, QNAPConfig, RemoteRetention
from storage_backends.base import StorageBackend
from storage_backends.generic_nfs import GenericNFSStorageBackend
from storage_backends.qnap_nfs import QNAPStorageBackend


class _FakeNFS:
    """Sostituisce NFSManager: niente subprocess, niente mount reale."""

    def __init__(self, mount_point: Path):
        self.mount_point = mount_point

    def is_mounted(self) -> bool:
        return True

    def mount(self) -> bool:
        return True


def _qnap_backend(mount_point: Path) -> QNAPStorageBackend:
    cfg = QNAPConfig(host='qnap.local', export_path='/export', mount_point=mount_point)
    backend = QNAPStorageBackend(cfg, RemoteRetention())
    backend._nfs = _FakeNFS(mount_point)
    return backend


def _generic_backend(mount_point: Path) -> GenericNFSStorageBackend:
    cfg = GenericNFSConfig(host='nfs.local', export_path='/export', mount_point=mount_point)
    backend = GenericNFSStorageBackend(cfg, RemoteRetention())
    backend._nfs = _FakeNFS(mount_point)
    return backend


class TestReplicateManifestDefault(unittest.TestCase):
    """Il default astratto (StorageBackend) è un no-op che ritorna False:
    i backend che non lo implementano lo dichiarano invece di fallire in modo
    oscuro."""

    def test_default_ritorna_false(self):
        class Nudo(StorageBackend):
            type_name = "nudo"

            def connect(self): return True
            def disconnect(self): return None
            def health_check(self): return True, "ok"
            def archive_exists(self, record): return False
            def upload_archive(self, record): return ""
            def list_archives(self, year=None, month=None): return []
            def fetch_archive(self, record_locator, dest): return dest
            def get_disk_usage(self): return None

        self.assertFalse(Nudo().replicate_manifest(Path('/tmp/nope.log')))


class TestReplicateManifestQnap(unittest.TestCase):
    def test_copia_il_manifest_e_ritorna_true(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / 'mount'
            mount.mkdir()
            manifest = root / 'manifest.log'
            manifest.write_text("riga-1\nriga-2\n")

            backend = _qnap_backend(mount)
            ok = backend.replicate_manifest(manifest)

            self.assertTrue(ok)
            copia = mount / 'manifests' / 'manifest.log'
            self.assertTrue(copia.exists())
            self.assertEqual(copia.read_text(), manifest.read_text())

    def test_sovrascrive_solo_il_file_dedicato_niente_altro(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / 'mount'
            mount.mkdir()
            (mount / '2026').mkdir()
            preesistente = mount / '2026' / 'wazuh-logs-2026-01-01.tar.gz'
            preesistente.write_bytes(b"archivio preesistente")

            manifest = root / 'manifest.log'
            manifest.write_text("v1\n")
            backend = _qnap_backend(mount)
            backend.replicate_manifest(manifest)

            # Una seconda replica con contenuto diverso sovrascrive SOLO il manifest.
            manifest.write_text("v1\nv2\n")
            backend.replicate_manifest(manifest)

            self.assertEqual((mount / 'manifests' / 'manifest.log').read_text(), "v1\nv2\n")
            self.assertEqual(preesistente.read_bytes(), b"archivio preesistente")

    def test_manifest_assente_ritorna_false_senza_sollevare(self):
        with TemporaryDirectory() as tmp:
            mount = Path(tmp) / 'mount'
            mount.mkdir()
            backend = _qnap_backend(mount)
            self.assertFalse(backend.replicate_manifest(Path(tmp) / 'non-esiste.log'))


class TestReplicateManifestGenericNfs(unittest.TestCase):
    def test_copia_il_manifest_e_ritorna_true(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / 'mount'
            mount.mkdir()
            manifest = root / 'manifest.log'
            manifest.write_text("riga-1\n")

            backend = _generic_backend(mount)
            ok = backend.replicate_manifest(manifest)

            self.assertTrue(ok)
            self.assertTrue((mount / 'manifests' / 'manifest.log').exists())


if __name__ == '__main__':
    unittest.main()
