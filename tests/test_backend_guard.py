import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from models import StorageConfig, QNAPConfig, GenericNFSConfig
from storage_backends import get_backend, StorageBackendError


class TestBackendGuard(unittest.TestCase):
    def test_qnap_e_consentito(self):
        cfg = StorageConfig(
            type='qnap-nfs',
            qnap_nfs=QNAPConfig(
                host='qnap.local',
                export_path='/export/wazuh',
                mount_point=Path('/mnt/qnap'),
            ),
        )
        backend = get_backend(cfg, None)
        self.assertEqual(backend.type_name, 'qnap-nfs')

    def test_generic_nfs_e_bloccato(self):
        cfg = StorageConfig(
            type='generic-nfs',
            generic_nfs=GenericNFSConfig(
                host='nfs.local',
                export_path='/export/wazuh',
                mount_point=Path('/mnt/nfs'),
            ),
        )
        with self.assertRaises(StorageBackendError) as ctx:
            get_backend(cfg, None)
        self.assertIn('non è pronto', str(ctx.exception))

    def test_s3_e_bloccato(self):
        cfg = StorageConfig(type='s3-compatible')
        with self.assertRaises(StorageBackendError) as ctx:
            get_backend(cfg, None)
        self.assertIn('non è pronto', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
