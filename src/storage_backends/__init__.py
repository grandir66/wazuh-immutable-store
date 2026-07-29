"""
Storage backends factory.

Punto unico di accesso: `get_backend(storage_config, retention_config)`
ritorna un `StorageBackend` pronto, in base a storage_config.type.

Backend supportati:
  - "qnap-nfs"      → QNAPStorageBackend
  - "generic-nfs"   → GenericNFSStorageBackend  (NFS senza WORM firmware)
  - "minio-s3"      → S3StorageBackend           (MinIO, ma alias di s3-compatible)
  - "s3-compatible" → S3StorageBackend           (MinIO/Wasabi/AWS/R2/B2)
"""

from typing import TYPE_CHECKING

from .base import StorageBackend, StorageBackendError
from .qnap_nfs import QNAPStorageBackend
from .generic_nfs import GenericNFSStorageBackend
from .s3_compat import S3StorageBackend

if TYPE_CHECKING:
    from models import RemoteRetention, StorageConfig


_SUPPORTED_TYPES = ("qnap-nfs", "generic-nfs", "minio-s3", "s3-compatible")


def get_backend(
    storage_config: "StorageConfig",
    remote_retention: "RemoteRetention",
) -> StorageBackend:
    """Factory: ritorna l'istanza di backend in base a storage_config.type.

    Args:
        storage_config: oggetto StorageConfig (vedi models.py)
        remote_retention: politica retention remota (usata da NFS-style backend)

    Raises:
        StorageBackendError: tipo non supportato o config mancante per il tipo.
    """
    btype = storage_config.type

    if btype == "qnap-nfs":
        if storage_config.qnap_nfs is None:
            raise StorageBackendError("storage.type=qnap-nfs ma manca storage.qnap_nfs config")
        return QNAPStorageBackend(storage_config.qnap_nfs, remote_retention)

    if btype == "generic-nfs":
        if storage_config.generic_nfs is None:
            raise StorageBackendError("storage.type=generic-nfs ma manca storage.generic_nfs config")
        return GenericNFSStorageBackend(storage_config.generic_nfs, remote_retention)

    if btype in ("minio-s3", "s3-compatible"):
        if storage_config.s3 is None:
            raise StorageBackendError(f"storage.type={btype} ma manca storage.s3 config")
        return S3StorageBackend(storage_config.s3)

    raise StorageBackendError(
        f"Tipo backend sconosciuto: {btype!r}. Supportati: {_SUPPORTED_TYPES}"
    )


__all__ = [
    "StorageBackend",
    "StorageBackendError",
    "QNAPStorageBackend",
    "GenericNFSStorageBackend",
    "S3StorageBackend",
    "get_backend",
]
