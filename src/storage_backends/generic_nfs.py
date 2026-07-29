"""
Generic NFS backend.

NFS share senza WORM firmware (TrueNAS share, NetApp non-SnapLock, qualsiasi NFS).
Comportamento simile a QNAP ma:
  - upload sovrascrive (no skip-if-exists, niente WORM lock applicativo)
  - L'immutabilità è demandata a snapshot ZFS / hardlink / chattr esterni
"""

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from models import ArchiveRecord, ArchiveStatus, GenericNFSConfig, RemoteRetention
from transfer import NFSManager
from models import QNAPConfig  # riusa NFSManager esistente

from .base import StorageBackend, StorageBackendError

logger = logging.getLogger(__name__)


class GenericNFSStorageBackend(StorageBackend):
    """Backend NFS generico (no WORM applicativo)."""

    type_name = "generic-nfs"

    def __init__(self, nfs_config: GenericNFSConfig, remote_retention: RemoteRetention):
        self.cfg = nfs_config
        self.retention = remote_retention
        # NFSManager attende QNAPConfig, ne sintetizziamo uno equivalent
        synth = QNAPConfig(
            host=nfs_config.host,
            export_path=nfs_config.export_path,
            mount_point=nfs_config.mount_point,
            nfs_version=nfs_config.nfs_version,
            mount_options=nfs_config.mount_options,
        )
        self._nfs = NFSManager(synth)

    # ---------- Lifecycle ----------

    def connect(self) -> bool:
        return self._nfs.is_mounted() or self._nfs.mount()

    def disconnect(self) -> None:
        return

    def health_check(self) -> Tuple[bool, str]:
        return self._nfs.check_connectivity()

    # ---------- Idempotency ----------

    def archive_exists(self, record: ArchiveRecord) -> bool:
        return self._compute_remote_path(record).exists()

    # ---------- Write ----------

    def upload_archive(self, record: ArchiveRecord) -> str:
        if not self._nfs.is_mounted():
            if not self._nfs.mount():
                raise StorageBackendError("Failed to mount NFS share")

        record.status = ArchiveStatus.TRANSFERRING
        remote_path = self._compute_remote_path(record)

        # Su NFS generico, default è SOVRASCRIVERE.
        # Se vuoi skip-if-exists, usa la flag `idempotent_skip` in config.
        if self.cfg.idempotent_skip and remote_path.exists():
            logger.info(f"Archive exists, idempotent skip (generic-nfs): {remote_path}")
            record.remote_path = remote_path
            record.transferred_at = datetime.now()
            record.status = ArchiveStatus.COMPLETED
            return str(remote_path)

        remote_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Transferring: {record.archive_path} -> {remote_path}")
        shutil.copy2(record.archive_path, remote_path)

        if record.signature_path and record.signature_path.exists():
            shutil.copy2(record.signature_path, remote_path.with_suffix(remote_path.suffix + ".sig"))

        checksum_local = record.archive_path.with_suffix(record.archive_path.suffix + ".sha256")
        if checksum_local.exists():
            shutil.copy2(checksum_local, remote_path.with_suffix(remote_path.suffix + ".sha256"))

        local_size = record.archive_path.stat().st_size
        remote_size = remote_path.stat().st_size
        if local_size != remote_size:
            record.status = ArchiveStatus.FAILED
            raise StorageBackendError(f"Size mismatch: local={local_size} remote={remote_size}")

        record.remote_path = remote_path
        record.transferred_at = datetime.now()
        record.status = ArchiveStatus.COMPLETED
        logger.info(f"Transfer completed: {record.id}")
        return str(remote_path)

    # ---------- Read ----------

    def list_archives(
        self,
        year: Optional[int] = None,
        month: Optional[int] = None,
    ) -> List[dict]:
        if not self._nfs.is_mounted():
            if not self._nfs.mount():
                raise StorageBackendError("Failed to mount NFS share")

        base = self._nfs.mount_point
        if year:
            base = base / str(year)
            if month:
                base = base / f"{month:02d}"

        if not base.exists():
            return []

        items: List[dict] = []
        for path in sorted(base.rglob("*.tar.gz")):
            stat = path.stat()
            items.append(
                {
                    "name": path.name,
                    "locator": str(path),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime),
                    "has_signature": path.with_suffix(path.suffix + ".sig").exists(),
                    "has_checksum": path.with_suffix(path.suffix + ".sha256").exists(),
                }
            )
        return items

    def fetch_archive(self, record_locator: str, dest: Path) -> Path:
        src = Path(record_locator)
        if not src.exists():
            raise StorageBackendError(f"Remote archive not found: {src}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return dest

    # ---------- Integrity ----------

    def replicate_manifest(self, manifest_path: Path) -> bool:
        if not manifest_path.exists():
            logger.warning(f"Manifest non trovato, replica saltata: {manifest_path}")
            return False
        if not self._nfs.is_mounted():
            if not self._nfs.mount():
                logger.warning("Replica manifest saltata: mount NFS non disponibile")
                return False
        try:
            dest = self._nfs.mount_point / "manifests" / manifest_path.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest_path, dest)
            return True
        except OSError as e:
            logger.warning(f"Replica manifest fallita: {e}")
            return False

    # ---------- Operations ----------

    def get_disk_usage(self) -> Optional[dict]:
        return self._nfs.get_disk_usage()

    @property
    def local_mount_point(self) -> Optional[Path]:
        return self._nfs.mount_point

    # ---------- Internal helpers ----------

    def _compute_remote_path(self, record: ArchiveRecord) -> Path:
        base = self._nfs.mount_point
        if self.retention.organize_by_date:
            year = record.created_at.strftime("%Y")
            month = record.created_at.strftime("%m")
            base = base / year / month
        return base / record.archive_path.name
