"""
QNAP NFS backend.

Wrap della logica esistente in transfer.py (NFSManager + ArchiveTransfer),
ridotta a un'unica classe che implementa StorageBackend.
Comportamento funzionale identico alla versione precedente.
"""

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from models import ArchiveRecord, ArchiveStatus, QNAPConfig, RemoteRetention
from transfer import NFSManager

from .base import StorageBackend, StorageBackendError

logger = logging.getLogger(__name__)


class QNAPStorageBackend(StorageBackend):
    """Backend QNAP via NFS mount con WORM firmware."""

    type_name = "qnap-nfs"

    def __init__(self, qnap_config: QNAPConfig, remote_retention: RemoteRetention):
        self.qnap = qnap_config
        self.retention = remote_retention
        self._nfs = NFSManager(qnap_config)

    # ---------- Lifecycle ----------

    def connect(self) -> bool:
        if self._nfs.is_mounted():
            return True
        return self._nfs.mount()

    def disconnect(self) -> None:
        # Non smontiamo: il mount viene mantenuto tra cicli (più veloce).
        return

    def health_check(self) -> Tuple[bool, str]:
        return self._nfs.check_connectivity()

    # ---------- Idempotency ----------

    def archive_exists(self, record: ArchiveRecord) -> bool:
        remote_path = self._compute_remote_path(record)
        return remote_path.exists()

    # ---------- Write ----------

    def upload_archive(self, record: ArchiveRecord) -> str:
        if not self._nfs.is_mounted():
            if not self._nfs.mount():
                raise StorageBackendError("Failed to mount NFS share")

        record.status = ArchiveStatus.TRANSFERRING
        remote_path = self._compute_remote_path(record)

        # WORM: il file potrebbe già esserci (idempotent skip)
        if remote_path.exists():
            logger.info(f"Archive already exists on WORM volume, skipping: {remote_path}")
            record.remote_path = remote_path
            record.transferred_at = datetime.now()
            record.status = ArchiveStatus.COMPLETED
            return str(remote_path)

        remote_dir = remote_path.parent
        remote_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Transferring: {record.archive_path} -> {remote_path}")
        self._copy_file(record.archive_path, remote_path)

        # Signature
        if record.signature_path and record.signature_path.exists():
            sig_remote = remote_path.with_suffix(remote_path.suffix + ".sig")
            self._copy_file(record.signature_path, sig_remote)

        # Checksum
        checksum_local = record.archive_path.with_suffix(
            record.archive_path.suffix + ".sha256"
        )
        if checksum_local.exists():
            checksum_remote = remote_path.with_suffix(remote_path.suffix + ".sha256")
            self._copy_file(checksum_local, checksum_remote)

        if not self._verify_size(record.archive_path, remote_path):
            record.status = ArchiveStatus.FAILED
            raise StorageBackendError("Size mismatch after transfer")

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

    def _copy_file(self, source: Path, destination: Path) -> None:
        """Copia con progress logging per file grandi (riusa logica esistente)."""
        file_size = source.stat().st_size
        chunk_size = 64 * 1024 * 1024  # 64 MiB

        if file_size < chunk_size:
            shutil.copy2(source, destination)
            return

        copied = 0
        last_percent = 0
        with open(source, "rb") as src, open(destination, "wb") as dst:
            while True:
                chunk = src.read(chunk_size)
                if not chunk:
                    break
                dst.write(chunk)
                copied += len(chunk)
                percent = int((copied / file_size) * 100)
                if percent >= last_percent + 10:
                    logger.info(f"Transfer progress: {percent}%")
                    last_percent = percent
        shutil.copystat(source, destination)

    def _verify_size(self, local: Path, remote: Path) -> bool:
        if not remote.exists():
            logger.error(f"Remote file does not exist: {remote}")
            return False
        local_size = local.stat().st_size
        remote_size = remote.stat().st_size
        if local_size != remote_size:
            logger.error(f"Size mismatch: local={local_size}, remote={remote_size}")
            return False
        return True
