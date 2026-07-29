"""
Storage backend abstract base class.

Ogni backend (QNAP NFS, MinIO/Wasabi S3, NFS generico, ...) implementa
questa interfaccia. Il resto dell'applicazione parla SOLO con questo
contratto: nessun if/elif su qnap vs s3 sparso in archiver/main/cleaner.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from models import ArchiveRecord


class StorageBackendError(Exception):
    """Errore di un backend storage (upload, mount, auth, ecc.)."""


class StorageBackend(ABC):
    """Contratto di un backend di archiviazione immutabile."""

    # Identificatore breve usato in log/manifest: "qnap-nfs" | "minio-s3" | ...
    type_name: str = "abstract"

    # ---------- Lifecycle ----------

    @abstractmethod
    def connect(self) -> bool:
        """Mount NFS / verifica S3 / autenticazione. Idempotente."""

    @abstractmethod
    def disconnect(self) -> None:
        """Best-effort cleanup. Può essere no-op."""

    @abstractmethod
    def health_check(self) -> Tuple[bool, str]:
        """(reachable, messaggio leggibile). Mai solleva eccezione."""

    # ---------- Idempotency ----------

    @abstractmethod
    def archive_exists(self, record: ArchiveRecord) -> bool:
        """True se l'archivio è già presente sul backend remoto.

        Usato per skip idempotente prima di upload (importante per WORM
        compliance: lì NON si può sovrascrivere)."""

    # ---------- Write ----------

    @abstractmethod
    def upload_archive(self, record: ArchiveRecord) -> str:
        """Carica tar.gz + .sig + .sha256 sul backend.

        Implementazione tipica:
          1. compute remote locator dal record (date layout, prefix, ...)
          2. caricare tar.gz, .sig, .sha256 (le ultime se esistono)
          3. (compliance backends) settare object lock / retention
          4. record.remote_path = <locator come Path o stringa>
          5. record.transferred_at = datetime.now()
          6. record.status = COMPLETED

        Ritorna: locator string (per logging).
        """

    # ---------- Read ----------

    @abstractmethod
    def list_archives(
        self,
        year: Optional[int] = None,
        month: Optional[int] = None,
    ) -> List[dict]:
        """Lista archivi presenti.

        Ogni elemento: {name, locator, size, modified, has_signature, has_checksum}.
        """

    @abstractmethod
    def fetch_archive(self, record_locator: str, dest: Path) -> Path:
        """Download del file remoto verso un path locale (per recovery)."""

    # ---------- Operations ----------

    @abstractmethod
    def get_disk_usage(self) -> Optional[dict]:
        """{size, used, available, use_percent} o None se non disponibile."""

    # ---------- Integrity ----------

    def replicate_manifest(self, manifest_path: Path) -> bool:
        """Copia `manifest_path` sullo storage immutabile, in una posizione
        fissa e nota (NON nel layout per-anno degli archivi).

        Serve a far sopravvivere la catena dei manifest alla perdita della
        directory temporanea locale dove viene scritta (unica copia, oggi):
        per questo scrive sempre sullo STESSO percorso remoto, sovrascrivendolo
        (idempotente) — mai altri file.

        Best-effort: ritorna True/False, non solleva mai. Il chiamante
        (`run_archive`) tratta un fallimento come un warning da loggare, non
        come motivo per far fallire un ciclo di archiviazione già riuscito.

        Implementazione di default: no-op che ritorna False, per i backend
        che non la supportano ancora (object storage) — dichiarano così
        esplicitamente di non farlo, invece di fallire in modo oscuro o
        silenzioso più a valle.
        """
        return False

    # ---------- Helpers (default impl) ----------

    @property
    def local_mount_point(self) -> Optional[Path]:
        """Per backend filesystem (NFS/QNAP) ritorna il mount point locale.

        Per object storage ritorna None — il cleaner deve usare
        archive_exists() invece di scanning filesystem."""
        return None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.type_name}>"
