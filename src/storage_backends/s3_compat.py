"""
S3-compatible backend (MinIO, Wasabi, AWS S3, Cloudflare R2, Backblaze B2).

Stesso codice per tutti: cambia solo endpoint/credentials/verify_tls
in config. Object Lock Compliance/Governance opzionale.
"""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from models import ArchiveRecord, ArchiveStatus, S3Config

from .base import StorageBackend, StorageBackendError

logger = logging.getLogger(__name__)


class S3StorageBackend(StorageBackend):
    """Backend S3-compatibile con opzionale Object Lock retention."""

    type_name = "s3-compatible"

    def __init__(self, s3_config: S3Config):
        self.cfg = s3_config
        self._client = None
        self._head_cache: dict = {}  # key -> bool, popolato per ottimizzare cleaner

    # ---------- Lazy boto3 init ----------

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.client import Config as BotoConfig
        except ImportError as e:
            raise StorageBackendError(
                "boto3 non installato. `pip install boto3` per usare backend S3."
            ) from e

        self._client = boto3.client(
            "s3",
            endpoint_url=self.cfg.endpoint,
            aws_access_key_id=self.cfg.access_key,
            aws_secret_access_key=self.cfg.secret_key,
            region_name=self.cfg.region,
            verify=self.cfg.verify_tls,
            config=BotoConfig(
                signature_version="s3v4",
                s3={"addressing_style": "path" if self.cfg.path_style else "virtual"},
                connect_timeout=15,
                read_timeout=300,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )
        return self._client

    # ---------- Lifecycle ----------

    def connect(self) -> bool:
        try:
            client = self._ensure_client()
            client.head_bucket(Bucket=self.cfg.bucket)
            return True
        except Exception as e:
            logger.error(f"S3 connect failed: {e}")
            return False

    def disconnect(self) -> None:
        self._client = None
        self._head_cache.clear()

    def health_check(self) -> Tuple[bool, str]:
        try:
            client = self._ensure_client()
            client.head_bucket(Bucket=self.cfg.bucket)
            return True, f"Connected to {self.cfg.endpoint}, bucket {self.cfg.bucket} accessible"
        except Exception as e:
            return False, f"S3 health check failed: {e}"

    # ---------- Idempotency ----------

    def archive_exists(self, record: ArchiveRecord) -> bool:
        key = self._compute_key(record)
        if key in self._head_cache:
            return self._head_cache[key]
        exists = self._head_object(key)
        self._head_cache[key] = exists
        return exists

    # ---------- Write ----------

    def upload_archive(self, record: ArchiveRecord) -> str:
        client = self._ensure_client()
        record.status = ArchiveStatus.TRANSFERRING

        key = self._compute_key(record)

        if self._head_object(key):
            logger.info(f"Archive already on S3 (idempotent skip): s3://{self.cfg.bucket}/{key}")
            record.remote_path = Path(f"s3://{self.cfg.bucket}/{key}")
            record.transferred_at = datetime.now()
            record.status = ArchiveStatus.COMPLETED
            return f"s3://{self.cfg.bucket}/{key}"

        extra = self._build_object_lock_params()

        logger.info(f"S3 upload: {record.archive_path} -> s3://{self.cfg.bucket}/{key}")
        try:
            client.upload_file(
                Filename=str(record.archive_path),
                Bucket=self.cfg.bucket,
                Key=key,
                ExtraArgs=extra if extra else None,
            )

            # Signature
            if record.signature_path and record.signature_path.exists():
                sig_key = key + ".sig"
                client.upload_file(
                    Filename=str(record.signature_path),
                    Bucket=self.cfg.bucket,
                    Key=sig_key,
                    ExtraArgs=extra if extra else None,
                )

            # Checksum
            checksum_local = record.archive_path.with_suffix(
                record.archive_path.suffix + ".sha256"
            )
            if checksum_local.exists():
                client.upload_file(
                    Filename=str(checksum_local),
                    Bucket=self.cfg.bucket,
                    Key=key + ".sha256",
                    ExtraArgs=extra if extra else None,
                )
        except Exception as e:
            record.status = ArchiveStatus.FAILED
            raise StorageBackendError(f"S3 upload failed: {e}") from e

        if not self._verify_size(record.archive_path, key):
            record.status = ArchiveStatus.FAILED
            raise StorageBackendError("Size mismatch after S3 upload")

        record.remote_path = Path(f"s3://{self.cfg.bucket}/{key}")
        record.transferred_at = datetime.now()
        record.status = ArchiveStatus.COMPLETED
        self._head_cache[key] = True
        logger.info(f"S3 upload completed: {record.id}")
        return f"s3://{self.cfg.bucket}/{key}"

    # ---------- Read ----------

    def list_archives(
        self,
        year: Optional[int] = None,
        month: Optional[int] = None,
    ) -> List[dict]:
        client = self._ensure_client()
        prefix = self._compute_prefix(year, month)

        items: List[dict] = []
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.cfg.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                # Skip sidecar files dalla lista principale; arricchiamo l'archive dopo
                if key.endswith(".tar.gz"):
                    items.append(
                        {
                            "name": key.rsplit("/", 1)[-1],
                            "locator": f"s3://{self.cfg.bucket}/{key}",
                            "size": obj["Size"],
                            "modified": obj["LastModified"],
                            "has_signature": self._head_object(key + ".sig"),
                            "has_checksum": self._head_object(key + ".sha256"),
                        }
                    )
        return items

    def fetch_archive(self, record_locator: str, dest: Path) -> Path:
        client = self._ensure_client()
        # record_locator: "s3://bucket/key" o solo "key"
        if record_locator.startswith("s3://"):
            _, _, rest = record_locator.partition("s3://")
            _, _, key = rest.partition("/")
        else:
            key = record_locator

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            client.download_file(Bucket=self.cfg.bucket, Key=key, Filename=str(dest))
        except Exception as e:
            raise StorageBackendError(f"S3 download failed for {key}: {e}") from e
        return dest

    # ---------- Operations ----------

    def get_disk_usage(self) -> Optional[dict]:
        """S3 non ha disk usage canonico. Calcoliamo total bytes nel bucket."""
        client = self._ensure_client()
        total_bytes = 0
        total_objects = 0
        try:
            paginator = client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.cfg.bucket):
                for obj in page.get("Contents", []):
                    total_bytes += obj["Size"]
                    total_objects += 1
        except Exception as e:
            logger.warning(f"S3 disk usage scan failed: {e}")
            return None

        return {
            "filesystem": f"s3://{self.cfg.bucket}",
            "size": "n/a (object storage)",
            "used": _human_bytes(total_bytes),
            "available": "n/a (cloud)",
            "use_percent": "n/a",
            "total_objects": total_objects,
        }

    # local_mount_point resta None (default) — i path locali non esistono su S3

    # ---------- Internal helpers ----------

    def _compute_key(self, record: ArchiveRecord) -> str:
        """Calcola la key S3. Layout: [prefix/]YYYY/MM/filename.tar.gz se organize_by_date."""
        parts = []
        if self.cfg.key_prefix:
            parts.append(self.cfg.key_prefix.strip("/"))
        if self.cfg.organize_by_date:
            parts.append(record.created_at.strftime("%Y"))
            parts.append(record.created_at.strftime("%m"))
        parts.append(record.archive_path.name)
        return "/".join(p for p in parts if p)

    def _compute_prefix(self, year: Optional[int], month: Optional[int]) -> str:
        parts = []
        if self.cfg.key_prefix:
            parts.append(self.cfg.key_prefix.strip("/"))
        if year is not None:
            parts.append(f"{year:04d}")
            if month is not None:
                parts.append(f"{month:02d}")
        prefix = "/".join(parts)
        return prefix + "/" if prefix else ""

    def _head_object(self, key: str) -> bool:
        try:
            client = self._ensure_client()
            client.head_object(Bucket=self.cfg.bucket, Key=key)
            return True
        except Exception:
            return False

    def _verify_size(self, local: Path, key: str) -> bool:
        try:
            client = self._ensure_client()
            head = client.head_object(Bucket=self.cfg.bucket, Key=key)
            remote_size = head["ContentLength"]
            local_size = local.stat().st_size
            if local_size != remote_size:
                logger.error(f"S3 size mismatch: local={local_size} remote={remote_size}")
                return False
            return True
        except Exception as e:
            logger.error(f"S3 head_object verify failed: {e}")
            return False

    def _build_object_lock_params(self) -> dict:
        """Costruisce gli ExtraArgs per Object Lock se configurato."""
        if not self.cfg.use_object_lock:
            return {}

        until = datetime.now(timezone.utc) + timedelta(days=self.cfg.retention_days)
        return {
            "ObjectLockMode": self.cfg.retention_mode,  # "COMPLIANCE" | "GOVERNANCE"
            "ObjectLockRetainUntilDate": until,
        }


def _human_bytes(n: int) -> str:
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"
