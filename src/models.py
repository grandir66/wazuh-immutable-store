"""
Data models for Wazuh Immutable Store
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List
from pathlib import Path


class ArchiveStatus(Enum):
    """Status of an archive"""
    PENDING = "pending"
    COMPRESSING = "compressing"
    SIGNING = "signing"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFIED = "verified"


class CompressionType(Enum):
    """Compression algorithms"""
    GZIP = "gzip"
    BZ2 = "bz2"
    XZ = "xz"


class ArchiveInterval(Enum):
    """Archive interval"""
    HOURLY = "hourly"
    DAILY = "daily"


@dataclass
class WazuhConfig:
    """Wazuh source configuration"""
    logs_path: Path
    file_pattern: str = "archives.json"
    include_alerts: bool = True
    alerts_path: Optional[Path] = None


@dataclass
class QNAPConfig:
    """QNAP NFS configuration"""
    host: str
    export_path: str
    mount_point: Path
    nfs_version: int = 4
    mount_options: str = "hard,intr,rsize=65536,wsize=65536"

    @property
    def nfs_source(self) -> str:
        return f"{self.host}:{self.export_path}"


@dataclass
class ArchiveConfig:
    """Archive settings"""
    compression: CompressionType = CompressionType.GZIP
    compression_level: int = 6
    naming_pattern: str = "wazuh-logs-{date}-{hour}.tar.gz"
    temp_dir: Path = Path("/tmp/wazuh-archive")
    interval: ArchiveInterval = ArchiveInterval.DAILY


@dataclass
class GPGConfig:
    """GPG signing configuration"""
    enabled: bool = True
    key_id: str = ""
    gpg_home: Optional[str] = None
    detached: bool = True


@dataclass
class IntegrityConfig:
    """Integrity verification settings"""
    algorithm: str = "sha256"
    create_manifest: bool = True
    chain_manifests: bool = True


@dataclass
class LocalRetention:
    """Local retention policy"""
    days_before_archive: int = 1
    days_keep_local: int = 7
    delete_after_transfer: bool = True


@dataclass
class RemoteRetention:
    """Remote retention policy"""
    days: int = 2555  # ~7 years
    organize_by_date: bool = True


@dataclass
class RetentionConfig:
    """Retention policies"""
    local: LocalRetention = field(default_factory=LocalRetention)
    remote: RemoteRetention = field(default_factory=RemoteRetention)


@dataclass
class ScheduleConfig:
    """Scheduling configuration"""
    archive_cron: str = "0 2 * * *"
    integrity_check_cron: str = "0 6 * * 0"
    cleanup_cron: str = "0 3 * * *"


@dataclass
class ArchiveRecord:
    """Record of a created archive"""
    id: str
    source_files: List[str]
    archive_path: Path
    archive_size: int
    checksum: str
    signature_path: Optional[Path]
    created_at: datetime
    transferred_at: Optional[datetime]
    remote_path: Optional[Path]
    status: ArchiveStatus
    manifest_entry: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_files": self.source_files,
            "archive_path": str(self.archive_path),
            "archive_size": self.archive_size,
            "checksum": self.checksum,
            "signature_path": str(self.signature_path) if self.signature_path else None,
            "created_at": self.created_at.isoformat(),
            "transferred_at": self.transferred_at.isoformat() if self.transferred_at else None,
            "remote_path": str(self.remote_path) if self.remote_path else None,
            "status": self.status.value,
            "manifest_entry": self.manifest_entry
        }


@dataclass
class ManifestEntry:
    """Entry in the archive manifest"""
    archive_id: str
    filename: str
    checksum: str
    size: int
    created_at: datetime
    previous_manifest_hash: Optional[str] = None

    def to_line(self) -> str:
        """Convert to manifest line format"""
        prev = self.previous_manifest_hash or "GENESIS"
        return f"{self.checksum}  {self.filename}  {self.size}  {self.created_at.isoformat()}  PREV:{prev}"


@dataclass
class RecoveryRequest:
    """Request to recover archived logs"""
    start_date: datetime
    end_date: datetime
    output_path: Path
    verify_signatures: bool = True
    decompress: bool = True
