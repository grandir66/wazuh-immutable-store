#!/usr/bin/env python3
"""
Wazuh Immutable Store - Archive Module
Gestione della compressione e creazione archivi log

Wazuh log structure:
  /var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD.log.gz
  /var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
"""

import os
import re
import tarfile
import gzip
import bz2
import lzma
import hashlib
import json
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Generator, Dict
from dataclasses import dataclass
import uuid

from models import (
    ArchiveRecord, ArchiveStatus, CompressionType,
    ArchiveConfig, WazuhConfig, ArchiveInterval
)


logger = logging.getLogger(__name__)


class ArchiveError(Exception):
    """Exception raised for archive operations"""
    pass


@dataclass
class LogFile:
    """Represents a log file to be archived"""
    path: Path
    size: int
    modified_time: datetime
    checksum: Optional[str] = None

    def calculate_checksum(self, algorithm: str = "sha256") -> str:
        """Calculate file checksum"""
        hash_func = hashlib.new(algorithm)
        with open(self.path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        self.checksum = hash_func.hexdigest()
        return self.checksum


class LogCollector:
    """Collects log files from Wazuh directories

    Scans Wazuh log directories with real structure:
      /var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD.log.gz
      /var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
    """

    # Month name mapping
    MONTHS = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
        'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
        'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }

    # Regex patterns for real Wazuh log files
    ARCHIVE_PATTERN = re.compile(r'ossec-archive-(\d{2})\.(log|json)(\.gz)?$')
    ALERT_PATTERN = re.compile(r'ossec-alerts-(\d{2})\.(log|json)(\.gz)?$')

    def __init__(self, wazuh_config: WazuhConfig):
        self.config = wazuh_config
        self.logs_path = Path(wazuh_config.logs_path)
        self.alerts_path = Path(wazuh_config.alerts_path) if wazuh_config.alerts_path else None

    def find_logs_to_archive(self, min_age_days: int = 1) -> List[LogFile]:
        """
        Find log files ready for archiving based on age

        Scans real Wazuh log structure: YYYY/Mon/ossec-archive-DD.log.gz

        Args:
            min_age_days: Minimum age in days before archiving

        Returns:
            List of LogFile objects ready for archiving
        """
        cutoff_date = datetime.now() - timedelta(days=min_age_days)
        cutoff_date = cutoff_date.replace(hour=23, minute=59, second=59)  # End of cutoff day
        files_to_archive = []

        # Collect from archives directory
        if self.logs_path.exists():
            files_to_archive.extend(
                self._scan_wazuh_directory(self.logs_path, 'archives', cutoff_date)
            )

        # Collect from alerts directory if configured
        if self.config.include_alerts and self.alerts_path and self.alerts_path.exists():
            files_to_archive.extend(
                self._scan_wazuh_directory(self.alerts_path, 'alerts', cutoff_date)
            )

        # Sort by date (oldest first)
        files_to_archive.sort(key=lambda x: x.modified_time)

        logger.info(f"Found {len(files_to_archive)} files ready for archiving")
        return files_to_archive

    def _scan_wazuh_directory(self, base_path: Path, log_type: str,
                               cutoff_date: datetime) -> List[LogFile]:
        """
        Scan a Wazuh log directory for date-organized logs

        Wazuh structure: YYYY/Mon/ossec-archive-DD.log.gz
        Example: 2026/Jan/ossec-archive-30.log.gz
        """
        files = []
        pattern = self.ARCHIVE_PATTERN if log_type == 'archives' else self.ALERT_PATTERN

        for year_dir in sorted(base_path.iterdir()):
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue

            year = int(year_dir.name)

            for month_dir in sorted(year_dir.iterdir()):
                if not month_dir.is_dir():
                    continue

                # Parse month name (Jan, Feb, etc.)
                month_num = self._parse_month(month_dir.name)
                if month_num == 0:
                    continue

                # Scan files in month directory
                for file_path in month_dir.iterdir():
                    if not file_path.is_file():
                        continue

                    # Match log file pattern
                    match = pattern.match(file_path.name)
                    if not match:
                        # Also include .sum files for archives
                        if file_path.suffix == '.sum':
                            sum_match = re.match(r'ossec-(archive|alerts)-(\d{2})\.(log|json)\.sum$', file_path.name)
                            if sum_match:
                                day = int(sum_match.group(2))
                                try:
                                    log_date = datetime(year, month_num, day)
                                    if log_date <= cutoff_date:
                                        stat = file_path.stat()
                                        files.append(LogFile(
                                            path=file_path,
                                            size=stat.st_size,
                                            modified_time=log_date
                                        ))
                                except ValueError:
                                    pass
                        continue

                    day = int(match.group(1))

                    try:
                        log_date = datetime(year, month_num, day)
                    except ValueError:
                        continue

                    # Only include files older than cutoff date
                    if log_date <= cutoff_date:
                        stat = file_path.stat()
                        files.append(LogFile(
                            path=file_path,
                            size=stat.st_size,
                            modified_time=log_date  # Use parsed date, not mtime
                        ))

        return files

    def _parse_month(self, month_name: str) -> int:
        """Parse month name to number"""
        return self.MONTHS.get(month_name.lower()[:3], 0)

    def _scan_directory(self, directory: Path, cutoff_time: datetime) -> List[LogFile]:
        """Legacy scan method - kept for compatibility"""
        return self._scan_wazuh_directory(directory, 'archives', cutoff_time)

    def find_logs_by_date(self, target_date: datetime) -> List[LogFile]:
        """Find log files for a specific date"""
        files = []

        # Get month name abbreviation
        month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                       'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        month_name = month_names[target_date.month - 1]
        year_str = target_date.strftime("%Y")
        day_str = target_date.strftime("%d")

        for directory, log_type in [(self.logs_path, 'archives'), (self.alerts_path, 'alerts')]:
            if not directory or not directory.exists():
                continue

            if log_type == 'alerts' and not self.config.include_alerts:
                continue

            # Wazuh structure: YYYY/Mon/ossec-archive-DD.log.gz
            month_dir = directory / year_str / month_name
            if not month_dir.exists():
                continue

            pattern = self.ARCHIVE_PATTERN if log_type == 'archives' else self.ALERT_PATTERN

            for file_path in month_dir.iterdir():
                if not file_path.is_file():
                    continue

                match = pattern.match(file_path.name)
                if match and match.group(1) == day_str:
                    stat = file_path.stat()
                    files.append(LogFile(
                        path=file_path,
                        size=stat.st_size,
                        modified_time=target_date
                    ))

        return files


class Archiver:
    """Creates compressed and signed archives of log files"""

    COMPRESSION_EXTENSIONS = {
        CompressionType.GZIP: '.gz',
        CompressionType.BZ2: '.bz2',
        CompressionType.XZ: '.xz'
    }

    def __init__(self, config: ArchiveConfig):
        self.config = config
        self.temp_dir = Path(config.temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def create_archive(self, files: List[LogFile],
                       archive_date: Optional[datetime] = None) -> ArchiveRecord:
        """
        Create a compressed archive from log files

        Args:
            files: List of LogFile objects to archive
            archive_date: Date for the archive (defaults to now)

        Returns:
            ArchiveRecord with archive details
        """
        if not files:
            raise ArchiveError("No files provided for archiving")

        archive_date = archive_date or datetime.now()
        archive_id = self._generate_archive_id(archive_date)

        # Generate archive filename
        archive_name = self._generate_archive_name(archive_date)
        archive_path = self.temp_dir / archive_name

        logger.info(f"Creating archive: {archive_name} with {len(files)} files")

        try:
            # Create tar archive with compression
            self._create_tar_archive(files, archive_path)

            # Calculate checksum
            checksum = self._calculate_checksum(archive_path)

            # Get archive size
            archive_size = archive_path.stat().st_size

            record = ArchiveRecord(
                id=archive_id,
                source_files=[str(f.path) for f in files],
                archive_path=archive_path,
                archive_size=archive_size,
                checksum=checksum,
                signature_path=None,
                created_at=datetime.now(),
                transferred_at=None,
                remote_path=None,
                status=ArchiveStatus.COMPRESSING
            )

            logger.info(f"Archive created: {archive_path} ({archive_size} bytes)")
            record.status = ArchiveStatus.PENDING
            return record

        except Exception as e:
            logger.error(f"Failed to create archive: {e}")
            # Cleanup on failure
            if archive_path.exists():
                archive_path.unlink()
            raise ArchiveError(f"Archive creation failed: {e}")

    def _generate_archive_id(self, date: datetime) -> str:
        """Generate unique archive ID"""
        date_str = date.strftime("%Y%m%d%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        return f"wazuh-{date_str}-{unique_id}"

    def _generate_archive_name(self, date: datetime) -> str:
        """Generate archive filename based on pattern"""
        name = self.config.naming_pattern.format(
            date=date.strftime("%Y-%m-%d"),
            hour=date.strftime("%H"),
            timestamp=date.strftime("%Y%m%d%H%M%S")
        )

        # Add compression extension if not present
        ext = self.COMPRESSION_EXTENSIONS.get(self.config.compression, '.gz')
        if not name.endswith(ext):
            if name.endswith('.tar'):
                name = name + ext
            elif not name.endswith('.tar' + ext):
                name = name.replace('.gz', '').replace('.bz2', '').replace('.xz', '')
                if not name.endswith('.tar'):
                    name = name + '.tar'
                name = name + ext

        return name

    def _create_tar_archive(self, files: List[LogFile], archive_path: Path):
        """Create compressed tar archive"""
        compression = self.config.compression
        level = self.config.compression_level

        # Determine compression mode
        if compression == CompressionType.GZIP:
            mode = 'w:gz'
        elif compression == CompressionType.BZ2:
            mode = 'w:bz2'
        elif compression == CompressionType.XZ:
            mode = 'w:xz'
        else:
            mode = 'w:gz'

        # Create archive
        with tarfile.open(archive_path, mode, compresslevel=level) as tar:
            for log_file in files:
                # Calculate checksum before adding
                log_file.calculate_checksum()

                # Add file to archive with relative path
                arcname = self._get_arcname(log_file)
                tar.add(log_file.path, arcname=arcname)

                logger.debug(f"Added to archive: {log_file.path} -> {arcname}")

            # Add manifest of included files
            manifest = self._create_internal_manifest(files)
            manifest_path = self.temp_dir / "manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2, default=str)
            tar.add(manifest_path, arcname="manifest.json")
            manifest_path.unlink()

    def _get_arcname(self, log_file: LogFile) -> str:
        """Generate archive name for a file preserving date structure"""
        # Preserve the date-based directory structure
        try:
            # Try to extract date structure from path
            parts = log_file.path.parts
            # Look for year directory (4 digits)
            for i, part in enumerate(parts):
                if len(part) == 4 and part.isdigit():
                    return str(Path(*parts[i:]))
        except Exception:
            pass

        # Fallback to filename only
        return log_file.path.name

    def _create_internal_manifest(self, files: List[LogFile]) -> dict:
        """Create manifest of files included in archive"""
        return {
            "created_at": datetime.now().isoformat(),
            "file_count": len(files),
            "files": [
                {
                    "path": str(f.path),
                    "size": f.size,
                    "modified": f.modified_time.isoformat(),
                    "checksum": f.checksum or "not_calculated"
                }
                for f in files
            ]
        }

    def _calculate_checksum(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate file checksum"""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def verify_archive(self, record: ArchiveRecord) -> bool:
        """Verify archive integrity"""
        if not record.archive_path.exists():
            logger.error(f"Archive file not found: {record.archive_path}")
            return False

        # Verify checksum
        calculated = self._calculate_checksum(record.archive_path)
        if calculated != record.checksum:
            logger.error(f"Checksum mismatch for {record.archive_path}")
            logger.error(f"Expected: {record.checksum}, Got: {calculated}")
            return False

        # Try to open and read the archive
        try:
            with tarfile.open(record.archive_path, 'r:*') as tar:
                members = tar.getmembers()
                if not members:
                    logger.error("Archive is empty")
                    return False

                # Verify manifest exists
                manifest_found = any(m.name == "manifest.json" for m in members)
                if not manifest_found:
                    logger.warning("Internal manifest not found in archive")

            logger.info(f"Archive verified: {record.archive_path}")
            return True

        except (tarfile.TarError, IOError) as e:
            logger.error(f"Failed to verify archive: {e}")
            return False

    def extract_archive(self, record: ArchiveRecord, destination: Path,
                        verify_first: bool = True) -> bool:
        """
        Extract archive to destination

        Args:
            record: Archive record to extract
            destination: Destination directory
            verify_first: Verify integrity before extraction

        Returns:
            True if extraction successful
        """
        if verify_first and not self.verify_archive(record):
            raise ArchiveError("Archive verification failed")

        destination.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(record.archive_path, 'r:*') as tar:
                # Security check - prevent path traversal
                for member in tar.getmembers():
                    member_path = Path(destination / member.name)
                    if not member_path.resolve().is_relative_to(destination.resolve()):
                        raise ArchiveError(f"Path traversal detected: {member.name}")

                tar.extractall(destination)

            logger.info(f"Archive extracted to: {destination}")
            return True

        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise ArchiveError(f"Extraction failed: {e}")

    def cleanup_temp(self):
        """Clean up temporary files"""
        try:
            for item in self.temp_dir.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            logger.debug("Temporary files cleaned up")
        except Exception as e:
            logger.warning(f"Failed to cleanup temp directory: {e}")


class ArchiveManager:
    """High-level manager for archive operations"""

    def __init__(self, wazuh_config: WazuhConfig, archive_config: ArchiveConfig,
                 remote_mount_point: Optional[Path] = None):
        self.collector = LogCollector(wazuh_config)
        self.archiver = Archiver(archive_config)
        self.archive_config = archive_config
        self.records: List[ArchiveRecord] = []
        self.remote_mount_point = remote_mount_point

    def _check_archive_exists_remote(self, archive_date: datetime) -> bool:
        """
        Check if archive for this date already exists on remote WORM storage

        Args:
            archive_date: Date of the archive to check

        Returns:
            True if archive already exists
        """
        if not self.remote_mount_point or not self.remote_mount_point.exists():
            return False

        # Generate expected filename
        archive_name = self.archiver._generate_archive_name(archive_date)

        # Check in date-organized structure (YYYY/MM/)
        year = archive_date.strftime("%Y")
        month = archive_date.strftime("%m")
        remote_path = self.remote_mount_point / year / month / archive_name

        if remote_path.exists():
            logger.info(f"Archive already exists on WORM: {remote_path}")
            return True

        # Also check root level
        root_path = self.remote_mount_point / archive_name
        if root_path.exists():
            logger.info(f"Archive already exists on WORM: {root_path}")
            return True

        return False

    def run_archive_cycle(self, min_age_days: int = 1) -> List[ArchiveRecord]:
        """
        Run a complete archive cycle

        Args:
            min_age_days: Minimum age of files to archive

        Returns:
            List of created archive records
        """
        logger.info("Starting archive cycle")

        # Find files to archive
        files = self.collector.find_logs_to_archive(min_age_days)

        if not files:
            logger.info("No files found for archiving")
            return []

        # Group files by date if doing daily archives
        if self.archive_config.interval == ArchiveInterval.DAILY:
            file_groups = self._group_by_date(files)
        else:
            # Hourly - group by hour
            file_groups = self._group_by_hour(files)

        created_records = []
        skipped_count = 0

        for group_date, group_files in file_groups.items():
            # Check if archive already exists on remote WORM storage
            if self._check_archive_exists_remote(group_date):
                logger.info(f"Skipping {group_date}: archive already exists on WORM storage")
                skipped_count += 1
                continue

            try:
                record = self.archiver.create_archive(group_files, group_date)
                created_records.append(record)
                self.records.append(record)
                logger.info(f"Created archive for {group_date}: {record.archive_path}")

            except ArchiveError as e:
                logger.error(f"Failed to create archive for {group_date}: {e}")
                continue

        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} archives (already exist on WORM)")

        return created_records

    def _group_by_date(self, files: List[LogFile]) -> dict:
        """Group files by date"""
        groups = {}
        for f in files:
            date_key = f.modified_time.replace(hour=0, minute=0, second=0, microsecond=0)
            if date_key not in groups:
                groups[date_key] = []
            groups[date_key].append(f)
        return groups

    def _group_by_hour(self, files: List[LogFile]) -> dict:
        """Group files by hour"""
        groups = {}
        for f in files:
            hour_key = f.modified_time.replace(minute=0, second=0, microsecond=0)
            if hour_key not in groups:
                groups[hour_key] = []
            groups[hour_key].append(f)
        return groups

    def get_pending_records(self) -> List[ArchiveRecord]:
        """Get records pending transfer"""
        return [r for r in self.records if r.status == ArchiveStatus.PENDING]

    def get_record_by_id(self, archive_id: str) -> Optional[ArchiveRecord]:
        """Get record by ID"""
        for r in self.records:
            if r.id == archive_id:
                return r
        return None
