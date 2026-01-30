#!/usr/bin/env python3
"""
Wazuh Immutable Store - Retention Manager Module
Gestione delle policy di retention locale e remota
"""

import os
import shutil
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass, asdict

from models import ArchiveRecord, ArchiveStatus, RetentionConfig, LocalRetention, RemoteRetention


logger = logging.getLogger(__name__)


class RetentionError(Exception):
    """Exception raised for retention operations"""
    pass


@dataclass
class RetentionAction:
    """Represents a retention action taken"""
    action_type: str  # 'archive', 'delete_local', 'delete_remote', 'keep'
    file_path: str
    file_age_days: int
    reason: str
    executed: bool = False
    error: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class RetentionReport:
    """Report of retention operations"""
    start_time: datetime
    end_time: Optional[datetime]
    local_files_checked: int
    local_files_deleted: int
    local_space_freed: int  # bytes
    remote_files_checked: int
    actions: List[RetentionAction]
    errors: List[str]

    def to_dict(self) -> dict:
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'local_files_checked': self.local_files_checked,
            'local_files_deleted': self.local_files_deleted,
            'local_space_freed_mb': round(self.local_space_freed / (1024 * 1024), 2),
            'remote_files_checked': self.remote_files_checked,
            'actions_count': len(self.actions),
            'errors_count': len(self.errors),
            'actions': [asdict(a) for a in self.actions[-50:]],  # Last 50 actions
            'errors': self.errors
        }


class LocalRetentionManager:
    """Manages local file retention"""

    def __init__(self, config: LocalRetention, archive_records: List[ArchiveRecord]):
        self.config = config
        self.records = archive_records

    def get_files_to_delete(self, local_archives_dir: Path) -> List[Tuple[Path, int, str]]:
        """
        Identify local files that should be deleted based on retention policy

        Args:
            local_archives_dir: Directory containing local archives

        Returns:
            List of (file_path, age_days, reason) tuples
        """
        files_to_delete = []
        now = datetime.now()

        if not local_archives_dir.exists():
            return files_to_delete

        for file_path in local_archives_dir.iterdir():
            if not file_path.is_file():
                continue

            # Skip non-archive files
            if not any(file_path.name.endswith(ext) for ext in
                       ['.tar.gz', '.tar.bz2', '.tar.xz', '.sig', '.sha256']):
                continue

            stat = file_path.stat()
            file_age = now - datetime.fromtimestamp(stat.st_mtime)
            age_days = file_age.days

            # Check if file should be deleted
            should_delete = False
            reason = ""

            # Rule 1: Delete if transferred and delete_after_transfer is enabled
            if self.config.delete_after_transfer:
                # Find corresponding record
                record = self._find_record_for_file(file_path)
                if record and record.status == ArchiveStatus.COMPLETED:
                    if record.transferred_at:
                        should_delete = True
                        reason = "Successfully transferred to remote"

            # Rule 2: Delete if older than days_keep_local
            if not should_delete and age_days > self.config.days_keep_local:
                record = self._find_record_for_file(file_path)
                if record and record.status == ArchiveStatus.COMPLETED:
                    should_delete = True
                    reason = f"Older than {self.config.days_keep_local} days"
                elif record is None:
                    # Orphan file without record - be cautious
                    if age_days > self.config.days_keep_local * 2:
                        should_delete = True
                        reason = f"Orphan file older than {self.config.days_keep_local * 2} days"

            if should_delete:
                files_to_delete.append((file_path, age_days, reason))

        return files_to_delete

    def _find_record_for_file(self, file_path: Path) -> Optional[ArchiveRecord]:
        """Find archive record for a file"""
        file_name = file_path.name
        # Remove extensions to get base name
        base_name = file_name
        for ext in ['.sig', '.sha256', '.tar.gz', '.tar.bz2', '.tar.xz']:
            if base_name.endswith(ext):
                base_name = base_name[:-len(ext)]
                break

        for record in self.records:
            if record.archive_path and base_name in record.archive_path.name:
                return record
        return None

    def delete_files(self, files: List[Tuple[Path, int, str]],
                     dry_run: bool = False) -> Tuple[int, int, List[str]]:
        """
        Delete files from local storage

        Args:
            files: List of (path, age, reason) tuples
            dry_run: If True, don't actually delete

        Returns:
            Tuple of (deleted_count, freed_bytes, errors)
        """
        deleted = 0
        freed_bytes = 0
        errors = []

        for file_path, age_days, reason in files:
            try:
                if not file_path.exists():
                    continue

                file_size = file_path.stat().st_size

                if dry_run:
                    logger.info(f"[DRY RUN] Would delete: {file_path} ({reason})")
                else:
                    file_path.unlink()
                    logger.info(f"Deleted: {file_path} ({reason})")

                deleted += 1
                freed_bytes += file_size

            except Exception as e:
                error_msg = f"Failed to delete {file_path}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        return deleted, freed_bytes, errors


class RemoteRetentionManager:
    """Manages remote file retention on QNAP"""

    def __init__(self, config: RemoteRetention, mount_point: Path):
        self.config = config
        self.mount_point = mount_point

    def get_expired_files(self) -> List[Tuple[Path, int, str]]:
        """
        Identify remote files that have exceeded retention period

        NOTE: On WORM volumes, these files cannot be deleted until
        the WORM retention period expires. This is informational only.

        Returns:
            List of (file_path, age_days, reason) tuples
        """
        expired_files = []
        now = datetime.now()

        if not self.mount_point.exists():
            logger.warning(f"Remote mount point not accessible: {self.mount_point}")
            return expired_files

        retention_days = self.config.days
        if retention_days == 0:
            # 0 means keep forever
            return expired_files

        for file_path in self.mount_point.rglob("*.tar.*"):
            if not file_path.is_file():
                continue

            stat = file_path.stat()
            file_age = now - datetime.fromtimestamp(stat.st_mtime)
            age_days = file_age.days

            if age_days > retention_days:
                expired_files.append((
                    file_path,
                    age_days,
                    f"Exceeded retention of {retention_days} days"
                ))

        return expired_files

    def get_storage_statistics(self) -> Dict:
        """
        Get storage statistics for remote location

        Returns:
            Dictionary with storage stats
        """
        stats = {
            'total_files': 0,
            'total_size': 0,
            'oldest_file': None,
            'newest_file': None,
            'by_year': {}
        }

        if not self.mount_point.exists():
            return stats

        oldest_time = None
        newest_time = None

        for file_path in self.mount_point.rglob("*.tar.*"):
            if not file_path.is_file():
                continue

            # Skip signature and checksum files
            if file_path.suffix in ['.sig', '.sha256']:
                continue

            stat = file_path.stat()
            file_time = datetime.fromtimestamp(stat.st_mtime)

            stats['total_files'] += 1
            stats['total_size'] += stat.st_size

            # Track oldest/newest
            if oldest_time is None or file_time < oldest_time:
                oldest_time = file_time
                stats['oldest_file'] = str(file_path)

            if newest_time is None or file_time > newest_time:
                newest_time = file_time
                stats['newest_file'] = str(file_path)

            # Group by year
            year = file_time.year
            if year not in stats['by_year']:
                stats['by_year'][year] = {'count': 0, 'size': 0}
            stats['by_year'][year]['count'] += 1
            stats['by_year'][year]['size'] += stat.st_size

        return stats


class RetentionManager:
    """High-level retention manager"""

    def __init__(self, config: RetentionConfig, local_archives_dir: Path,
                 remote_mount_point: Path, archive_records: List[ArchiveRecord]):
        self.config = config
        self.local_dir = local_archives_dir
        self.remote_mount = remote_mount_point

        self.local_manager = LocalRetentionManager(config.local, archive_records)
        self.remote_manager = RemoteRetentionManager(config.remote, remote_mount_point)

        self.reports_dir = local_archives_dir.parent / "retention_reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def run_retention_cycle(self, dry_run: bool = False) -> RetentionReport:
        """
        Run a complete retention cycle

        Args:
            dry_run: If True, don't actually delete files

        Returns:
            RetentionReport with details
        """
        report = RetentionReport(
            start_time=datetime.now(),
            end_time=None,
            local_files_checked=0,
            local_files_deleted=0,
            local_space_freed=0,
            remote_files_checked=0,
            actions=[],
            errors=[]
        )

        logger.info(f"Starting retention cycle {'(DRY RUN)' if dry_run else ''}")

        try:
            # Process local retention
            self._process_local_retention(report, dry_run)

            # Check remote retention (informational on WORM)
            self._check_remote_retention(report)

        except Exception as e:
            error_msg = f"Retention cycle error: {e}"
            logger.error(error_msg)
            report.errors.append(error_msg)

        report.end_time = datetime.now()

        # Save report
        self._save_report(report)

        return report

    def _process_local_retention(self, report: RetentionReport, dry_run: bool):
        """Process local file retention"""
        logger.info("Processing local retention...")

        # Get files to delete
        files_to_delete = self.local_manager.get_files_to_delete(self.local_dir)
        report.local_files_checked = len(list(self.local_dir.iterdir())) if self.local_dir.exists() else 0

        for file_path, age_days, reason in files_to_delete:
            action = RetentionAction(
                action_type='delete_local',
                file_path=str(file_path),
                file_age_days=age_days,
                reason=reason
            )
            report.actions.append(action)

        if files_to_delete:
            deleted, freed, errors = self.local_manager.delete_files(
                files_to_delete, dry_run=dry_run
            )
            report.local_files_deleted = deleted
            report.local_space_freed = freed
            report.errors.extend(errors)

            # Update action status
            for action in report.actions:
                if action.action_type == 'delete_local':
                    if any(action.file_path in err for err in errors):
                        action.executed = False
                        action.error = "Deletion failed"
                    else:
                        action.executed = not dry_run

        logger.info(f"Local retention: {report.local_files_deleted} files deleted, "
                    f"{report.local_space_freed / (1024*1024):.2f} MB freed")

    def _check_remote_retention(self, report: RetentionReport):
        """Check remote file retention status"""
        logger.info("Checking remote retention...")

        if not self.remote_mount.exists():
            logger.warning("Remote mount point not accessible")
            return

        # Get expired files (informational on WORM)
        expired = self.remote_manager.get_expired_files()
        report.remote_files_checked = len(expired)

        for file_path, age_days, reason in expired:
            action = RetentionAction(
                action_type='keep',  # WORM prevents deletion
                file_path=str(file_path),
                file_age_days=age_days,
                reason=f"WORM protected - {reason}"
            )
            report.actions.append(action)

        if expired:
            logger.info(f"Found {len(expired)} files past retention on WORM volume (protected)")

    def _save_report(self, report: RetentionReport):
        """Save retention report to file"""
        timestamp = report.start_time.strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"retention_report_{timestamp}.json"

        try:
            with open(report_file, 'w') as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            logger.info(f"Retention report saved: {report_file}")
        except Exception as e:
            logger.error(f"Failed to save retention report: {e}")

    def get_retention_summary(self) -> Dict:
        """
        Get summary of current retention status

        Returns:
            Dictionary with retention status
        """
        summary = {
            'local': {
                'directory': str(self.local_dir),
                'total_files': 0,
                'total_size': 0,
                'files_pending_deletion': 0
            },
            'remote': {
                'directory': str(self.remote_mount),
                'accessible': self.remote_mount.exists()
            },
            'policy': {
                'local_days_keep': self.config.local.days_keep_local,
                'local_delete_after_transfer': self.config.local.delete_after_transfer,
                'remote_retention_days': self.config.remote.days,
                'remote_retention_years': round(self.config.remote.days / 365, 1)
            }
        }

        # Count local files
        if self.local_dir.exists():
            for f in self.local_dir.iterdir():
                if f.is_file():
                    summary['local']['total_files'] += 1
                    summary['local']['total_size'] += f.stat().st_size

            files_to_delete = self.local_manager.get_files_to_delete(self.local_dir)
            summary['local']['files_pending_deletion'] = len(files_to_delete)

        # Get remote stats
        if summary['remote']['accessible']:
            summary['remote'].update(self.remote_manager.get_storage_statistics())

        return summary

    def get_recent_reports(self, count: int = 10) -> List[Dict]:
        """Get recent retention reports"""
        reports = []

        if not self.reports_dir.exists():
            return reports

        report_files = sorted(
            self.reports_dir.glob("retention_report_*.json"),
            reverse=True
        )[:count]

        for report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    reports.append(json.load(f))
            except Exception as e:
                logger.error(f"Failed to load report {report_file}: {e}")

        return reports
