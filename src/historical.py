#!/usr/bin/env python3
"""
Wazuh Immutable Store - Historical Logs Manager
Gestione dei log storici di Wazuh e pulizia locale

Wazuh log structure:
  /var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD.log.gz
  /var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
"""

import os
import re
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from models import WazuhConfig, ArchiveConfig, RetentionConfig

logger = logging.getLogger(__name__)


@dataclass
class HistoricalLogGroup:
    """Represents a group of historical log files by date"""
    date: datetime
    date_str: str
    files: List[Path]
    total_size: int
    file_count: int
    log_type: str  # 'archives' or 'alerts'
    already_archived: bool = False

    def size_mb(self) -> float:
        return round(self.total_size / (1024 * 1024), 2)


class HistoricalLogsScanner:
    """Scans Wazuh directories for historical logs"""

    # Month name mapping
    MONTHS = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
        'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
        'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }

    # Regex patterns for Wazuh log files
    # ossec-archive-DD.log.gz, ossec-archive-DD.json.gz, ossec-alerts-DD.log.gz, etc.
    ARCHIVE_PATTERN = re.compile(r'ossec-archive-(\d{2})\.(log|json)(\.gz)?$')
    ALERT_PATTERN = re.compile(r'ossec-alerts-(\d{2})\.(log|json)(\.gz)?$')

    def __init__(self, wazuh_config: WazuhConfig):
        self.config = wazuh_config
        self.logs_path = Path(wazuh_config.logs_path)
        self.alerts_path = Path(wazuh_config.alerts_path) if wazuh_config.alerts_path else None

    def scan_historical_logs(self, remote_mount_point: Optional[Path] = None) -> List[HistoricalLogGroup]:
        """
        Scan for all historical log groups in Wazuh directories

        Args:
            remote_mount_point: Path to remote WORM storage to check for already archived

        Returns:
            List of HistoricalLogGroup objects
        """
        groups = []

        # Scan archives directory
        if self.logs_path.exists():
            archive_groups = self._scan_directory(self.logs_path, 'archives', remote_mount_point)
            groups.extend(archive_groups)

        # Scan alerts directory if configured
        if self.config.include_alerts and self.alerts_path and self.alerts_path.exists():
            alert_groups = self._scan_directory(self.alerts_path, 'alerts', remote_mount_point)
            groups.extend(alert_groups)

        # Sort by date (oldest first)
        groups.sort(key=lambda x: x.date)

        return groups

    def _scan_directory(self, base_path: Path, log_type: str,
                        remote_mount: Optional[Path] = None) -> List[HistoricalLogGroup]:
        """
        Scan a Wazuh log directory for date-organized logs

        Wazuh structure: YYYY/Mon/ossec-archive-DD.log.gz
        Example: 2026/Jan/ossec-archive-30.log.gz
        """
        groups = []
        files_by_date: Dict[datetime, List[Path]] = {}

        # Select pattern based on log type
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
                        # Also include .sum files
                        if file_path.suffix == '.sum':
                            # Extract day from sum file name
                            sum_match = re.match(r'ossec-(archive|alerts)-(\d{2})\.(log|json)\.sum$', file_path.name)
                            if sum_match:
                                day = int(sum_match.group(2))
                                try:
                                    log_date = datetime(year, month_num, day)
                                    if log_date not in files_by_date:
                                        files_by_date[log_date] = []
                                    files_by_date[log_date].append(file_path)
                                except ValueError:
                                    continue
                        continue

                    day = int(match.group(1))

                    try:
                        log_date = datetime(year, month_num, day)
                    except ValueError:
                        continue

                    if log_date not in files_by_date:
                        files_by_date[log_date] = []
                    files_by_date[log_date].append(file_path)

        # Create groups from collected files
        for log_date, files in files_by_date.items():
            # Calculate total size
            total_size = sum(f.stat().st_size for f in files if f.exists())
            file_count = len(files)

            # Check if already archived on remote
            already_archived = False
            if remote_mount and remote_mount.exists():
                already_archived = self._check_already_archived(log_date, remote_mount)

            group = HistoricalLogGroup(
                date=log_date,
                date_str=log_date.strftime("%Y-%m-%d"),
                files=files,
                total_size=total_size,
                file_count=file_count,
                log_type=log_type,
                already_archived=already_archived
            )
            groups.append(group)

        return groups

    def _parse_month(self, month_name: str) -> int:
        """Parse month name to number"""
        return self.MONTHS.get(month_name.lower()[:3], 0)

    def _check_already_archived(self, log_date: datetime, remote_mount: Path) -> bool:
        """Check if this date's logs are already archived on remote"""
        # Check common archive naming patterns
        date_str = log_date.strftime("%Y-%m-%d")
        year = log_date.strftime("%Y")
        month = log_date.strftime("%m")

        # Check in organized structure (YYYY/MM/)
        check_paths = [
            remote_mount / year / month / f"wazuh-logs-{date_str}*.tar.gz",
            remote_mount / year / month / f"wazuh-logs-{date_str}*.tar.bz2",
            remote_mount / year / month / f"wazuh-logs-{date_str}*.tar.xz",
            remote_mount / f"wazuh-logs-{date_str}*.tar.gz",
            remote_mount / f"wazuh-logs-{date_str}*.tar.bz2",
        ]

        for pattern in check_paths:
            if pattern.parent.exists() and list(pattern.parent.glob(pattern.name)):
                return True

        return False

    def get_summary(self, remote_mount_point: Optional[Path] = None) -> Dict:
        """Get summary of historical logs"""
        groups = self.scan_historical_logs(remote_mount_point)

        if not groups:
            return {
                'total_groups': 0,
                'total_files': 0,
                'total_size_mb': 0,
                'oldest_date': None,
                'newest_date': None,
                'already_archived': 0,
                'pending_archive': 0,
                'by_type': {}
            }

        summary = {
            'total_groups': len(groups),
            'total_files': sum(g.file_count for g in groups),
            'total_size_mb': round(sum(g.total_size for g in groups) / (1024 * 1024), 2),
            'oldest_date': min(g.date_str for g in groups),
            'newest_date': max(g.date_str for g in groups),
            'already_archived': len([g for g in groups if g.already_archived]),
            'pending_archive': len([g for g in groups if not g.already_archived]),
            'by_type': {}
        }

        # Group by log type
        for log_type in ['archives', 'alerts']:
            type_groups = [g for g in groups if g.log_type == log_type]
            if type_groups:
                summary['by_type'][log_type] = {
                    'groups': len(type_groups),
                    'files': sum(g.file_count for g in type_groups),
                    'size_mb': round(sum(g.total_size for g in type_groups) / (1024 * 1024), 2)
                }

        return summary


class WazuhLogsCleaner:
    """Manages cleanup of original Wazuh log files after archiving"""

    def __init__(self, wazuh_config: WazuhConfig, retention_config: RetentionConfig):
        self.wazuh_config = wazuh_config
        self.retention_config = retention_config
        self.logs_path = Path(wazuh_config.logs_path)
        self.alerts_path = Path(wazuh_config.alerts_path) if wazuh_config.alerts_path else None

    def get_logs_to_clean(self, remote_mount_point: Path,
                          keep_local_days: int = None) -> List[HistoricalLogGroup]:
        """
        Get list of log groups that can be cleaned (already archived on WORM)

        Args:
            remote_mount_point: Path to remote WORM storage
            keep_local_days: Days to keep locally (overrides config if provided)

        Returns:
            List of HistoricalLogGroup that are safe to delete
        """
        if keep_local_days is None:
            keep_local_days = self.retention_config.local.days_keep_local

        scanner = HistoricalLogsScanner(self.wazuh_config)
        all_groups = scanner.scan_historical_logs(remote_mount_point)

        cutoff_date = datetime.now() - timedelta(days=keep_local_days)

        # Filter: only already archived AND older than retention period
        cleanable = [
            g for g in all_groups
            if g.already_archived and g.date < cutoff_date
        ]

        return cleanable

    def clean_archived_logs(self, remote_mount_point: Path,
                            keep_local_days: int = None,
                            dry_run: bool = False) -> Dict:
        """
        Clean local Wazuh logs that are already archived on WORM

        Args:
            remote_mount_point: Path to remote WORM storage
            keep_local_days: Days to keep locally
            dry_run: If True, only simulate

        Returns:
            Dictionary with cleanup results
        """
        results = {
            'groups_cleaned': 0,
            'files_deleted': 0,
            'space_freed_mb': 0,
            'errors': [],
            'details': []
        }

        cleanable = self.get_logs_to_clean(remote_mount_point, keep_local_days)

        if not cleanable:
            logger.info("No logs to clean - all within retention period or not archived")
            return results

        logger.info(f"Found {len(cleanable)} log groups to clean")

        for group in cleanable:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] Would delete {group.file_count} files "
                               f"from {group.date_str} ({group.size_mb()} MB)")
                    results['groups_cleaned'] += 1
                    results['files_deleted'] += group.file_count
                    results['space_freed_mb'] += group.size_mb()
                else:
                    # Delete files
                    deleted_count = 0
                    for file_path in group.files:
                        try:
                            file_path.unlink()
                            deleted_count += 1
                        except Exception as e:
                            results['errors'].append(f"Failed to delete {file_path}: {e}")

                    # Try to remove empty parent directories
                    self._cleanup_empty_dirs(group.files[0].parent if group.files else None)

                    results['groups_cleaned'] += 1
                    results['files_deleted'] += deleted_count
                    results['space_freed_mb'] += group.size_mb()

                    logger.info(f"Cleaned {deleted_count} files from {group.date_str} "
                               f"({group.size_mb()} MB)")

                results['details'].append({
                    'date': group.date_str,
                    'files': group.file_count,
                    'size_mb': group.size_mb(),
                    'type': group.log_type
                })

            except Exception as e:
                error_msg = f"Error cleaning {group.date_str}: {e}"
                logger.error(error_msg)
                results['errors'].append(error_msg)

        results['space_freed_mb'] = round(results['space_freed_mb'], 2)

        return results

    def _cleanup_empty_dirs(self, start_dir: Optional[Path]):
        """Remove empty directories up the tree"""
        if not start_dir or not start_dir.exists():
            return

        current = start_dir

        # Go up to 2 levels (month -> year)
        for _ in range(2):
            if not current.exists():
                break

            # Check if directory is empty
            if not any(current.iterdir()):
                try:
                    current.rmdir()
                    logger.debug(f"Removed empty directory: {current}")
                except Exception as e:
                    logger.debug(f"Could not remove directory {current}: {e}")
                    break
            else:
                break

            current = current.parent


class HistoricalArchiveManager:
    """High-level manager for historical log operations"""

    def __init__(self, wazuh_config: WazuhConfig, archive_config: ArchiveConfig,
                 retention_config: RetentionConfig, remote_mount_point: Path):
        self.wazuh_config = wazuh_config
        self.archive_config = archive_config
        self.retention_config = retention_config
        self.remote_mount = remote_mount_point

        self.scanner = HistoricalLogsScanner(wazuh_config)
        self.cleaner = WazuhLogsCleaner(wazuh_config, retention_config)

    def analyze_historical_logs(self) -> Dict:
        """
        Analyze historical logs and provide recommendations

        Returns:
            Analysis dictionary with recommendations
        """
        summary = self.scanner.get_summary(self.remote_mount)

        analysis = {
            'summary': summary,
            'recommendations': [],
            'pending_groups': [],
            'cleanable_groups': []
        }

        if summary['total_groups'] == 0:
            analysis['recommendations'].append("Nessun log storico trovato")
            return analysis

        # Get pending and cleanable
        all_groups = self.scanner.scan_historical_logs(self.remote_mount)
        pending = [g for g in all_groups if not g.already_archived]
        cleanable = self.cleaner.get_logs_to_clean(self.remote_mount)

        analysis['pending_groups'] = [
            {
                'date': g.date_str,
                'files': g.file_count,
                'size_mb': g.size_mb(),
                'type': g.log_type
            }
            for g in pending[:20]  # Limit to first 20
        ]

        analysis['cleanable_groups'] = [
            {
                'date': g.date_str,
                'files': g.file_count,
                'size_mb': g.size_mb(),
                'type': g.log_type
            }
            for g in cleanable[:20]
        ]

        # Generate recommendations
        if pending:
            total_pending_mb = sum(g.total_size for g in pending) / (1024 * 1024)
            analysis['recommendations'].append(
                f"Ci sono {len(pending)} gruppi di log ({total_pending_mb:.1f} MB) "
                f"non ancora archiviati su WORM. Eseguire 'archive' per archiviarli."
            )

        if cleanable:
            total_cleanable_mb = sum(g.total_size for g in cleanable) / (1024 * 1024)
            analysis['recommendations'].append(
                f"Ci sono {len(cleanable)} gruppi di log ({total_cleanable_mb:.1f} MB) "
                f"già archiviati su WORM che possono essere eliminati localmente."
            )

        if not pending and not cleanable:
            analysis['recommendations'].append(
                "Tutti i log storici sono archiviati e la pulizia locale è aggiornata."
            )

        return analysis

    def archive_historical_logs(self, dry_run: bool = False) -> Dict:
        """
        Archive all pending historical logs

        This is called from the main archive cycle, but can also be
        triggered manually for bulk historical archiving.
        """
        # This functionality is handled by the main ArchiveManager
        # This method provides a convenient wrapper
        from archiver import ArchiveManager

        archive_manager = ArchiveManager(
            self.wazuh_config,
            self.archive_config,
            remote_mount_point=self.remote_mount
        )

        records = archive_manager.run_archive_cycle(
            min_age_days=self.retention_config.local.days_before_archive
        )

        return {
            'archives_created': len(records),
            'records': [
                {
                    'id': r.id,
                    'path': str(r.archive_path),
                    'size_mb': round(r.archive_size / (1024 * 1024), 2)
                }
                for r in records
            ]
        }

    def cleanup_local_logs(self, keep_days: int = None,
                           dry_run: bool = False) -> Dict:
        """
        Clean up local Wazuh logs that are already on WORM

        Args:
            keep_days: Days to keep locally (uses config if not specified)
            dry_run: If True, only simulate

        Returns:
            Cleanup results dictionary
        """
        return self.cleaner.clean_archived_logs(
            self.remote_mount,
            keep_local_days=keep_days,
            dry_run=dry_run
        )
