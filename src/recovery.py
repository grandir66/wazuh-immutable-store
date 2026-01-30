#!/usr/bin/env python3
"""
Wazuh Immutable Store - Recovery Module
Gestione del recupero e verifica degli archivi
"""

import os
import tarfile
import logging
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Generator
from dataclasses import dataclass

from models import ArchiveRecord, ArchiveStatus, RecoveryRequest
from signer import GPGSigner, IntegrityManager, GPGConfig, IntegrityConfig
from transfer import NFSManager, QNAPConfig


logger = logging.getLogger(__name__)


class RecoveryError(Exception):
    """Exception raised for recovery operations"""
    pass


@dataclass
class ArchiveInfo:
    """Information about an archive"""
    path: Path
    name: str
    size: int
    created: datetime
    has_signature: bool
    has_checksum: bool
    is_verified: bool = False
    verification_errors: List[str] = None

    def __post_init__(self):
        if self.verification_errors is None:
            self.verification_errors = []


@dataclass
class RecoveryResult:
    """Result of a recovery operation"""
    request: RecoveryRequest
    archives_found: int
    archives_recovered: int
    files_extracted: int
    total_size: int
    output_path: Path
    errors: List[str]
    verification_passed: bool
    start_time: datetime
    end_time: datetime

    def to_dict(self) -> dict:
        return {
            'request': {
                'start_date': self.request.start_date.isoformat(),
                'end_date': self.request.end_date.isoformat(),
                'output_path': str(self.request.output_path),
                'verify_signatures': self.request.verify_signatures,
                'decompress': self.request.decompress
            },
            'archives_found': self.archives_found,
            'archives_recovered': self.archives_recovered,
            'files_extracted': self.files_extracted,
            'total_size_mb': round(self.total_size / (1024 * 1024), 2),
            'output_path': str(self.output_path),
            'errors': self.errors,
            'verification_passed': self.verification_passed,
            'duration_seconds': (self.end_time - self.start_time).total_seconds()
        }


class ArchiveSearcher:
    """Searches for archives in local and remote locations"""

    def __init__(self, local_dir: Path, remote_mount: Optional[Path] = None):
        self.local_dir = local_dir
        self.remote_mount = remote_mount

    def find_archives_by_date_range(self, start_date: datetime,
                                     end_date: datetime,
                                     include_remote: bool = True) -> List[ArchiveInfo]:
        """
        Find archives within a date range

        Args:
            start_date: Start of date range
            end_date: End of date range
            include_remote: Include remote archives in search

        Returns:
            List of ArchiveInfo objects
        """
        archives = []

        # Search local
        if self.local_dir.exists():
            archives.extend(self._search_directory(
                self.local_dir, start_date, end_date
            ))

        # Search remote
        if include_remote and self.remote_mount and self.remote_mount.exists():
            archives.extend(self._search_directory(
                self.remote_mount, start_date, end_date
            ))

        # Sort by date
        archives.sort(key=lambda x: x.created)

        return archives

    def _search_directory(self, directory: Path, start_date: datetime,
                          end_date: datetime) -> List[ArchiveInfo]:
        """Search a directory for archives in date range"""
        archives = []

        for file_path in directory.rglob("*.tar.*"):
            if not file_path.is_file():
                continue

            # Skip signature and checksum files
            if file_path.suffix in ['.sig', '.sha256', '.sha512']:
                continue

            stat = file_path.stat()
            file_date = datetime.fromtimestamp(stat.st_mtime)

            # Check if within date range
            if start_date <= file_date <= end_date:
                info = ArchiveInfo(
                    path=file_path,
                    name=file_path.name,
                    size=stat.st_size,
                    created=file_date,
                    has_signature=file_path.with_suffix(file_path.suffix + '.sig').exists(),
                    has_checksum=any(
                        file_path.with_suffix(file_path.suffix + ext).exists()
                        for ext in ['.sha256', '.sha512']
                    )
                )
                archives.append(info)

        return archives

    def find_archive_by_name(self, archive_name: str,
                             include_remote: bool = True) -> Optional[ArchiveInfo]:
        """Find a specific archive by name"""
        # Search local first
        local_path = self.local_dir / archive_name
        if local_path.exists():
            return self._create_archive_info(local_path)

        # Search remote
        if include_remote and self.remote_mount and self.remote_mount.exists():
            for file_path in self.remote_mount.rglob(archive_name):
                if file_path.is_file():
                    return self._create_archive_info(file_path)

        return None

    def _create_archive_info(self, file_path: Path) -> ArchiveInfo:
        """Create ArchiveInfo from file path"""
        stat = file_path.stat()
        return ArchiveInfo(
            path=file_path,
            name=file_path.name,
            size=stat.st_size,
            created=datetime.fromtimestamp(stat.st_mtime),
            has_signature=file_path.with_suffix(file_path.suffix + '.sig').exists(),
            has_checksum=any(
                file_path.with_suffix(file_path.suffix + ext).exists()
                for ext in ['.sha256', '.sha512']
            )
        )


class ArchiveVerifier:
    """Verifies archive integrity and signatures"""

    def __init__(self, gpg_config: Optional[GPGConfig] = None,
                 integrity_config: Optional[IntegrityConfig] = None):
        self.gpg_signer = GPGSigner(gpg_config) if gpg_config and gpg_config.enabled else None
        self.integrity_config = integrity_config or IntegrityConfig()

    def verify_archive(self, archive_info: ArchiveInfo) -> Tuple[bool, List[str]]:
        """
        Verify archive integrity

        Args:
            archive_info: Archive to verify

        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []
        file_path = archive_info.path

        # Verify checksum
        if archive_info.has_checksum:
            checksum_valid = self._verify_checksum(file_path)
            if not checksum_valid:
                errors.append("Checksum verification failed")
        else:
            errors.append("No checksum file found")

        # Verify GPG signature
        if self.gpg_signer and archive_info.has_signature:
            sig_path = file_path.with_suffix(file_path.suffix + '.sig')
            if not self.gpg_signer.verify_signature(file_path, sig_path):
                errors.append("GPG signature verification failed")
        elif self.gpg_signer and not archive_info.has_signature:
            errors.append("No GPG signature found")

        # Verify archive can be opened
        if not self._verify_archive_readable(file_path):
            errors.append("Archive is corrupted or unreadable")

        archive_info.is_verified = len(errors) == 0
        archive_info.verification_errors = errors

        return len(errors) == 0, errors

    def _verify_checksum(self, file_path: Path) -> bool:
        """Verify file checksum"""
        import hashlib

        # Try SHA256 first, then SHA512
        for algorithm in ['sha256', 'sha512']:
            checksum_path = file_path.with_suffix(file_path.suffix + f'.{algorithm}')
            if checksum_path.exists():
                try:
                    with open(checksum_path, 'r') as f:
                        expected = f.read().strip().split()[0]

                    hash_func = hashlib.new(algorithm)
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            hash_func.update(chunk)
                    actual = hash_func.hexdigest()

                    return expected == actual
                except Exception as e:
                    logger.error(f"Checksum verification error: {e}")
                    return False

        return False

    def _verify_archive_readable(self, file_path: Path) -> bool:
        """Verify archive can be opened and read"""
        try:
            with tarfile.open(file_path, 'r:*') as tar:
                members = tar.getmembers()
                return len(members) > 0
        except Exception as e:
            logger.error(f"Archive read error: {e}")
            return False


class ArchiveRecovery:
    """Handles archive extraction and recovery"""

    def __init__(self, verifier: ArchiveVerifier):
        self.verifier = verifier

    def recover_archive(self, archive_info: ArchiveInfo, output_dir: Path,
                        verify_first: bool = True) -> Tuple[bool, int, List[str]]:
        """
        Recover/extract a single archive

        Args:
            archive_info: Archive to recover
            output_dir: Output directory
            verify_first: Verify integrity before extraction

        Returns:
            Tuple of (success, files_extracted, errors)
        """
        errors = []
        files_extracted = 0

        # Verify if requested
        if verify_first:
            valid, verify_errors = self.verifier.verify_archive(archive_info)
            if not valid:
                return False, 0, verify_errors

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(archive_info.path, 'r:*') as tar:
                # Security check - prevent path traversal
                for member in tar.getmembers():
                    member_path = output_dir / member.name
                    if not member_path.resolve().is_relative_to(output_dir.resolve()):
                        errors.append(f"Path traversal detected: {member.name}")
                        continue

                # Extract all
                tar.extractall(output_dir)
                files_extracted = len(tar.getmembers())

            logger.info(f"Extracted {files_extracted} files from {archive_info.name}")
            return True, files_extracted, errors

        except Exception as e:
            error_msg = f"Extraction failed: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            return False, files_extracted, errors

    def list_archive_contents(self, archive_info: ArchiveInfo) -> List[Dict]:
        """
        List contents of an archive without extracting

        Args:
            archive_info: Archive to list

        Returns:
            List of file information dictionaries
        """
        contents = []

        try:
            with tarfile.open(archive_info.path, 'r:*') as tar:
                for member in tar.getmembers():
                    contents.append({
                        'name': member.name,
                        'size': member.size,
                        'mtime': datetime.fromtimestamp(member.mtime).isoformat(),
                        'is_dir': member.isdir(),
                        'is_file': member.isfile()
                    })

        except Exception as e:
            logger.error(f"Failed to list archive contents: {e}")

        return contents


class RecoveryManager:
    """High-level recovery manager"""

    def __init__(self, local_dir: Path, remote_mount: Optional[Path],
                 gpg_config: Optional[GPGConfig] = None,
                 integrity_config: Optional[IntegrityConfig] = None):
        self.searcher = ArchiveSearcher(local_dir, remote_mount)
        self.verifier = ArchiveVerifier(gpg_config, integrity_config)
        self.recovery = ArchiveRecovery(self.verifier)
        self.local_dir = local_dir
        self.remote_mount = remote_mount

    def recover_date_range(self, request: RecoveryRequest) -> RecoveryResult:
        """
        Recover all archives within a date range

        Args:
            request: Recovery request details

        Returns:
            RecoveryResult with details
        """
        start_time = datetime.now()
        errors = []
        archives_recovered = 0
        files_extracted = 0
        total_size = 0
        verification_passed = True

        # Find archives
        archives = self.searcher.find_archives_by_date_range(
            request.start_date,
            request.end_date
        )

        logger.info(f"Found {len(archives)} archives for date range "
                    f"{request.start_date} to {request.end_date}")

        # Create output directory
        request.output_path.mkdir(parents=True, exist_ok=True)

        # Recover each archive
        for archive in archives:
            logger.info(f"Recovering: {archive.name}")

            # Create subdirectory for this archive
            archive_output = request.output_path / archive.name.replace('.tar.gz', '').replace('.tar.bz2', '').replace('.tar.xz', '')

            success, extracted, arch_errors = self.recovery.recover_archive(
                archive,
                archive_output,
                verify_first=request.verify_signatures
            )

            if success:
                archives_recovered += 1
                files_extracted += extracted
                total_size += archive.size
            else:
                errors.extend(arch_errors)
                verification_passed = False

        result = RecoveryResult(
            request=request,
            archives_found=len(archives),
            archives_recovered=archives_recovered,
            files_extracted=files_extracted,
            total_size=total_size,
            output_path=request.output_path,
            errors=errors,
            verification_passed=verification_passed,
            start_time=start_time,
            end_time=datetime.now()
        )

        # Save recovery report
        self._save_recovery_report(result)

        return result

    def recover_specific_archive(self, archive_name: str, output_path: Path,
                                  verify: bool = True) -> Tuple[bool, str]:
        """
        Recover a specific archive by name

        Args:
            archive_name: Name of archive to recover
            output_path: Output directory
            verify: Verify before extraction

        Returns:
            Tuple of (success, message)
        """
        archive = self.searcher.find_archive_by_name(archive_name)

        if not archive:
            return False, f"Archive not found: {archive_name}"

        success, files, errors = self.recovery.recover_archive(
            archive, output_path, verify_first=verify
        )

        if success:
            return True, f"Recovered {files} files to {output_path}"
        else:
            return False, f"Recovery failed: {'; '.join(errors)}"

    def verify_archive(self, archive_name: str) -> Tuple[bool, Dict]:
        """
        Verify a specific archive

        Args:
            archive_name: Name of archive to verify

        Returns:
            Tuple of (is_valid, details)
        """
        archive = self.searcher.find_archive_by_name(archive_name)

        if not archive:
            return False, {'error': f"Archive not found: {archive_name}"}

        valid, errors = self.verifier.verify_archive(archive)

        return valid, {
            'archive': archive_name,
            'is_valid': valid,
            'has_signature': archive.has_signature,
            'has_checksum': archive.has_checksum,
            'errors': errors
        }

    def list_available_archives(self, start_date: Optional[datetime] = None,
                                 end_date: Optional[datetime] = None) -> List[Dict]:
        """
        List available archives with optional date filtering

        Args:
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            List of archive information dictionaries
        """
        if start_date is None:
            start_date = datetime(2000, 1, 1)
        if end_date is None:
            end_date = datetime.now() + timedelta(days=1)

        archives = self.searcher.find_archives_by_date_range(start_date, end_date)

        return [
            {
                'name': a.name,
                'path': str(a.path),
                'size': a.size,
                'size_mb': round(a.size / (1024 * 1024), 2),
                'created': a.created.isoformat(),
                'has_signature': a.has_signature,
                'has_checksum': a.has_checksum,
                'location': 'remote' if self.remote_mount and str(self.remote_mount) in str(a.path) else 'local'
            }
            for a in archives
        ]

    def _save_recovery_report(self, result: RecoveryResult):
        """Save recovery report"""
        reports_dir = self.local_dir.parent / "recovery_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = result.start_time.strftime("%Y%m%d_%H%M%S")
        report_file = reports_dir / f"recovery_report_{timestamp}.json"

        try:
            with open(report_file, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            logger.info(f"Recovery report saved: {report_file}")
        except Exception as e:
            logger.error(f"Failed to save recovery report: {e}")

    def get_recovery_statistics(self) -> Dict:
        """Get statistics about available archives"""
        all_archives = self.list_available_archives()

        stats = {
            'total_archives': len(all_archives),
            'total_size_gb': round(sum(a['size'] for a in all_archives) / (1024**3), 2),
            'local_count': len([a for a in all_archives if a['location'] == 'local']),
            'remote_count': len([a for a in all_archives if a['location'] == 'remote']),
            'with_signature': len([a for a in all_archives if a['has_signature']]),
            'with_checksum': len([a for a in all_archives if a['has_checksum']]),
            'date_range': {
                'oldest': min((a['created'] for a in all_archives), default=None),
                'newest': max((a['created'] for a in all_archives), default=None)
            }
        }

        return stats
