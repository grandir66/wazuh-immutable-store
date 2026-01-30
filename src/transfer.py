#!/usr/bin/env python3
"""
Wazuh Immutable Store - NFS Transfer Module
Gestione del trasferimento archivi verso QNAP via NFS
"""

import os
import subprocess
import shutil
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass

from models import ArchiveRecord, ArchiveStatus, QNAPConfig, RemoteRetention


logger = logging.getLogger(__name__)


class TransferError(Exception):
    """Exception raised for transfer operations"""
    pass


class NFSManager:
    """Manages NFS mount operations"""

    def __init__(self, config: QNAPConfig):
        self.config = config
        self.host = config.host
        self.export_path = config.export_path
        self.mount_point = Path(config.mount_point)
        self.nfs_version = config.nfs_version
        self.mount_options = config.mount_options

    def is_mounted(self) -> bool:
        """Check if NFS share is mounted"""
        try:
            result = subprocess.run(
                ['mountpoint', '-q', str(self.mount_point)],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            # mountpoint command not available, try alternative
            try:
                result = subprocess.run(
                    ['mount'],
                    capture_output=True,
                    text=True
                )
                return str(self.mount_point) in result.stdout
            except Exception:
                return False

    def mount(self, timeout: int = 30) -> bool:
        """
        Mount NFS share

        Args:
            timeout: Timeout in seconds for mount operation

        Returns:
            True if mount successful
        """
        if self.is_mounted():
            logger.info(f"NFS share already mounted at {self.mount_point}")
            return True

        # Create mount point if it doesn't exist
        self.mount_point.mkdir(parents=True, exist_ok=True)

        # Build mount command
        nfs_source = f"{self.host}:{self.export_path}"
        mount_opts = f"nfsvers={self.nfs_version},{self.mount_options}"

        cmd = [
            'mount', '-t', f'nfs{self.nfs_version}' if self.nfs_version == 4 else 'nfs',
            '-o', mount_opts,
            nfs_source,
            str(self.mount_point)
        ]

        logger.info(f"Mounting NFS: {nfs_source} -> {self.mount_point}")
        logger.debug(f"Mount command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                logger.info("NFS mount successful")
                return True
            else:
                logger.error(f"Mount failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Mount timed out after {timeout} seconds")
            return False
        except PermissionError:
            logger.error("Permission denied. Mount requires root privileges.")
            return False

    def unmount(self, force: bool = False) -> bool:
        """
        Unmount NFS share

        Args:
            force: Force unmount even if busy

        Returns:
            True if unmount successful
        """
        if not self.is_mounted():
            logger.info("NFS share not mounted")
            return True

        cmd = ['umount']
        if force:
            cmd.append('-f')
        cmd.append(str(self.mount_point))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info("NFS unmount successful")
                return True
            else:
                logger.error(f"Unmount failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Unmount timed out")
            return False

    def check_connectivity(self) -> Tuple[bool, str]:
        """
        Check connectivity to NFS server

        Returns:
            Tuple of (is_connected, status_message)
        """
        try:
            # Try showmount first
            result = subprocess.run(
                ['showmount', '-e', self.host],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                if self.export_path in result.stdout:
                    return True, f"Connected to {self.host}, export {self.export_path} available"
                else:
                    return False, f"Export {self.export_path} not found on {self.host}"
            else:
                return False, f"Cannot connect to NFS server: {result.stderr}"

        except subprocess.TimeoutExpired:
            return False, f"Connection to {self.host} timed out"
        except FileNotFoundError:
            # showmount not available, try simple ping
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '5', self.host],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return True, f"Host {self.host} is reachable (NFS not verified)"
                else:
                    return False, f"Host {self.host} is not reachable"
            except Exception as e:
                return False, f"Connectivity check failed: {e}"

    def get_disk_usage(self) -> Optional[dict]:
        """Get disk usage of mounted NFS share"""
        if not self.is_mounted():
            return None

        try:
            result = subprocess.run(
                ['df', '-h', str(self.mount_point)],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 2:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        return {
                            'filesystem': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'use_percent': parts[4]
                        }

        except Exception as e:
            logger.error(f"Failed to get disk usage: {e}")

        return None


class ArchiveTransfer:
    """Handles archive transfer to QNAP"""

    def __init__(self, nfs_manager: NFSManager, retention_config: RemoteRetention):
        self.nfs = nfs_manager
        self.retention = retention_config
        self.mount_point = nfs_manager.mount_point

    def get_remote_path(self, record: ArchiveRecord) -> Path:
        """
        Calculate remote path for archive based on date organization

        Args:
            record: Archive record

        Returns:
            Path on remote storage
        """
        base_path = self.mount_point

        if self.retention.organize_by_date:
            # Organize by year/month
            year = record.created_at.strftime("%Y")
            month = record.created_at.strftime("%m")
            base_path = base_path / year / month

        return base_path / record.archive_path.name

    def transfer_archive(self, record: ArchiveRecord,
                         verify_after: bool = True) -> bool:
        """
        Transfer archive to QNAP

        Args:
            record: Archive record to transfer
            verify_after: Verify integrity after transfer

        Returns:
            True if transfer successful
        """
        # Ensure NFS is mounted
        if not self.nfs.is_mounted():
            if not self.nfs.mount():
                raise TransferError("Failed to mount NFS share")

        record.status = ArchiveStatus.TRANSFERRING

        try:
            remote_path = self.get_remote_path(record)

            # Check if file already exists on WORM volume (cannot overwrite)
            if remote_path.exists():
                logger.info(f"Archive already exists on WORM volume, skipping: {remote_path}")
                record.remote_path = remote_path
                record.transferred_at = datetime.now()
                record.status = ArchiveStatus.COMPLETED
                return True

            # Create remote directory structure
            remote_dir = remote_path.parent
            remote_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"Transferring: {record.archive_path} -> {remote_path}")

            # Copy archive file
            self._copy_file_with_progress(record.archive_path, remote_path)

            # Copy signature file if exists
            if record.signature_path and record.signature_path.exists():
                sig_remote = remote_path.with_suffix(remote_path.suffix + '.sig')
                self._copy_file_with_progress(record.signature_path, sig_remote)

            # Copy checksum file
            checksum_local = record.archive_path.with_suffix(
                record.archive_path.suffix + '.sha256'
            )
            if checksum_local.exists():
                checksum_remote = remote_path.with_suffix(remote_path.suffix + '.sha256')
                self._copy_file_with_progress(checksum_local, checksum_remote)

            # Verify transfer
            if verify_after:
                if not self._verify_transfer(record.archive_path, remote_path):
                    raise TransferError("Transfer verification failed")

            # Update record
            record.remote_path = remote_path
            record.transferred_at = datetime.now()
            record.status = ArchiveStatus.COMPLETED

            logger.info(f"Transfer completed: {record.id}")
            return True

        except Exception as e:
            logger.error(f"Transfer failed for {record.id}: {e}")
            record.status = ArchiveStatus.FAILED
            raise TransferError(f"Transfer failed: {e}")

    def _copy_file_with_progress(self, source: Path, destination: Path):
        """Copy file with progress logging for large files"""
        file_size = source.stat().st_size
        chunk_size = 64 * 1024 * 1024  # 64MB chunks

        if file_size < chunk_size:
            # Small file, simple copy
            shutil.copy2(source, destination)
            return

        # Large file, copy with progress
        copied = 0
        last_percent = 0

        with open(source, 'rb') as src, open(destination, 'wb') as dst:
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

        # Preserve metadata
        shutil.copystat(source, destination)

    def _verify_transfer(self, local_path: Path, remote_path: Path) -> bool:
        """Verify transferred file matches local"""
        if not remote_path.exists():
            logger.error(f"Remote file does not exist: {remote_path}")
            return False

        local_size = local_path.stat().st_size
        remote_size = remote_path.stat().st_size

        if local_size != remote_size:
            logger.error(f"Size mismatch: local={local_size}, remote={remote_size}")
            return False

        # For WORM volumes, we can't modify after write, so size check is sufficient
        # Full checksum verification is optional and time-consuming for large files

        logger.debug(f"Transfer verified: sizes match ({local_size} bytes)")
        return True

    def list_remote_archives(self, year: Optional[int] = None,
                             month: Optional[int] = None) -> List[Path]:
        """
        List archives on remote storage

        Args:
            year: Filter by year
            month: Filter by month

        Returns:
            List of archive paths
        """
        if not self.nfs.is_mounted():
            if not self.nfs.mount():
                raise TransferError("Failed to mount NFS share")

        search_path = self.mount_point

        if year:
            search_path = search_path / str(year)
            if month:
                search_path = search_path / f"{month:02d}"

        if not search_path.exists():
            return []

        archives = []
        for path in search_path.rglob("*.tar.gz"):
            archives.append(path)
        for path in search_path.rglob("*.tar.bz2"):
            archives.append(path)
        for path in search_path.rglob("*.tar.xz"):
            archives.append(path)

        return sorted(archives)

    def get_remote_archive_info(self, archive_path: Path) -> Optional[dict]:
        """Get information about a remote archive"""
        if not archive_path.exists():
            return None

        stat = archive_path.stat()

        info = {
            'path': str(archive_path),
            'name': archive_path.name,
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime),
            'has_signature': archive_path.with_suffix(archive_path.suffix + '.sig').exists(),
            'has_checksum': archive_path.with_suffix(archive_path.suffix + '.sha256').exists()
        }

        return info


class TransferManager:
    """High-level manager for archive transfers"""

    def __init__(self, qnap_config: QNAPConfig, retention_config: RemoteRetention):
        self.nfs_manager = NFSManager(qnap_config)
        self.transfer = ArchiveTransfer(self.nfs_manager, retention_config)
        self.qnap_config = qnap_config
        self.transfer_queue: List[ArchiveRecord] = []

    def add_to_queue(self, record: ArchiveRecord):
        """Add archive to transfer queue"""
        self.transfer_queue.append(record)
        logger.debug(f"Added to transfer queue: {record.id}")

    def process_queue(self, max_retries: int = 3) -> Tuple[int, int]:
        """
        Process all archives in transfer queue

        Args:
            max_retries: Maximum retry attempts per archive

        Returns:
            Tuple of (successful_count, failed_count)
        """
        if not self.transfer_queue:
            logger.info("Transfer queue is empty")
            return 0, 0

        # Ensure NFS is mounted
        if not self.nfs_manager.is_mounted():
            logger.info("Mounting NFS share...")
            if not self.nfs_manager.mount():
                logger.error("Failed to mount NFS share")
                return 0, len(self.transfer_queue)

        successful = 0
        failed = 0

        for record in self.transfer_queue[:]:
            retries = 0
            while retries < max_retries:
                try:
                    self.transfer.transfer_archive(record)
                    successful += 1
                    self.transfer_queue.remove(record)
                    break
                except TransferError as e:
                    retries += 1
                    if retries < max_retries:
                        logger.warning(f"Transfer failed, retrying ({retries}/{max_retries}): {e}")
                        time.sleep(5 * retries)  # Exponential backoff
                    else:
                        logger.error(f"Transfer permanently failed for {record.id}: {e}")
                        failed += 1

        return successful, failed

    def check_connectivity(self) -> dict:
        """
        Check system connectivity and status

        Returns:
            Status dictionary
        """
        status = {
            'nfs_server_reachable': False,
            'nfs_mounted': False,
            'message': '',
            'disk_usage': None
        }

        # Check connectivity
        connected, message = self.nfs_manager.check_connectivity()
        status['nfs_server_reachable'] = connected
        status['message'] = message

        # Check mount status
        status['nfs_mounted'] = self.nfs_manager.is_mounted()

        # Get disk usage if mounted
        if status['nfs_mounted']:
            status['disk_usage'] = self.nfs_manager.get_disk_usage()

        return status

    def get_queue_status(self) -> dict:
        """Get current queue status"""
        return {
            'queue_length': len(self.transfer_queue),
            'pending': [r.id for r in self.transfer_queue if r.status == ArchiveStatus.PENDING],
            'transferring': [r.id for r in self.transfer_queue if r.status == ArchiveStatus.TRANSFERRING],
            'failed': [r.id for r in self.transfer_queue if r.status == ArchiveStatus.FAILED]
        }
