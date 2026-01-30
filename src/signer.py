#!/usr/bin/env python3
"""
Wazuh Immutable Store - GPG Signing Module
Gestione della firma digitale e verifica integrità
"""

import os
import subprocess
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List
from dataclasses import dataclass

from models import ArchiveRecord, ArchiveStatus, GPGConfig, IntegrityConfig, ManifestEntry


logger = logging.getLogger(__name__)


class SigningError(Exception):
    """Exception raised for signing operations"""
    pass


class GPGSigner:
    """Handles GPG signing operations for archives"""

    def __init__(self, config: GPGConfig):
        self.config = config
        self.enabled = config.enabled
        self.key_id = config.key_id
        self.gpg_home = config.gpg_home

        if self.enabled:
            self._verify_gpg_setup()

    def _verify_gpg_setup(self):
        """Verify GPG is properly configured"""
        try:
            # Check GPG is installed
            result = subprocess.run(
                ['gpg', '--version'],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise SigningError("GPG is not installed or not accessible")

            # Check key exists
            if self.key_id:
                result = subprocess.run(
                    ['gpg', '--list-secret-keys', self.key_id],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    raise SigningError(f"GPG key not found: {self.key_id}")

            logger.info("GPG signing is properly configured")

        except FileNotFoundError:
            raise SigningError("GPG command not found")

    def sign_file(self, file_path: Path) -> Path:
        """
        Create a detached GPG signature for a file

        Args:
            file_path: Path to file to sign

        Returns:
            Path to signature file
        """
        if not self.enabled:
            raise SigningError("GPG signing is not enabled")

        if not file_path.exists():
            raise SigningError(f"File not found: {file_path}")

        signature_path = file_path.with_suffix(file_path.suffix + '.sig')

        cmd = ['gpg', '--batch', '--yes']

        if self.gpg_home:
            cmd.extend(['--homedir', self.gpg_home])

        if self.key_id:
            cmd.extend(['--default-key', self.key_id])

        if self.config.detached:
            cmd.extend(['--detach-sign', '--armor'])
        else:
            cmd.append('--sign')

        cmd.extend(['--output', str(signature_path), str(file_path)])

        logger.debug(f"Signing command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large files
            )

            if result.returncode != 0:
                raise SigningError(f"GPG signing failed: {result.stderr}")

            logger.info(f"Created signature: {signature_path}")
            return signature_path

        except subprocess.TimeoutExpired:
            raise SigningError("GPG signing timed out")

    def verify_signature(self, file_path: Path, signature_path: Optional[Path] = None) -> bool:
        """
        Verify GPG signature of a file

        Args:
            file_path: Path to signed file
            signature_path: Path to detached signature (optional)

        Returns:
            True if signature is valid
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        # Determine signature path
        if signature_path is None:
            signature_path = file_path.with_suffix(file_path.suffix + '.sig')

        if not signature_path.exists():
            logger.error(f"Signature not found: {signature_path}")
            return False

        cmd = ['gpg', '--batch', '--verify']

        if self.gpg_home:
            cmd.extend(['--homedir', self.gpg_home])

        cmd.extend([str(signature_path), str(file_path)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                logger.info(f"Signature verified: {file_path}")
                return True
            else:
                logger.error(f"Signature verification failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Signature verification timed out")
            return False

    def get_key_info(self) -> dict:
        """Get information about the signing key"""
        if not self.key_id:
            return {}

        try:
            result = subprocess.run(
                ['gpg', '--list-keys', '--with-colons', self.key_id],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                info = {}
                for line in lines:
                    parts = line.split(':')
                    if parts[0] == 'pub':
                        info['key_id'] = parts[4]
                        info['creation_date'] = parts[5]
                        info['expiration_date'] = parts[6] if parts[6] else None
                        info['algorithm'] = parts[3]
                    elif parts[0] == 'uid':
                        info['uid'] = parts[9]
                return info

        except Exception as e:
            logger.error(f"Failed to get key info: {e}")

        return {}


class IntegrityManager:
    """Manages integrity verification using checksums and manifests"""

    def __init__(self, config: IntegrityConfig, manifest_dir: Path):
        self.config = config
        self.algorithm = config.algorithm
        self.manifest_dir = manifest_dir
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = manifest_dir / "manifest.log"
        self.last_manifest_hash: Optional[str] = None

        # Load last manifest hash if exists
        self._load_last_hash()

    def _load_last_hash(self):
        """Load the hash of the last manifest entry"""
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        # Get hash of last entry
                        last_line = lines[-1].strip()
                        if last_line:
                            self.last_manifest_hash = self.calculate_hash(last_line.encode())
            except Exception as e:
                logger.warning(f"Could not load last manifest hash: {e}")

    def calculate_hash(self, data: bytes) -> str:
        """Calculate hash of data"""
        hash_func = hashlib.new(self.algorithm)
        hash_func.update(data)
        return hash_func.hexdigest()

    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate hash of a file"""
        hash_func = hashlib.new(self.algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def create_checksum_file(self, archive_path: Path) -> Path:
        """
        Create a checksum file for an archive

        Args:
            archive_path: Path to archive

        Returns:
            Path to checksum file
        """
        checksum = self.calculate_file_hash(archive_path)
        checksum_path = archive_path.with_suffix(archive_path.suffix + f'.{self.algorithm}')

        with open(checksum_path, 'w') as f:
            f.write(f"{checksum}  {archive_path.name}\n")

        logger.info(f"Created checksum file: {checksum_path}")
        return checksum_path

    def verify_checksum_file(self, archive_path: Path, checksum_path: Optional[Path] = None) -> bool:
        """
        Verify archive against checksum file

        Args:
            archive_path: Path to archive
            checksum_path: Path to checksum file (optional)

        Returns:
            True if checksum matches
        """
        if checksum_path is None:
            checksum_path = archive_path.with_suffix(archive_path.suffix + f'.{self.algorithm}')

        if not checksum_path.exists():
            logger.error(f"Checksum file not found: {checksum_path}")
            return False

        try:
            with open(checksum_path, 'r') as f:
                content = f.read().strip()
                expected_checksum = content.split()[0]

            actual_checksum = self.calculate_file_hash(archive_path)

            if expected_checksum == actual_checksum:
                logger.info(f"Checksum verified: {archive_path}")
                return True
            else:
                logger.error(f"Checksum mismatch for {archive_path}")
                logger.error(f"Expected: {expected_checksum}")
                logger.error(f"Actual: {actual_checksum}")
                return False

        except Exception as e:
            logger.error(f"Checksum verification failed: {e}")
            return False

    def add_manifest_entry(self, record: ArchiveRecord) -> ManifestEntry:
        """
        Add an entry to the manifest with chain hash

        Args:
            record: Archive record to add

        Returns:
            ManifestEntry created
        """
        entry = ManifestEntry(
            archive_id=record.id,
            filename=record.archive_path.name,
            checksum=record.checksum,
            size=record.archive_size,
            created_at=record.created_at,
            previous_manifest_hash=self.last_manifest_hash
        )

        # Write to manifest file
        entry_line = entry.to_line()
        with open(self.manifest_file, 'a') as f:
            f.write(entry_line + '\n')

        # Update chain hash
        self.last_manifest_hash = self.calculate_hash(entry_line.encode())

        # Update record with manifest entry
        record.manifest_entry = entry_line

        logger.info(f"Added manifest entry for: {record.id}")
        return entry

    def verify_manifest_chain(self) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of the entire manifest chain

        Returns:
            Tuple of (is_valid, list of errors)
        """
        if not self.manifest_file.exists():
            return True, []

        errors = []
        previous_hash = None

        try:
            with open(self.manifest_file, 'r') as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue

                # Parse the line
                parts = line.split('  ')
                if len(parts) < 5:
                    errors.append(f"Line {i+1}: Invalid format")
                    continue

                # Extract previous hash reference
                prev_ref = parts[-1]  # PREV:hash or PREV:GENESIS
                if prev_ref.startswith('PREV:'):
                    expected_prev = prev_ref[5:]

                    if expected_prev == 'GENESIS':
                        if previous_hash is not None:
                            errors.append(f"Line {i+1}: Unexpected GENESIS marker")
                    else:
                        if previous_hash is None:
                            errors.append(f"Line {i+1}: Expected GENESIS marker")
                        elif expected_prev != previous_hash:
                            errors.append(f"Line {i+1}: Chain hash mismatch")
                            errors.append(f"  Expected: {expected_prev}")
                            errors.append(f"  Got: {previous_hash}")

                # Calculate hash of this line for next iteration
                previous_hash = self.calculate_hash(line.encode())

            if errors:
                logger.error(f"Manifest chain verification failed with {len(errors)} errors")
                return False, errors

            logger.info("Manifest chain verified successfully")
            return True, []

        except Exception as e:
            errors.append(f"Verification error: {e}")
            return False, errors

    def get_manifest_entries(self) -> List[ManifestEntry]:
        """Load all manifest entries"""
        entries = []

        if not self.manifest_file.exists():
            return entries

        try:
            with open(self.manifest_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split('  ')
                    if len(parts) >= 5:
                        entry = ManifestEntry(
                            archive_id=parts[1].split('-')[1] if '-' in parts[1] else parts[1],
                            filename=parts[1],
                            checksum=parts[0],
                            size=int(parts[2]),
                            created_at=datetime.fromisoformat(parts[3]),
                            previous_manifest_hash=parts[4].replace('PREV:', '') if parts[4] != 'PREV:GENESIS' else None
                        )
                        entries.append(entry)

        except Exception as e:
            logger.error(f"Failed to load manifest entries: {e}")

        return entries


class SigningManager:
    """Combines GPG signing and integrity verification"""

    def __init__(self, gpg_config: GPGConfig, integrity_config: IntegrityConfig,
                 manifest_dir: Path):
        self.gpg_signer = GPGSigner(gpg_config) if gpg_config.enabled else None
        self.integrity_manager = IntegrityManager(integrity_config, manifest_dir)

    def sign_and_record(self, record: ArchiveRecord) -> ArchiveRecord:
        """
        Sign an archive and add to manifest

        Args:
            record: Archive record to sign

        Returns:
            Updated archive record
        """
        record.status = ArchiveStatus.SIGNING

        try:
            # Create checksum file
            self.integrity_manager.create_checksum_file(record.archive_path)

            # GPG sign if enabled
            if self.gpg_signer and self.gpg_signer.enabled:
                signature_path = self.gpg_signer.sign_file(record.archive_path)
                record.signature_path = signature_path

            # Add to manifest with chain
            self.integrity_manager.add_manifest_entry(record)

            record.status = ArchiveStatus.PENDING
            logger.info(f"Archive signed and recorded: {record.id}")

            return record

        except Exception as e:
            logger.error(f"Signing failed for {record.id}: {e}")
            record.status = ArchiveStatus.FAILED
            raise SigningError(f"Signing failed: {e}")

    def verify_archive_complete(self, archive_path: Path,
                                signature_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
        """
        Perform complete verification of an archive

        Args:
            archive_path: Path to archive
            signature_path: Path to signature (optional)

        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []

        # Verify checksum
        if not self.integrity_manager.verify_checksum_file(archive_path):
            errors.append("Checksum verification failed")

        # Verify GPG signature if available
        if self.gpg_signer and self.gpg_signer.enabled:
            if signature_path is None:
                signature_path = archive_path.with_suffix(archive_path.suffix + '.sig')

            if signature_path.exists():
                if not self.gpg_signer.verify_signature(archive_path, signature_path):
                    errors.append("GPG signature verification failed")
            else:
                errors.append("GPG signature file not found")

        return len(errors) == 0, errors

    def verify_all_integrity(self) -> Tuple[bool, dict]:
        """
        Verify integrity of all archives in manifest

        Returns:
            Tuple of (all_valid, detailed_results)
        """
        results = {
            'manifest_chain_valid': False,
            'chain_errors': [],
            'archives_checked': 0,
            'archives_valid': 0,
            'archive_errors': []
        }

        # Verify manifest chain
        chain_valid, chain_errors = self.integrity_manager.verify_manifest_chain()
        results['manifest_chain_valid'] = chain_valid
        results['chain_errors'] = chain_errors

        # TODO: Could also verify each archive file if paths are accessible
        # This would be done during recovery operations

        return chain_valid and len(chain_errors) == 0, results
