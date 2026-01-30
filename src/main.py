#!/usr/bin/env python3
"""
Wazuh Immutable Store - Main CLI Application
Punto di ingresso principale per il sistema di archiviazione
"""

import argparse
import sys
import logging
import yaml
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from models import (
    WazuhConfig, QNAPConfig, ArchiveConfig, GPGConfig,
    IntegrityConfig, RetentionConfig, LocalRetention, RemoteRetention,
    CompressionType, ArchiveInterval, RecoveryRequest
)
from archiver import ArchiveManager, LogCollector, Archiver
from signer import SigningManager, GPGSigner, IntegrityManager
from transfer import TransferManager, NFSManager
from retention import RetentionManager
from recovery import RecoveryManager
from wizard import SetupWizard


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wazuh-immutable-store')


class ConfigLoader:
    """Loads and validates configuration"""

    DEFAULT_PATHS = [
        Path('/etc/wazuh-immutable-store/config.yaml'),
        Path.home() / '.wazuh-immutable-store' / 'config.yaml',
        Path('./config/config.yaml')
    ]

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> dict:
        """Load configuration from file"""
        if config_path and config_path.exists():
            return cls._load_file(config_path)

        for path in cls.DEFAULT_PATHS:
            if path.exists():
                logger.info(f"Loading config from: {path}")
                return cls._load_file(path)

        raise FileNotFoundError(
            "Configuration file not found. Run 'wazuh-immutable-store setup' first."
        )

    @classmethod
    def _load_file(cls, path: Path) -> dict:
        """Load YAML configuration file"""
        with open(path, 'r') as f:
            return yaml.safe_load(f)

    @classmethod
    def to_models(cls, config: dict) -> dict:
        """Convert config dict to model objects"""
        models = {}

        # Wazuh config
        wazuh = config.get('wazuh', {})
        models['wazuh'] = WazuhConfig(
            logs_path=Path(wazuh.get('logs_path', '/var/ossec/logs/archives')),
            file_pattern=wazuh.get('file_pattern', 'archives.json'),
            include_alerts=wazuh.get('include_alerts', True),
            alerts_path=Path(wazuh['alerts_path']) if wazuh.get('alerts_path') else None
        )

        # QNAP config
        qnap = config.get('qnap', {})
        models['qnap'] = QNAPConfig(
            host=qnap.get('host', ''),
            export_path=qnap.get('export_path', '/wazuh-archive'),
            mount_point=Path(qnap.get('mount_point', '/mnt/qnap-wazuh')),
            nfs_version=qnap.get('nfs_version', 4),
            mount_options=qnap.get('mount_options', 'hard,intr')
        )

        # Archive config
        archive = config.get('archive', {})
        comp_type = archive.get('compression', 'gzip')
        models['archive'] = ArchiveConfig(
            compression=CompressionType(comp_type) if comp_type in ['gzip', 'bz2', 'xz'] else CompressionType.GZIP,
            compression_level=archive.get('compression_level', 6),
            naming_pattern=archive.get('naming_pattern', 'wazuh-logs-{date}-{hour}.tar.gz'),
            temp_dir=Path(archive.get('temp_dir', '/tmp/wazuh-archive')),
            interval=ArchiveInterval(archive.get('interval', 'daily'))
        )

        # GPG config
        gpg = config.get('gpg', {})
        models['gpg'] = GPGConfig(
            enabled=gpg.get('enabled', False),
            key_id=gpg.get('key_id', ''),
            gpg_home=gpg.get('gpg_home'),
            detached=gpg.get('detached', True)
        )

        # Integrity config
        integrity = config.get('integrity', {})
        models['integrity'] = IntegrityConfig(
            algorithm=integrity.get('algorithm', 'sha256'),
            create_manifest=integrity.get('create_manifest', True),
            chain_manifests=integrity.get('chain_manifests', True)
        )

        # Retention config
        retention = config.get('retention', {})
        local = retention.get('local', {})
        remote = retention.get('remote', {})
        models['retention'] = RetentionConfig(
            local=LocalRetention(
                days_before_archive=local.get('days_before_archive', 1),
                days_keep_local=local.get('days_keep_local', 7),
                delete_after_transfer=local.get('delete_after_transfer', True)
            ),
            remote=RemoteRetention(
                days=remote.get('days', 2555),
                organize_by_date=remote.get('organize_by_date', True)
            )
        )

        return models


class WazuhImmutableStore:
    """Main application class"""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.config = None
        self.models = None

    def load_config(self):
        """Load configuration"""
        self.config = ConfigLoader.load(self.config_path)
        self.models = ConfigLoader.to_models(self.config)

    def run_archive(self, dry_run: bool = False):
        """Run archive cycle"""
        logger.info("Starting archive cycle...")

        # Initialize managers
        archive_manager = ArchiveManager(
            self.models['wazuh'],
            self.models['archive']
        )

        # Create archives
        records = archive_manager.run_archive_cycle(
            min_age_days=self.models['retention'].local.days_before_archive
        )

        if not records:
            logger.info("No archives created")
            return

        # Sign archives
        manifest_dir = self.models['archive'].temp_dir / 'manifests'
        signing_manager = SigningManager(
            self.models['gpg'],
            self.models['integrity'],
            manifest_dir
        )

        for record in records:
            try:
                signing_manager.sign_and_record(record)
                logger.info(f"Signed archive: {record.id}")
            except Exception as e:
                logger.error(f"Failed to sign {record.id}: {e}")

        # Transfer to QNAP
        if not dry_run:
            transfer_manager = TransferManager(
                self.models['qnap'],
                self.models['retention'].remote
            )

            for record in records:
                transfer_manager.add_to_queue(record)

            successful, failed = transfer_manager.process_queue()
            logger.info(f"Transfer complete: {successful} successful, {failed} failed")

        logger.info("Archive cycle complete")

    def run_retention(self, dry_run: bool = False):
        """Run retention cycle"""
        logger.info("Starting retention cycle...")

        retention_manager = RetentionManager(
            self.models['retention'],
            self.models['archive'].temp_dir,
            self.models['qnap'].mount_point,
            []  # Would load existing records from database
        )

        report = retention_manager.run_retention_cycle(dry_run=dry_run)

        logger.info(f"Retention cycle complete: "
                    f"{report.local_files_deleted} files deleted, "
                    f"{report.local_space_freed / (1024*1024):.2f} MB freed")

    def verify_integrity(self):
        """Verify integrity of all archives"""
        logger.info("Starting integrity verification...")

        manifest_dir = self.models['archive'].temp_dir / 'manifests'
        signing_manager = SigningManager(
            self.models['gpg'],
            self.models['integrity'],
            manifest_dir
        )

        valid, results = signing_manager.verify_all_integrity()

        if valid:
            logger.info("All integrity checks passed")
        else:
            logger.error("Integrity verification failed")
            logger.error(f"Errors: {results}")

        return valid

    def recover(self, start_date: str, end_date: str, output_path: str,
                verify: bool = True):
        """Recover archives within date range"""
        logger.info(f"Starting recovery: {start_date} to {end_date}")

        recovery_manager = RecoveryManager(
            self.models['archive'].temp_dir,
            self.models['qnap'].mount_point,
            self.models['gpg'],
            self.models['integrity']
        )

        request = RecoveryRequest(
            start_date=datetime.fromisoformat(start_date),
            end_date=datetime.fromisoformat(end_date),
            output_path=Path(output_path),
            verify_signatures=verify,
            decompress=True
        )

        result = recovery_manager.recover_date_range(request)

        logger.info(f"Recovery complete: {result.archives_recovered}/{result.archives_found} "
                    f"archives, {result.files_extracted} files")

        if result.errors:
            logger.warning(f"Errors: {result.errors}")

        return result

    def list_archives(self, format_output: str = 'table'):
        """List available archives"""
        recovery_manager = RecoveryManager(
            self.models['archive'].temp_dir,
            self.models['qnap'].mount_point,
            self.models['gpg'],
            self.models['integrity']
        )

        archives = recovery_manager.list_available_archives()

        if format_output == 'json':
            print(json.dumps(archives, indent=2))
        else:
            print(f"\n{'Name':<50} {'Size (MB)':<12} {'Location':<10} {'Date':<20}")
            print("-" * 95)
            for a in archives:
                print(f"{a['name']:<50} {a['size_mb']:<12.2f} {a['location']:<10} {a['created'][:19]}")
            print(f"\nTotal: {len(archives)} archives")

    def check_status(self):
        """Check system status"""
        print("\n" + "=" * 60)
        print("Wazuh Immutable Store - System Status")
        print("=" * 60)

        # Check NFS connectivity
        nfs_manager = NFSManager(self.models['qnap'])
        connected, message = nfs_manager.check_connectivity()

        print(f"\nQNAP NFS Server: {self.models['qnap'].host}")
        print(f"  Export: {self.models['qnap'].export_path}")
        print(f"  Mount point: {self.models['qnap'].mount_point}")
        print(f"  Status: {'✓ Connected' if connected else '✗ Not Connected'}")
        print(f"  Message: {message}")
        print(f"  Mounted: {'✓ Yes' if nfs_manager.is_mounted() else '✗ No'}")

        if nfs_manager.is_mounted():
            usage = nfs_manager.get_disk_usage()
            if usage:
                print(f"  Disk Usage: {usage['used']} / {usage['size']} ({usage['use_percent']})")
        else:
            nfs_ver = self.models['qnap'].nfs_version
            mount_opts = self.models['qnap'].mount_options
            host = self.models['qnap'].host
            export = self.models['qnap'].export_path
            mount_point = self.models['qnap'].mount_point
            print(f"\n  Per montare manualmente:")
            print(f"  sudo mount -t nfs -o vers={nfs_ver},{mount_opts} {host}:{export} {mount_point}")

        # Check Wazuh logs
        print(f"\nWazuh Logs:")
        print(f"  Path: {self.models['wazuh'].logs_path}")
        logs_exist = self.models['wazuh'].logs_path.exists()
        print(f"  Exists: {'✓ Yes' if logs_exist else '✗ No'}")
        if logs_exist:
            import os
            log_files = list(self.models['wazuh'].logs_path.rglob('*'))
            print(f"  Files found: {len(log_files)}")

        # Check GPG
        print(f"\nGPG Signing: {'✓ Enabled' if self.models['gpg'].enabled else '○ Disabled'}")
        if self.models['gpg'].enabled:
            print(f"  Key ID: {self.models['gpg'].key_id}")

        # Show retention policy
        print(f"\nRetention Policy:")
        print(f"  Local: {self.models['retention'].local.days_keep_local} days")
        print(f"  Remote: {self.models['retention'].remote.days} days "
              f"({self.models['retention'].remote.days // 365} years)")

        # Show archive settings
        print(f"\nArchive Settings:")
        print(f"  Compression: {self.models['archive'].compression.value}")
        print(f"  Interval: {self.models['archive'].interval.value}")
        print(f"  Temp dir: {self.models['archive'].temp_dir}")

        print("\n" + "=" * 60)

    def test_connection(self):
        """Test NFS connection and write permissions"""
        print("\n" + "=" * 60)
        print("Wazuh Immutable Store - Connection Test")
        print("=" * 60)

        nfs_manager = NFSManager(self.models['qnap'])

        # Test 1: Check connectivity
        print("\n[1/4] Testing NFS server connectivity...")
        connected, message = nfs_manager.check_connectivity()
        if connected:
            print(f"  ✓ {message}")
        else:
            print(f"  ✗ {message}")
            print(f"\n  Suggerimento: Verifica che il QNAP sia raggiungibile")
            print(f"  ping {self.models['qnap'].host}")
            return False

        # Test 2: Check if mounted
        print("\n[2/4] Checking NFS mount...")
        if nfs_manager.is_mounted():
            print(f"  ✓ NFS is mounted at {self.models['qnap'].mount_point}")
        else:
            print(f"  ✗ NFS is not mounted")
            print(f"\n  Montare con:")
            nfs_ver = self.models['qnap'].nfs_version
            mount_opts = self.models['qnap'].mount_options
            host = self.models['qnap'].host
            export = self.models['qnap'].export_path
            mount_point = self.models['qnap'].mount_point
            print(f"  sudo mount -t nfs -o vers={nfs_ver},{mount_opts} {host}:{export} {mount_point}")
            return False

        # Test 3: Check write permissions
        print("\n[3/4] Testing write permissions...")
        test_file = self.models['qnap'].mount_point / '.wazuh-test-write'
        try:
            test_file.write_text("test")
            test_file.unlink()
            print(f"  ✓ Write permissions OK")
        except PermissionError:
            print(f"  ✗ Permission denied - cannot write to NFS share")
            print(f"\n  Sul QNAP verifica:")
            print(f"  1. L'IP di questo server è autorizzato nell'export NFS")
            print(f"  2. Squash è impostato su 'No mapping' o 'Map root to admin'")
            return False
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False

        # Test 4: Check Wazuh logs
        print("\n[4/4] Checking Wazuh logs...")
        if self.models['wazuh'].logs_path.exists():
            log_files = list(self.models['wazuh'].logs_path.rglob('*.json'))
            print(f"  ✓ Found {len(log_files)} JSON log files")
        else:
            print(f"  ✗ Wazuh logs path not found: {self.models['wazuh'].logs_path}")
            return False

        print("\n" + "=" * 60)
        print("  ✓ All tests passed! System is ready.")
        print("=" * 60)
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Wazuh Immutable Store - Archiviazione immutabile log Wazuh su QNAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Comandi disponibili:
  setup           Esegue il wizard di configurazione iniziale
  status          Mostra lo stato del sistema
  test            Testa connessione NFS e permessi
  archive         Esegue un ciclo di archiviazione
  retention       Esegue il ciclo di retention/pulizia
  verify          Verifica l'integrità degli archivi
  recover         Recupera archivi da un intervallo di date
  list            Lista gli archivi disponibili

Esempi:
  wazuh-immutable-store setup                    # Configurazione iniziale
  wazuh-immutable-store status                   # Verifica stato
  wazuh-immutable-store test                     # Test connessione NFS
  wazuh-immutable-store archive --dry-run        # Test archiviazione
  wazuh-immutable-store archive                  # Archiviazione reale
  wazuh-immutable-store verify                   # Verifica integrità
  wazuh-immutable-store list                     # Lista archivi
  wazuh-immutable-store list --format json       # Lista in JSON
  wazuh-immutable-store recover --start 2025-01-01 --end 2025-01-31 --output /tmp/recovery
        """
    )

    parser.add_argument('command', nargs='?', default='status',
                        choices=['setup', 'archive', 'retention', 'verify',
                                 'recover', 'list', 'status', 'test'],
                        help='Comando da eseguire')

    parser.add_argument('-c', '--config', type=Path,
                        help='Percorso file di configurazione')

    parser.add_argument('--dry-run', action='store_true',
                        help='Esegui senza effettuare modifiche')

    parser.add_argument('--start', type=str,
                        help='Data inizio per recovery (YYYY-MM-DD)')

    parser.add_argument('--end', type=str,
                        help='Data fine per recovery (YYYY-MM-DD)')

    parser.add_argument('--output', type=str,
                        help='Directory output per recovery')

    parser.add_argument('--format', choices=['table', 'json'], default='table',
                        help='Formato output per list')

    parser.add_argument('--no-verify', action='store_true',
                        help='Salta verifica durante recovery')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Output dettagliato')

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle setup command
    if args.command == 'setup':
        wizard = SetupWizard()
        sys.exit(0 if wizard.run() else 1)

    # Load configuration for other commands
    try:
        app = WazuhImmutableStore(args.config)
        app.load_config()
    except FileNotFoundError as e:
        print(f"Errore: {e}")
        print("Esegui 'wazuh-immutable-store setup' per configurare il sistema.")
        sys.exit(1)
    except Exception as e:
        print(f"Errore nel caricamento della configurazione: {e}")
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'archive':
            app.run_archive(dry_run=args.dry_run)

        elif args.command == 'retention':
            app.run_retention(dry_run=args.dry_run)

        elif args.command == 'verify':
            valid = app.verify_integrity()
            sys.exit(0 if valid else 1)

        elif args.command == 'recover':
            if not args.start or not args.end or not args.output:
                print("Errore: --start, --end e --output sono richiesti per recovery")
                sys.exit(1)
            app.recover(args.start, args.end, args.output,
                        verify=not args.no_verify)

        elif args.command == 'list':
            app.list_archives(format_output=args.format)

        elif args.command == 'status':
            app.check_status()

        elif args.command == 'test':
            success = app.test_connection()
            sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\nOperazione annullata")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Errore: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
