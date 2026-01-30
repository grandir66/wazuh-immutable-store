#!/usr/bin/env python3
"""
Wazuh Immutable Store - Interactive Menu System
Sistema a menu interattivo per la gestione delle operazioni
"""

import os
import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any

logger = logging.getLogger(__name__)


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')


def press_enter_to_continue():
    """Wait for user to press Enter"""
    input("\nPremi INVIO per continuare...")


class MenuColors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output"""
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
        cls.END = ''


# Disable colors if not a TTY
if not sys.stdout.isatty():
    MenuColors.disable()


class MenuItem:
    """Represents a menu item"""

    def __init__(self, key: str, label: str, action: Optional[Callable] = None,
                 submenu: 'Menu' = None, description: str = ""):
        self.key = key
        self.label = label
        self.action = action
        self.submenu = submenu
        self.description = description


class Menu:
    """Interactive menu class"""

    def __init__(self, title: str, items: List[MenuItem] = None):
        self.title = title
        self.items = items or []
        self.parent = None

    def add_item(self, item: MenuItem):
        """Add item to menu"""
        if item.submenu:
            item.submenu.parent = self
        self.items.append(item)

    def display(self):
        """Display the menu"""
        clear_screen()
        self._print_header()
        self._print_items()
        self._print_footer()

    def _print_header(self):
        """Print menu header"""
        width = 60
        print(f"{MenuColors.CYAN}{'=' * width}{MenuColors.END}")
        print(f"{MenuColors.BOLD}{MenuColors.CYAN}{self.title.center(width)}{MenuColors.END}")
        print(f"{MenuColors.CYAN}{'=' * width}{MenuColors.END}")
        print()

    def _print_items(self):
        """Print menu items"""
        for item in self.items:
            key_display = f"[{item.key}]"
            print(f"  {MenuColors.GREEN}{key_display:>4}{MenuColors.END}  {item.label}")
            if item.description:
                print(f"       {MenuColors.YELLOW}{item.description}{MenuColors.END}")

    def _print_footer(self):
        """Print menu footer"""
        print()
        print(f"{MenuColors.CYAN}{'-' * 60}{MenuColors.END}")
        if self.parent:
            print(f"  {MenuColors.YELLOW}[0]{MenuColors.END}  Torna al menu precedente")
        print(f"  {MenuColors.RED}[q]{MenuColors.END}  Esci")
        print()

    def get_choice(self) -> str:
        """Get user's choice"""
        return input(f"{MenuColors.BOLD}Seleziona un'opzione: {MenuColors.END}").strip().lower()

    def run(self) -> bool:
        """Run the menu loop. Returns True if should continue parent menu."""
        while True:
            self.display()
            choice = self.get_choice()

            if choice == 'q':
                return False

            if choice == '0' and self.parent:
                return True

            # Find matching item
            for item in self.items:
                if item.key.lower() == choice:
                    if item.submenu:
                        if not item.submenu.run():
                            return False
                    elif item.action:
                        try:
                            item.action()
                        except Exception as e:
                            print(f"\n{MenuColors.RED}Errore: {e}{MenuColors.END}")
                        press_enter_to_continue()
                    break
            else:
                if choice not in ['q', '0']:
                    print(f"\n{MenuColors.RED}Opzione non valida: {choice}{MenuColors.END}")
                    press_enter_to_continue()

        return True


class InteractiveMenu:
    """Main interactive menu system for Wazuh Immutable Store"""

    def __init__(self, app):
        """
        Initialize interactive menu

        Args:
            app: WazuhImmutableStore instance
        """
        self.app = app
        self.main_menu = self._build_main_menu()

    def _build_main_menu(self) -> Menu:
        """Build the main menu structure"""
        main_menu = Menu("Wazuh Immutable Store")

        # Status
        main_menu.add_item(MenuItem(
            key="1",
            label="Stato del Sistema",
            action=self._show_status,
            description="Verifica connessione, configurazione e stato"
        ))

        # Archive submenu
        archive_menu = self._build_archive_menu()
        main_menu.add_item(MenuItem(
            key="2",
            label="Archiviazione",
            submenu=archive_menu,
            description="Gestione cicli di archiviazione"
        ))

        # Browse/Recovery submenu
        browse_menu = self._build_browse_menu()
        main_menu.add_item(MenuItem(
            key="3",
            label="Consultazione Log",
            submenu=browse_menu,
            description="Sfoglia, cerca e recupera log archiviati"
        ))

        # Verification submenu
        verify_menu = self._build_verify_menu()
        main_menu.add_item(MenuItem(
            key="4",
            label="Verifica Integrità",
            submenu=verify_menu,
            description="Verifica firme e checksum degli archivi"
        ))

        # Retention submenu
        retention_menu = self._build_retention_menu()
        main_menu.add_item(MenuItem(
            key="5",
            label="Retention / Pulizia",
            submenu=retention_menu,
            description="Gestione policy di retention"
        ))

        # Test
        main_menu.add_item(MenuItem(
            key="6",
            label="Test Connessione",
            action=self._test_connection,
            description="Test completo di connessione e permessi"
        ))

        return main_menu

    def _build_archive_menu(self) -> Menu:
        """Build archive submenu"""
        menu = Menu("Archiviazione")

        menu.add_item(MenuItem(
            key="1",
            label="Esegui Archiviazione (dry-run)",
            action=self._archive_dry_run,
            description="Simula archiviazione senza modifiche"
        ))

        menu.add_item(MenuItem(
            key="2",
            label="Esegui Archiviazione",
            action=self._archive_run,
            description="Esegue ciclo di archiviazione completo"
        ))

        menu.add_item(MenuItem(
            key="3",
            label="Lista Archivi Locali",
            action=self._list_local_archives,
            description="Mostra archivi in attesa di trasferimento"
        ))

        menu.add_item(MenuItem(
            key="4",
            label="Lista Archivi Remoti",
            action=self._list_remote_archives,
            description="Mostra archivi su QNAP"
        ))

        return menu

    def _build_browse_menu(self) -> Menu:
        """Build browse/recovery submenu"""
        menu = Menu("Consultazione Log")

        menu.add_item(MenuItem(
            key="1",
            label="Lista Tutti gli Archivi",
            action=self._list_all_archives,
            description="Mostra tutti gli archivi disponibili"
        ))

        menu.add_item(MenuItem(
            key="2",
            label="Cerca per Data",
            action=self._search_by_date,
            description="Cerca archivi in un intervallo di date"
        ))

        menu.add_item(MenuItem(
            key="3",
            label="Visualizza Contenuto Archivio",
            action=self._view_archive_contents,
            description="Lista file contenuti in un archivio"
        ))

        menu.add_item(MenuItem(
            key="4",
            label="Recupera Archivio Singolo",
            action=self._recover_single_archive,
            description="Estrae un singolo archivio"
        ))

        menu.add_item(MenuItem(
            key="5",
            label="Recupera per Intervallo Date",
            action=self._recover_date_range,
            description="Estrae tutti gli archivi in un periodo"
        ))

        menu.add_item(MenuItem(
            key="6",
            label="Statistiche Archivi",
            action=self._show_archive_stats,
            description="Mostra statistiche sugli archivi"
        ))

        return menu

    def _build_verify_menu(self) -> Menu:
        """Build verification submenu"""
        menu = Menu("Verifica Integrità")

        menu.add_item(MenuItem(
            key="1",
            label="Verifica Tutti gli Archivi",
            action=self._verify_all,
            description="Verifica integrità di tutti gli archivi"
        ))

        menu.add_item(MenuItem(
            key="2",
            label="Verifica Archivio Singolo",
            action=self._verify_single,
            description="Verifica un archivio specifico"
        ))

        menu.add_item(MenuItem(
            key="3",
            label="Verifica Chain Manifest",
            action=self._verify_chain,
            description="Verifica catena di hash manifest"
        ))

        return menu

    def _build_retention_menu(self) -> Menu:
        """Build retention submenu"""
        menu = Menu("Retention / Pulizia")

        menu.add_item(MenuItem(
            key="1",
            label="Mostra Policy Retention",
            action=self._show_retention_policy,
            description="Visualizza policy di retention configurate"
        ))

        menu.add_item(MenuItem(
            key="2",
            label="Analizza Log Storici Wazuh",
            action=self._analyze_historical,
            description="Scansiona log storici e mostra stato archiviazione"
        ))

        menu.add_item(MenuItem(
            key="3",
            label="Pulisci Log Locali (dry-run)",
            action=self._cleanup_local_dry_run,
            description="Simula pulizia log già archiviati su WORM"
        ))

        menu.add_item(MenuItem(
            key="4",
            label="Pulisci Log Locali",
            action=self._cleanup_local_run,
            description="Elimina log locali già archiviati su WORM"
        ))

        menu.add_item(MenuItem(
            key="5",
            label="Esegui Retention (dry-run)",
            action=self._retention_dry_run,
            description="Simula pulizia archivi temp senza cancellare"
        ))

        menu.add_item(MenuItem(
            key="6",
            label="Esegui Retention",
            action=self._retention_run,
            description="Esegue ciclo di pulizia archivi temp"
        ))

        return menu

    # === Action Methods ===

    def _show_status(self):
        """Show system status"""
        self.app.check_status()

    def _test_connection(self):
        """Test connection"""
        self.app.test_connection()

    def _archive_dry_run(self):
        """Run archive in dry-run mode"""
        print(f"\n{MenuColors.YELLOW}Esecuzione archiviazione (simulazione)...{MenuColors.END}\n")
        self.app.run_archive(dry_run=True)

    def _archive_run(self):
        """Run actual archive"""
        confirm = input(f"\n{MenuColors.YELLOW}Confermi l'esecuzione dell'archiviazione? [s/N]: {MenuColors.END}").strip().lower()
        if confirm == 's':
            print(f"\n{MenuColors.GREEN}Esecuzione archiviazione...{MenuColors.END}\n")
            self.app.run_archive(dry_run=False)
        else:
            print("Operazione annullata")

    def _list_local_archives(self):
        """List local archives"""
        from recovery import RecoveryManager

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            None,  # No remote
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        archives = recovery_manager.list_available_archives()
        self._display_archives_table(archives, "Archivi Locali")

    def _list_remote_archives(self):
        """List remote archives"""
        from recovery import RecoveryManager

        # Check if mounted
        if not self.app.models['qnap'].mount_point.exists():
            print(f"\n{MenuColors.RED}NFS non montato{MenuColors.END}")
            return

        recovery_manager = RecoveryManager(
            Path('/nonexistent'),  # No local
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        archives = recovery_manager.list_available_archives()
        self._display_archives_table(archives, "Archivi Remoti (QNAP)")

    def _list_all_archives(self):
        """List all archives"""
        from recovery import RecoveryManager

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        archives = recovery_manager.list_available_archives()
        self._display_archives_table(archives, "Tutti gli Archivi")

    def _search_by_date(self):
        """Search archives by date range"""
        from recovery import RecoveryManager

        print(f"\n{MenuColors.CYAN}=== Ricerca per Data ==={MenuColors.END}\n")

        # Get date range from user
        start_str = input("Data inizio (YYYY-MM-DD) [default: 30 giorni fa]: ").strip()
        end_str = input("Data fine (YYYY-MM-DD) [default: oggi]: ").strip()

        try:
            if start_str:
                start_date = datetime.strptime(start_str, "%Y-%m-%d")
            else:
                start_date = datetime.now() - timedelta(days=30)

            if end_str:
                end_date = datetime.strptime(end_str, "%Y-%m-%d")
            else:
                end_date = datetime.now()

            # Add end of day
            end_date = end_date.replace(hour=23, minute=59, second=59)

        except ValueError as e:
            print(f"\n{MenuColors.RED}Formato data non valido: {e}{MenuColors.END}")
            return

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        archives = recovery_manager.searcher.find_archives_by_date_range(start_date, end_date)

        # Convert to dict format
        archives_list = [
            {
                'name': a.name,
                'path': str(a.path),
                'size': a.size,
                'size_mb': round(a.size / (1024 * 1024), 2),
                'created': a.created.isoformat(),
                'has_signature': a.has_signature,
                'has_checksum': a.has_checksum,
                'location': 'remote' if self.app.models['qnap'].mount_point and
                           str(self.app.models['qnap'].mount_point) in str(a.path) else 'local'
            }
            for a in archives
        ]

        self._display_archives_table(archives_list,
                                     f"Archivi dal {start_date.strftime('%Y-%m-%d')} al {end_date.strftime('%Y-%m-%d')}")

    def _view_archive_contents(self):
        """View contents of an archive"""
        from recovery import RecoveryManager

        print(f"\n{MenuColors.CYAN}=== Visualizza Contenuto Archivio ==={MenuColors.END}\n")

        archive_name = input("Nome archivio (o parte del nome): ").strip()
        if not archive_name:
            print("Nome archivio richiesto")
            return

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        # Find matching archives
        all_archives = recovery_manager.list_available_archives()
        matches = [a for a in all_archives if archive_name.lower() in a['name'].lower()]

        if not matches:
            print(f"\n{MenuColors.RED}Nessun archivio trovato con '{archive_name}'{MenuColors.END}")
            return

        if len(matches) > 1:
            print(f"\n{MenuColors.YELLOW}Trovati {len(matches)} archivi:{MenuColors.END}")
            for i, a in enumerate(matches, 1):
                print(f"  {i}. {a['name']}")
            choice = input("\nSeleziona numero: ").strip()
            try:
                idx = int(choice) - 1
                archive_info = matches[idx]
            except (ValueError, IndexError):
                print("Selezione non valida")
                return
        else:
            archive_info = matches[0]

        # Get archive details
        archive = recovery_manager.searcher.find_archive_by_name(archive_info['name'])
        if not archive:
            print(f"\n{MenuColors.RED}Archivio non trovato{MenuColors.END}")
            return

        contents = recovery_manager.recovery.list_archive_contents(archive)

        print(f"\n{MenuColors.CYAN}=== Contenuto: {archive_info['name']} ==={MenuColors.END}")
        print(f"Dimensione: {archive_info['size_mb']:.2f} MB")
        print(f"Posizione: {archive_info['location']}")
        print(f"Firma GPG: {'Sì' if archive_info['has_signature'] else 'No'}")
        print(f"Checksum: {'Sì' if archive_info['has_checksum'] else 'No'}")
        print(f"\n{MenuColors.YELLOW}File contenuti ({len(contents)}):{MenuColors.END}\n")

        for item in contents[:50]:  # Limit to first 50
            if item['is_dir']:
                print(f"  {MenuColors.BLUE}[DIR]{MenuColors.END}  {item['name']}")
            else:
                size_kb = item['size'] / 1024
                print(f"  {MenuColors.GREEN}[FILE]{MenuColors.END} {item['name']} ({size_kb:.1f} KB)")

        if len(contents) > 50:
            print(f"\n  ... e altri {len(contents) - 50} elementi")

    def _recover_single_archive(self):
        """Recover a single archive"""
        from recovery import RecoveryManager

        print(f"\n{MenuColors.CYAN}=== Recupera Archivio Singolo ==={MenuColors.END}\n")

        archive_name = input("Nome archivio: ").strip()
        if not archive_name:
            print("Nome archivio richiesto")
            return

        output_path = input("Directory di output [/tmp/wazuh-recovery]: ").strip()
        if not output_path:
            output_path = "/tmp/wazuh-recovery"

        verify = input("Verificare integrità prima dell'estrazione? [S/n]: ").strip().lower()
        verify = verify != 'n'

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        print(f"\n{MenuColors.YELLOW}Recupero in corso...{MenuColors.END}")

        success, message = recovery_manager.recover_specific_archive(
            archive_name, Path(output_path), verify=verify
        )

        if success:
            print(f"\n{MenuColors.GREEN}✓ {message}{MenuColors.END}")
        else:
            print(f"\n{MenuColors.RED}✗ {message}{MenuColors.END}")

    def _recover_date_range(self):
        """Recover archives in date range"""
        from recovery import RecoveryManager
        from models import RecoveryRequest

        print(f"\n{MenuColors.CYAN}=== Recupera per Intervallo Date ==={MenuColors.END}\n")

        start_str = input("Data inizio (YYYY-MM-DD): ").strip()
        end_str = input("Data fine (YYYY-MM-DD): ").strip()

        if not start_str or not end_str:
            print("Date richieste")
            return

        try:
            start_date = datetime.strptime(start_str, "%Y-%m-%d")
            end_date = datetime.strptime(end_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
        except ValueError as e:
            print(f"\n{MenuColors.RED}Formato data non valido: {e}{MenuColors.END}")
            return

        output_path = input("Directory di output [/tmp/wazuh-recovery]: ").strip()
        if not output_path:
            output_path = "/tmp/wazuh-recovery"

        verify = input("Verificare integrità prima dell'estrazione? [S/n]: ").strip().lower()
        verify = verify != 'n'

        confirm = input(f"\n{MenuColors.YELLOW}Recuperare archivi dal {start_str} al {end_str}? [s/N]: {MenuColors.END}").strip().lower()
        if confirm != 's':
            print("Operazione annullata")
            return

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        request = RecoveryRequest(
            start_date=start_date,
            end_date=end_date,
            output_path=Path(output_path),
            verify_signatures=verify,
            decompress=True
        )

        print(f"\n{MenuColors.YELLOW}Recupero in corso...{MenuColors.END}")

        result = recovery_manager.recover_date_range(request)

        print(f"\n{MenuColors.CYAN}=== Risultato Recupero ==={MenuColors.END}")
        print(f"  Archivi trovati: {result.archives_found}")
        print(f"  Archivi recuperati: {result.archives_recovered}")
        print(f"  File estratti: {result.files_extracted}")
        print(f"  Dimensione totale: {result.total_size / (1024*1024):.2f} MB")
        print(f"  Output: {result.output_path}")
        print(f"  Verifica: {'Passata' if result.verification_passed else 'Fallita'}")

        if result.errors:
            print(f"\n{MenuColors.RED}Errori:{MenuColors.END}")
            for error in result.errors:
                print(f"  - {error}")

    def _show_archive_stats(self):
        """Show archive statistics"""
        from recovery import RecoveryManager

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        stats = recovery_manager.get_recovery_statistics()

        print(f"\n{MenuColors.CYAN}=== Statistiche Archivi ==={MenuColors.END}\n")
        print(f"  Archivi totali:     {stats['total_archives']}")
        print(f"  Dimensione totale:  {stats['total_size_gb']:.2f} GB")
        print(f"  Archivi locali:     {stats['local_count']}")
        print(f"  Archivi remoti:     {stats['remote_count']}")
        print(f"  Con firma GPG:      {stats['with_signature']}")
        print(f"  Con checksum:       {stats['with_checksum']}")

        if stats['date_range']['oldest']:
            print(f"\n  Archivio più vecchio: {stats['date_range']['oldest'][:10]}")
            print(f"  Archivio più recente: {stats['date_range']['newest'][:10]}")

    def _verify_all(self):
        """Verify all archives"""
        print(f"\n{MenuColors.YELLOW}Verifica integrità di tutti gli archivi...{MenuColors.END}\n")
        valid = self.app.verify_integrity()

        if valid:
            print(f"\n{MenuColors.GREEN}✓ Tutti gli archivi sono integri{MenuColors.END}")
        else:
            print(f"\n{MenuColors.RED}✗ Alcuni archivi hanno problemi di integrità{MenuColors.END}")

    def _verify_single(self):
        """Verify a single archive"""
        from recovery import RecoveryManager

        print(f"\n{MenuColors.CYAN}=== Verifica Archivio Singolo ==={MenuColors.END}\n")

        archive_name = input("Nome archivio: ").strip()
        if not archive_name:
            print("Nome archivio richiesto")
            return

        recovery_manager = RecoveryManager(
            self.app.models['archive'].temp_dir,
            self.app.models['qnap'].mount_point,
            self.app.models['gpg'],
            self.app.models['integrity']
        )

        valid, details = recovery_manager.verify_archive(archive_name)

        print(f"\n{MenuColors.CYAN}=== Risultato Verifica ==={MenuColors.END}")
        print(f"  Archivio: {details.get('archive', archive_name)}")
        print(f"  Valido: {'Sì' if valid else 'No'}")
        print(f"  Firma GPG: {'Presente' if details.get('has_signature') else 'Assente'}")
        print(f"  Checksum: {'Presente' if details.get('has_checksum') else 'Assente'}")

        if details.get('errors'):
            print(f"\n{MenuColors.RED}Errori:{MenuColors.END}")
            for error in details['errors']:
                print(f"  - {error}")

    def _verify_chain(self):
        """Verify manifest chain"""
        manifest_dir = self.app.models['archive'].temp_dir / 'manifests'

        print(f"\n{MenuColors.CYAN}=== Verifica Chain Manifest ==={MenuColors.END}\n")

        if not manifest_dir.exists():
            print(f"{MenuColors.RED}Directory manifest non trovata: {manifest_dir}{MenuColors.END}")
            return

        manifest_files = sorted(manifest_dir.glob('manifest_*.json'))

        if not manifest_files:
            print(f"{MenuColors.YELLOW}Nessun manifest trovato{MenuColors.END}")
            return

        print(f"Trovati {len(manifest_files)} manifest")
        print(f"\n{MenuColors.YELLOW}Verifica catena in corso...{MenuColors.END}")

        # This would verify the chain - simplified version
        import json

        prev_hash = None
        errors = []

        for mf in manifest_files:
            try:
                with open(mf, 'r') as f:
                    manifest = json.load(f)

                if prev_hash is not None:
                    if manifest.get('previous_hash') != prev_hash:
                        errors.append(f"{mf.name}: hash precedente non corrisponde")

                prev_hash = manifest.get('hash')

            except Exception as e:
                errors.append(f"{mf.name}: errore lettura - {e}")

        if errors:
            print(f"\n{MenuColors.RED}✗ Verifica fallita:{MenuColors.END}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"\n{MenuColors.GREEN}✓ Catena manifest verificata correttamente{MenuColors.END}")

    def _show_retention_policy(self):
        """Show retention policy"""
        print(f"\n{MenuColors.CYAN}=== Policy di Retention ==={MenuColors.END}\n")

        local = self.app.models['retention'].local
        remote = self.app.models['retention'].remote

        print(f"{MenuColors.YELLOW}Locale:{MenuColors.END}")
        print(f"  Giorni prima di archiviare: {local.days_before_archive}")
        print(f"  Giorni di retention locale: {local.days_keep_local}")
        print(f"  Elimina dopo trasferimento: {'Sì' if local.delete_after_transfer else 'No'}")

        print(f"\n{MenuColors.YELLOW}Remoto (QNAP):{MenuColors.END}")
        print(f"  Giorni di retention: {remote.days} ({remote.days // 365} anni)")
        print(f"  Organizza per data: {'Sì' if remote.organize_by_date else 'No'}")

    def _retention_dry_run(self):
        """Run retention in dry-run mode"""
        print(f"\n{MenuColors.YELLOW}Esecuzione retention (simulazione)...{MenuColors.END}\n")
        self.app.run_retention(dry_run=True)

    def _retention_run(self):
        """Run actual retention"""
        confirm = input(f"\n{MenuColors.YELLOW}Confermi l'esecuzione della pulizia? [s/N]: {MenuColors.END}").strip().lower()
        if confirm == 's':
            print(f"\n{MenuColors.GREEN}Esecuzione retention...{MenuColors.END}\n")
            self.app.run_retention(dry_run=False)
        else:
            print("Operazione annullata")

    def _analyze_historical(self):
        """Analyze historical Wazuh logs"""
        print(f"\n{MenuColors.YELLOW}Analisi log storici Wazuh...{MenuColors.END}\n")
        self.app.analyze_historical()

    def _cleanup_local_dry_run(self):
        """Run local cleanup in dry-run mode"""
        print(f"\n{MenuColors.YELLOW}Simulazione pulizia log locali...{MenuColors.END}\n")

        # Ask for days to keep
        days_input = input("Giorni da mantenere in locale [default: da config]: ").strip()
        keep_days = int(days_input) if days_input else None

        self.app.cleanup_local(keep_days=keep_days, dry_run=True)

    def _cleanup_local_run(self):
        """Run actual local cleanup"""
        print(f"\n{MenuColors.CYAN}=== Pulizia Log Locali ==={MenuColors.END}\n")

        # First show analysis
        print(f"{MenuColors.YELLOW}Analisi in corso...{MenuColors.END}\n")
        self.app.analyze_historical()

        # Ask for days to keep
        days_input = input("\nGiorni da mantenere in locale [default: da config]: ").strip()
        keep_days = int(days_input) if days_input else None

        confirm = input(f"\n{MenuColors.YELLOW}Confermi l'eliminazione dei log già archiviati? [s/N]: {MenuColors.END}").strip().lower()
        if confirm == 's':
            print(f"\n{MenuColors.GREEN}Esecuzione pulizia...{MenuColors.END}\n")
            self.app.cleanup_local(keep_days=keep_days, dry_run=False)
        else:
            print("Operazione annullata")

    def _display_archives_table(self, archives: List[Dict], title: str):
        """Display archives in a table format"""
        print(f"\n{MenuColors.CYAN}=== {title} ==={MenuColors.END}\n")

        if not archives:
            print(f"{MenuColors.YELLOW}Nessun archivio trovato{MenuColors.END}")
            return

        # Header
        print(f"{'#':<4} {'Nome':<45} {'MB':<10} {'Posizione':<10} {'Data':<12} {'GPG':<4} {'Hash':<4}")
        print("-" * 95)

        for i, a in enumerate(archives, 1):
            gpg = "✓" if a['has_signature'] else "-"
            hash_ok = "✓" if a['has_checksum'] else "-"
            date = a['created'][:10] if a.get('created') else 'N/A'

            print(f"{i:<4} {a['name'][:44]:<45} {a['size_mb']:<10.2f} {a['location']:<10} {date:<12} {gpg:<4} {hash_ok:<4}")

        print("-" * 95)
        print(f"Totale: {len(archives)} archivi, {sum(a['size_mb'] for a in archives):.2f} MB")

    def run(self):
        """Run the interactive menu"""
        try:
            self.main_menu.run()
        except KeyboardInterrupt:
            print(f"\n\n{MenuColors.YELLOW}Arrivederci!{MenuColors.END}\n")
