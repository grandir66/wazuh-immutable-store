#!/usr/bin/env python3
"""
Wazuh Immutable Store - Interactive Setup Wizard
Configurazione guidata passo-passo per il sistema di archiviazione
"""

import os
import sys
import subprocess
import yaml
import getpass
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from dataclasses import asdict


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SetupWizard:
    """Interactive wizard for Wazuh Immutable Store setup"""

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.config_path = Path("/etc/wazuh-immutable-store/config.yaml")

    def print_header(self, text: str):
        """Print a formatted header"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}  {text}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")

    def print_step(self, step: int, total: int, title: str):
        """Print step indicator"""
        print(f"\n{Colors.CYAN}[Passo {step}/{total}] {title}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'-'*50}{Colors.ENDC}")

    def print_success(self, text: str):
        """Print success message"""
        print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")

    def print_error(self, text: str):
        """Print error message"""
        print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

    def print_info(self, text: str):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ {text}{Colors.ENDC}")

    def ask_yes_no(self, question: str, default: bool = True) -> bool:
        """Ask a yes/no question"""
        default_str = "S/n" if default else "s/N"
        while True:
            response = input(f"{question} [{default_str}]: ").strip().lower()
            if not response:
                return default
            if response in ('s', 'si', 'sì', 'y', 'yes'):
                return True
            if response in ('n', 'no'):
                return False
            print("Risposta non valida. Inserire 's' o 'n'.")

    def ask_input(self, prompt: str, default: str = "", required: bool = True,
                  validator: callable = None) -> str:
        """Ask for text input with optional validation"""
        default_display = f" [{default}]" if default else ""
        while True:
            value = input(f"{prompt}{default_display}: ").strip()
            if not value:
                if default:
                    value = default
                elif required:
                    print("Questo campo è obbligatorio.")
                    continue

            if validator:
                valid, error = validator(value)
                if not valid:
                    print(f"Valore non valido: {error}")
                    continue

            return value

    def ask_choice(self, prompt: str, choices: list, default: int = 0) -> str:
        """Ask to choose from a list"""
        print(f"\n{prompt}")
        for i, choice in enumerate(choices):
            marker = "→" if i == default else " "
            print(f"  {marker} {i+1}) {choice}")

        while True:
            try:
                value = input(f"Scelta [1-{len(choices)}] (default: {default+1}): ").strip()
                if not value:
                    return choices[default]
                idx = int(value) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
                print(f"Inserire un numero tra 1 e {len(choices)}")
            except ValueError:
                print("Inserire un numero valido")

    def ask_number(self, prompt: str, default: int, min_val: int = 0,
                   max_val: int = None) -> int:
        """Ask for a number input"""
        while True:
            try:
                value = input(f"{prompt} [{default}]: ").strip()
                if not value:
                    return default
                num = int(value)
                if num < min_val:
                    print(f"Il valore deve essere almeno {min_val}")
                    continue
                if max_val and num > max_val:
                    print(f"Il valore non può superare {max_val}")
                    continue
                return num
            except ValueError:
                print("Inserire un numero valido")

    def validate_path(self, path: str) -> Tuple[bool, str]:
        """Validate a path exists"""
        if Path(path).exists():
            return True, ""
        return False, f"Il percorso '{path}' non esiste"

    def validate_ip_or_hostname(self, value: str) -> Tuple[bool, str]:
        """Validate IP address or hostname"""
        import re
        # Simple validation - accept IPs and hostnames
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'

        if re.match(ip_pattern, value) or re.match(hostname_pattern, value):
            return True, ""
        return False, "Inserire un indirizzo IP o hostname valido"

    def test_nfs_connection(self, host: str, export_path: str) -> bool:
        """Test NFS connectivity"""
        try:
            # Try to list NFS exports
            result = subprocess.run(
                ['showmount', '-e', host],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and export_path in result.stdout:
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def check_gpg_installed(self) -> bool:
        """Check if GPG is installed"""
        try:
            result = subprocess.run(['gpg', '--version'], capture_output=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def list_gpg_keys(self) -> list:
        """List available GPG keys"""
        try:
            result = subprocess.run(
                ['gpg', '--list-secret-keys', '--keyid-format', 'LONG'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                keys = []
                for line in result.stdout.split('\n'):
                    if 'sec' in line:
                        parts = line.split('/')
                        if len(parts) > 1:
                            key_id = parts[1].split()[0]
                            keys.append(key_id)
                return keys
        except Exception:
            pass
        return []

    def generate_gpg_key(self) -> Optional[str]:
        """Guide user through GPG key generation"""
        print("\nGenerazione nuova chiave GPG per la firma degli archivi...")
        print("Seguire le istruzioni per creare la chiave.\n")

        # Generate key with batch mode
        name = self.ask_input("Nome per la chiave", "Wazuh Archive Signer")
        email = self.ask_input("Email per la chiave", "wazuh-archive@localhost")

        key_config = f"""
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: {name}
Name-Email: {email}
Expire-Date: 0
%commit
"""
        try:
            result = subprocess.run(
                ['gpg', '--batch', '--generate-key'],
                input=key_config,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                # Get the key ID
                keys = self.list_gpg_keys()
                if keys:
                    return keys[-1]  # Return the newest key
        except Exception as e:
            self.print_error(f"Errore nella generazione della chiave: {e}")
        return None

    def run(self):
        """Run the setup wizard"""
        self.print_header("Wazuh Immutable Store - Setup Wizard")

        print("Benvenuto nel wizard di configurazione!")
        print("Questo processo ti guiderà nella configurazione del sistema")
        print("di archiviazione immutabile per i log di Wazuh su QNAP.\n")

        if not self.ask_yes_no("Vuoi procedere con la configurazione?"):
            print("Configurazione annullata.")
            return False

        total_steps = 7

        # Step 1: Wazuh Configuration
        self.print_step(1, total_steps, "Configurazione Sorgente Wazuh")
        self.configure_wazuh()

        # Step 2: QNAP Connection
        self.print_step(2, total_steps, "Connessione QNAP NFS")
        self.configure_qnap()

        # Step 3: Archive Settings
        self.print_step(3, total_steps, "Impostazioni Archivio")
        self.configure_archive()

        # Step 4: GPG Signing
        self.print_step(4, total_steps, "Firma Digitale GPG")
        self.configure_gpg()

        # Step 5: Retention Policies
        self.print_step(5, total_steps, "Policy di Retention")
        self.configure_retention()

        # Step 6: Scheduling
        self.print_step(6, total_steps, "Schedulazione")
        self.configure_schedule()

        # Step 7: Review and Save
        self.print_step(7, total_steps, "Riepilogo e Salvataggio")
        return self.review_and_save()

    def configure_wazuh(self):
        """Configure Wazuh source settings"""
        self.print_info("Configurazione della sorgente dei log Wazuh")

        # Default Wazuh paths
        default_logs = "/var/ossec/logs/archives"
        default_alerts = "/var/ossec/logs/alerts"

        logs_path = self.ask_input(
            "Percorso directory log Wazuh",
            default_logs,
            required=True
        )

        include_alerts = self.ask_yes_no(
            "Includere anche i log degli alerts?",
            default=True
        )

        alerts_path = None
        if include_alerts:
            alerts_path = self.ask_input(
                "Percorso directory alerts",
                default_alerts
            )

        file_pattern = self.ask_input(
            "Pattern file da archiviare",
            "archives.json"
        )

        self.config['wazuh'] = {
            'logs_path': logs_path,
            'file_pattern': file_pattern,
            'include_alerts': include_alerts,
            'alerts_path': alerts_path
        }

        self.print_success("Configurazione Wazuh completata")

    def configure_qnap(self):
        """Configure QNAP NFS connection"""
        self.print_info("Configurazione connessione NFS al QNAP")

        print("\n" + Colors.WARNING + "NOTA: Prima di procedere, assicurati che sul QNAP sia:")
        print("  1. Creato un volume con WORM abilitato")
        print("  2. Configurato l'export NFS")
        print("  3. Il server Wazuh sia autorizzato ad accedere" + Colors.ENDC + "\n")

        host = self.ask_input(
            "Indirizzo IP o hostname del QNAP",
            "",
            validator=self.validate_ip_or_hostname
        )

        export_path = self.ask_input(
            "Percorso export NFS sul QNAP",
            "/wazuh-archive"
        )

        mount_point = self.ask_input(
            "Mount point locale",
            "/mnt/qnap-wazuh"
        )

        nfs_version = self.ask_choice(
            "Versione NFS da utilizzare:",
            ["NFSv4 (consigliato)", "NFSv3"],
            default=0
        )
        nfs_ver = 4 if "v4" in nfs_version.lower() else 3

        # Test connection
        print("\nTest connessione NFS...")
        if self.test_nfs_connection(host, export_path):
            self.print_success(f"Connessione a {host} riuscita!")
        else:
            self.print_warning(f"Impossibile verificare la connessione a {host}")
            self.print_info("Il test potrebbe fallire se il servizio NFS non è ancora configurato")
            if not self.ask_yes_no("Vuoi continuare comunque?"):
                self.print_error("Configurazione annullata")
                sys.exit(1)

        self.config['qnap'] = {
            'host': host,
            'export_path': export_path,
            'mount_point': mount_point,
            'nfs_version': nfs_ver,
            'mount_options': "hard,intr,rsize=65536,wsize=65536"
        }

        self.print_success("Configurazione QNAP completata")

    def configure_archive(self):
        """Configure archive settings"""
        self.print_info("Configurazione delle impostazioni di archiviazione")

        compression = self.ask_choice(
            "Algoritmo di compressione:",
            ["gzip (bilanciato)", "bz2 (migliore compressione)", "xz (massima compressione)"],
            default=0
        )
        comp_type = compression.split()[0]

        comp_level = self.ask_number(
            "Livello di compressione (1-9)",
            default=6,
            min_val=1,
            max_val=9
        )

        interval = self.ask_choice(
            "Frequenza di archiviazione:",
            ["Giornaliera (consigliato)", "Oraria"],
            default=0
        )
        interval_type = "daily" if "Giornaliera" in interval else "hourly"

        temp_dir = self.ask_input(
            "Directory temporanea per creazione archivi",
            "/tmp/wazuh-archive"
        )

        self.config['archive'] = {
            'compression': comp_type,
            'compression_level': comp_level,
            'naming_pattern': "wazuh-logs-{date}-{hour}.tar.gz",
            'temp_dir': temp_dir,
            'interval': interval_type
        }

        self.print_success("Configurazione archivio completata")

    def configure_gpg(self):
        """Configure GPG signing"""
        self.print_info("Configurazione della firma digitale GPG")

        if not self.check_gpg_installed():
            self.print_warning("GPG non trovato nel sistema")
            self.print_info("Installare GPG con: apt install gnupg")
            enable_gpg = False
        else:
            enable_gpg = self.ask_yes_no(
                "Abilitare la firma GPG degli archivi? (consigliato per immutabilità)",
                default=True
            )

        key_id = ""
        if enable_gpg:
            keys = self.list_gpg_keys()
            if keys:
                print("\nChiavi GPG disponibili:")
                for i, key in enumerate(keys):
                    print(f"  {i+1}) {key}")
                print(f"  {len(keys)+1}) Genera nuova chiave")

                choice = self.ask_number(
                    "Seleziona chiave da usare",
                    default=1,
                    min_val=1,
                    max_val=len(keys)+1
                )

                if choice <= len(keys):
                    key_id = keys[choice-1]
                else:
                    key_id = self.generate_gpg_key()
                    if not key_id:
                        self.print_warning("Generazione chiave fallita, GPG disabilitato")
                        enable_gpg = False
            else:
                if self.ask_yes_no("Nessuna chiave trovata. Generare una nuova chiave?"):
                    key_id = self.generate_gpg_key()
                    if not key_id:
                        self.print_warning("Generazione chiave fallita, GPG disabilitato")
                        enable_gpg = False
                else:
                    enable_gpg = False

        self.config['gpg'] = {
            'enabled': enable_gpg,
            'key_id': key_id,
            'gpg_home': "",
            'detached': True
        }

        self.config['integrity'] = {
            'algorithm': 'sha256',
            'create_manifest': True,
            'chain_manifests': True
        }

        if enable_gpg:
            self.print_success(f"Firma GPG configurata con chiave: {key_id}")
        else:
            self.print_warning("Firma GPG disabilitata - solo hash SHA256")

    def configure_retention(self):
        """Configure retention policies"""
        self.print_info("Configurazione delle policy di retention")

        print("\n" + Colors.BLUE + "Policy di retention locale:" + Colors.ENDC)

        days_before_archive = self.ask_number(
            "Giorni di attesa prima di archiviare i log",
            default=1,
            min_val=0,
            max_val=30
        )

        days_keep_local = self.ask_number(
            "Giorni di mantenimento archivi locali dopo il trasferimento",
            default=7,
            min_val=0,
            max_val=365
        )

        delete_after_transfer = self.ask_yes_no(
            "Eliminare archivi locali dopo trasferimento verificato?",
            default=True
        )

        print("\n" + Colors.BLUE + "Policy di retention remota (QNAP):" + Colors.ENDC)

        print("\nPeriodo di retention su QNAP:")
        print("  Nota: Il WORM del QNAP impone una retention minima.")
        print("  Impostare un valore >= alla retention WORM configurata.")

        retention_choice = self.ask_choice(
            "Periodo di retention remota:",
            [
                "1 anno (365 giorni)",
                "3 anni (1095 giorni)",
                "5 anni (1825 giorni)",
                "7 anni (2555 giorni) - GDPR/compliance",
                "10 anni (3650 giorni)",
                "Personalizzato"
            ],
            default=3
        )

        retention_map = {
            "1 anno": 365,
            "3 anni": 1095,
            "5 anni": 1825,
            "7 anni": 2555,
            "10 anni": 3650
        }

        remote_days = 2555
        for key, value in retention_map.items():
            if key in retention_choice:
                remote_days = value
                break

        if "Personalizzato" in retention_choice:
            remote_days = self.ask_number(
                "Giorni di retention remota",
                default=2555,
                min_val=30
            )

        organize_by_date = self.ask_yes_no(
            "Organizzare archivi per anno/mese?",
            default=True
        )

        self.config['retention'] = {
            'local': {
                'days_before_archive': days_before_archive,
                'days_keep_local': days_keep_local,
                'delete_after_transfer': delete_after_transfer
            },
            'remote': {
                'days': remote_days,
                'organize_by_date': organize_by_date
            }
        }

        self.print_success("Policy di retention configurate")

    def configure_schedule(self):
        """Configure scheduling"""
        self.print_info("Configurazione della schedulazione")

        print("\nOrario di esecuzione dell'archiviazione:")
        archive_hour = self.ask_number(
            "Ora di esecuzione (0-23)",
            default=2,
            min_val=0,
            max_val=23
        )

        archive_minute = self.ask_number(
            "Minuto (0-59)",
            default=0,
            min_val=0,
            max_val=59
        )

        print("\nVerifica integrità settimanale:")
        integrity_day = self.ask_choice(
            "Giorno della settimana:",
            ["Domenica", "Lunedì", "Martedì", "Mercoledì",
             "Giovedì", "Venerdì", "Sabato"],
            default=0
        )
        day_map = {
            "Domenica": 0, "Lunedì": 1, "Martedì": 2,
            "Mercoledì": 3, "Giovedì": 4, "Venerdì": 5, "Sabato": 6
        }
        integrity_day_num = day_map.get(integrity_day, 0)

        integrity_hour = self.ask_number(
            "Ora verifica integrità (0-23)",
            default=6,
            min_val=0,
            max_val=23
        )

        self.config['schedule'] = {
            'archive_cron': f"{archive_minute} {archive_hour} * * *",
            'integrity_check_cron': f"0 {integrity_hour} * * {integrity_day_num}",
            'cleanup_cron': f"0 {(archive_hour + 1) % 24} * * *"
        }

        self.print_success("Schedulazione configurata")

    def review_and_save(self) -> bool:
        """Review configuration and save"""
        # Add default logging and notifications
        self.config['logging'] = {
            'level': 'INFO',
            'file': '/var/log/wazuh-immutable-store.log',
            'max_size': 100,
            'backup_count': 5
        }

        self.config['notifications'] = {
            'email': {
                'enabled': False,
                'smtp_server': '',
                'smtp_port': 587,
                'username': '',
                'password': '',
                'from_address': '',
                'to_addresses': []
            },
            'syslog': {
                'enabled': True,
                'facility': 'local0'
            }
        }

        # Display summary
        self.print_header("Riepilogo Configurazione")

        print(f"{Colors.BOLD}Sorgente Wazuh:{Colors.ENDC}")
        print(f"  Log path: {self.config['wazuh']['logs_path']}")
        print(f"  Include alerts: {self.config['wazuh']['include_alerts']}")

        print(f"\n{Colors.BOLD}QNAP NFS:{Colors.ENDC}")
        print(f"  Server: {self.config['qnap']['host']}")
        print(f"  Export: {self.config['qnap']['export_path']}")
        print(f"  Mount point: {self.config['qnap']['mount_point']}")

        print(f"\n{Colors.BOLD}Archivio:{Colors.ENDC}")
        print(f"  Compressione: {self.config['archive']['compression']} (livello {self.config['archive']['compression_level']})")
        print(f"  Intervallo: {self.config['archive']['interval']}")

        print(f"\n{Colors.BOLD}Sicurezza:{Colors.ENDC}")
        print(f"  Firma GPG: {'Abilitata' if self.config['gpg']['enabled'] else 'Disabilitata'}")
        if self.config['gpg']['enabled']:
            print(f"  Key ID: {self.config['gpg']['key_id']}")
        print(f"  Hash: SHA256 con manifest chain")

        print(f"\n{Colors.BOLD}Retention:{Colors.ENDC}")
        print(f"  Locale: {self.config['retention']['local']['days_keep_local']} giorni")
        print(f"  Remota: {self.config['retention']['remote']['days']} giorni ({self.config['retention']['remote']['days']//365} anni)")

        print(f"\n{Colors.BOLD}Schedulazione:{Colors.ENDC}")
        print(f"  Archiviazione: {self.config['schedule']['archive_cron']}")
        print(f"  Verifica integrità: {self.config['schedule']['integrity_check_cron']}")

        print()
        if not self.ask_yes_no("Confermi la configurazione?"):
            print("Configurazione non salvata.")
            return False

        # Save configuration
        return self.save_config()

    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            # Create config directory
            config_dir = self.config_path.parent
            config_dir.mkdir(parents=True, exist_ok=True)

            # Write config file
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)

            # Set permissions
            os.chmod(self.config_path, 0o600)

            self.print_success(f"Configurazione salvata in: {self.config_path}")

            # Create necessary directories
            self.create_directories()

            # Show next steps
            self.show_next_steps()

            return True

        except PermissionError:
            self.print_error(f"Permessi insufficienti per scrivere in {self.config_path}")
            self.print_info("Eseguire lo script come root o con sudo")

            # Offer to save to alternative location
            alt_path = Path.home() / ".wazuh-immutable-store" / "config.yaml"
            if self.ask_yes_no(f"Salvare in {alt_path} invece?"):
                self.config_path = alt_path
                return self.save_config()
            return False

        except Exception as e:
            self.print_error(f"Errore nel salvataggio: {e}")
            return False

    def create_directories(self):
        """Create necessary directories"""
        dirs = [
            Path(self.config['archive']['temp_dir']),
            Path(self.config['qnap']['mount_point']),
        ]

        for d in dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                self.print_success(f"Directory creata: {d}")
            except PermissionError:
                self.print_warning(f"Impossibile creare {d} - creare manualmente con sudo")

    def show_next_steps(self):
        """Show next steps after configuration"""
        self.print_header("Prossimi Passi")

        print(f"""
{Colors.BOLD}1. Configurazione QNAP (manuale):{Colors.ENDC}
   - Creare volume WORM su QNAP
   - Configurare export NFS: {self.config['qnap']['export_path']}
   - Autorizzare l'IP del server Wazuh

{Colors.BOLD}2. Mount NFS:{Colors.ENDC}
   sudo mount -t nfs{self.config['qnap']['nfs_version']} \\
       -o {self.config['qnap']['mount_options']} \\
       {self.config['qnap']['host']}:{self.config['qnap']['export_path']} \\
       {self.config['qnap']['mount_point']}

{Colors.BOLD}3. Aggiungere a /etc/fstab per mount automatico:{Colors.ENDC}
   {self.config['qnap']['host']}:{self.config['qnap']['export_path']} {self.config['qnap']['mount_point']} nfs{self.config['qnap']['nfs_version']} {self.config['qnap']['mount_options']},_netdev 0 0

{Colors.BOLD}4. Installare e avviare il servizio:{Colors.ENDC}
   sudo cp systemd/wazuh-immutable-store.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable wazuh-immutable-store
   sudo systemctl start wazuh-immutable-store

{Colors.BOLD}5. Verificare lo stato:{Colors.ENDC}
   sudo systemctl status wazuh-immutable-store
   sudo journalctl -u wazuh-immutable-store -f

{Colors.BOLD}6. Test manuale:{Colors.ENDC}
   wazuh-immutable-store --test-archive
   wazuh-immutable-store --verify-integrity
""")


def main():
    """Main entry point"""
    # Check if running as root (recommended)
    if os.geteuid() != 0:
        print(f"{Colors.WARNING}⚠ Attenzione: Si consiglia di eseguire come root per la configurazione completa{Colors.ENDC}")
        print()

    wizard = SetupWizard()
    success = wizard.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
