#!/bin/bash
#
# Wazuh Immutable Store — Installation Wizard
#
# Wizard interattivo per installazione completa della soluzione.
# Input richiesti all'utente: solo IP del NAS e nome della share NFS.
# Tutto il resto viene configurato automaticamente con default sensati,
# modificabili in seguito tramite scripts/maintenance.sh
#
# Componenti installati:
#   - Pacchetto applicativo Python (in /opt/wazuh-immutable-store)
#   - Wrapper CLI (in /usr/local/bin/wazuh-immutable-store)
#   - Mount NFS persistente (/etc/fstab)
#   - Chiave GPG dedicata (RSA 4096) + backup cifrato AES256
#   - Certificato di revoca pre-generato
#   - Timer systemd: archive orario + retention giornaliera + verify settimanale
#   - Script rolling hash chain (5 min) con composite hash
#
# Uso:
#   sudo bash scripts/install-wizard.sh
#   sudo bash scripts/install-wizard.sh --non-interactive --qnap-host 192.168.1.100 --qnap-share /wazuh-archive
#
set -euo pipefail

# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ------------------------------------------------------------------
# Defaults (override interattivo o via flag CLI)
# ------------------------------------------------------------------
QNAP_HOST=""
QNAP_SHARE=""
MOUNT_POINT="/mnt/qnap-wazuh"
NFS_VERSION="4"
GPG_KEY_TYPE="RSA"
GPG_KEY_LENGTH="4096"
GPG_KEY_EMAIL="wazuh-archive@$(hostname -s 2>/dev/null || echo srv-wazuh)"
GPG_KEY_NAME="Wazuh Archive Signer"
RETENTION_DAYS="365"
ARCHIVE_INTERVAL="hourly"
COMPRESSION="gzip"
COMPRESSION_LEVEL="6"
DAYS_KEEP_LOCAL="7"
ENABLE_ROLLING_HASH="yes"
ROLLING_INTERVAL_MIN="5"
NON_INTERACTIVE="no"

INSTALL_DIR="/opt/wazuh-immutable-store"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/wazuh-immutable-store"
SYSTEMD_DIR="/etc/systemd/system"
LOG_DIR="/var/log/wazuh-immutable-store"
GPG_BACKUP_DIR="/root/gpg-backup"
SCRIPT_DIR_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR_REPO/.." && pwd)"

# ------------------------------------------------------------------
# Logging helpers
# ------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo; echo -e "${BOLD}${CYAN}━━━ $* ━━━${NC}"; }

ask_input() {
  local prompt="$1" default="${2:-}" var
  if [[ "$NON_INTERACTIVE" == "yes" ]]; then
    echo "$default"; return
  fi
  if [[ -n "$default" ]]; then
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [${default}]: ")" var
    echo "${var:-$default}"
  else
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC}: ")" var
    echo "$var"
  fi
}

ask_yesno() {
  local prompt="$1" default="${2:-Y}" var
  if [[ "$NON_INTERACTIVE" == "yes" ]]; then
    [[ "$default" =~ ^[YySs] ]] && return 0 || return 1
  fi
  while true; do
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [Y/n]: ")" var
    var="${var:-$default}"
    case "$var" in
      [YySs]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "  Rispondere y o n" ;;
    esac
  done
}

# ------------------------------------------------------------------
# Sanity checks
# ------------------------------------------------------------------
check_root() {
  [[ $EUID -eq 0 ]] || { log_error "Wizard da eseguire come root (sudo $0)"; exit 1; }
}

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    log_warn "OS non riconosciuto, proseguo a rischio dell'utente"
    return
  fi
  . /etc/os-release
  log_info "OS rilevato: ${PRETTY_NAME:-$ID $VERSION_ID}"
  case "$ID" in
    ubuntu|debian|rhel|centos|rocky|almalinux|fedora) ;;
    *) log_warn "Distribuzione $ID non testata, proseguo comunque" ;;
  esac
}

# ------------------------------------------------------------------
# CLI args
# ------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --non-interactive) NON_INTERACTIVE="yes"; shift ;;
      --qnap-host) QNAP_HOST="$2"; shift 2 ;;
      --qnap-share) QNAP_SHARE="$2"; shift 2 ;;
      --mount-point) MOUNT_POINT="$2"; shift 2 ;;
      --retention-days) RETENTION_DAYS="$2"; shift 2 ;;
      --archive-interval) ARCHIVE_INTERVAL="$2"; shift 2 ;;
      --no-rolling) ENABLE_ROLLING_HASH="no"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Opzione sconosciuta: $1"; usage; exit 1 ;;
    esac
  done
}

usage() {
  cat <<USAGE
Wazuh Immutable Store — Installation Wizard

Uso interattivo:
  sudo bash $0

Uso non interattivo (per CI/automation):
  sudo bash $0 --non-interactive --qnap-host IP --qnap-share /wazuh-archive

Opzioni CLI:
  --non-interactive          Salta i prompt, usa solo i flag passati e i default
  --qnap-host HOST           IP o hostname del NAS (obbligatorio)
  --qnap-share PATH          Path della NFS share esportata (obbligatorio)
  --mount-point PATH         Mount point locale (default: $MOUNT_POINT)
  --retention-days N         Retention archivi su WORM (default: $RETENTION_DAYS)
  --archive-interval VAL     hourly o daily (default: $ARCHIVE_INTERVAL)
  --no-rolling               Disabilita il rolling hash chain (sconsigliato)
  -h, --help                 Mostra questo aiuto
USAGE
}

# ------------------------------------------------------------------
# Step 1: Benvenuto
# ------------------------------------------------------------------
welcome() {
  clear
  cat <<'BANNER'

  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║         Wazuh Immutable Store — Install Wizard               ║
  ║                                                              ║
  ║   Installa la soluzione completa di archiviazione            ║
  ║   immutabile per i log di Wazuh SIEM.                        ║
  ║                                                              ║
  ║   Tempo stimato: 5-10 minuti.                                ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝

BANNER
  log_info "Input minimi richiesti: IP del NAS + nome della NFS share."
  log_info "Tutto il resto userà default sensati (modificabili dopo l'install)."
  echo
  if [[ "$NON_INTERACTIVE" != "yes" ]]; then
    read -r -p "Premi INVIO per iniziare..."
  fi
}

# ------------------------------------------------------------------
# Step 2: Verifica prerequisiti
# ------------------------------------------------------------------
check_prerequisites() {
  log_step "1/8 Verifica prerequisiti"

  local missing=()
  command -v python3 >/dev/null 2>&1 || missing+=("python3")
  command -v gpg >/dev/null 2>&1 || missing+=("gnupg")
  command -v mount.nfs >/dev/null 2>&1 || missing+=("nfs-common")
  command -v curl >/dev/null 2>&1 || missing+=("curl")
  command -v tar >/dev/null 2>&1 || missing+=("tar")
  command -v sha256sum >/dev/null 2>&1 || missing+=("coreutils")
  python3 -c "import yaml" 2>/dev/null || missing+=("python3-yaml")

  if [[ ${#missing[@]} -eq 0 ]]; then
    log_ok "Tutti i pacchetti richiesti sono presenti"
    return
  fi

  log_warn "Pacchetti mancanti: ${missing[*]}"
  if ! ask_yesno "Installare automaticamente i pacchetti mancanti?" "Y"; then
    log_error "Installazione annullata, installa manualmente: ${missing[*]}"
    exit 1
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y "${missing[@]}" || { log_error "apt-get install fallito"; exit 1; }
  elif command -v dnf >/dev/null 2>&1; then
    local rhel_pkgs=("${missing[@]/python3-yaml/python3-pyyaml}")
    rhel_pkgs=("${rhel_pkgs[@]/nfs-common/nfs-utils}")
    dnf install -y "${rhel_pkgs[@]}" || { log_error "dnf install fallito"; exit 1; }
  elif command -v yum >/dev/null 2>&1; then
    local rhel_pkgs=("${missing[@]/python3-yaml/python3-pyyaml}")
    rhel_pkgs=("${rhel_pkgs[@]/nfs-common/nfs-utils}")
    yum install -y "${rhel_pkgs[@]}" || { log_error "yum install fallito"; exit 1; }
  else
    log_error "Package manager non riconosciuto. Installa manualmente: ${missing[*]}"
    exit 1
  fi
  log_ok "Pacchetti installati"
}

# ------------------------------------------------------------------
# Step 3: Input utente (IP + share)
# ------------------------------------------------------------------
gather_input() {
  log_step "2/8 Configurazione NAS"

  if [[ -z "$QNAP_HOST" ]]; then
    while true; do
      QNAP_HOST=$(ask_input "IP o hostname del NAS")
      [[ -n "$QNAP_HOST" ]] && break
      log_warn "Campo obbligatorio"
    done
  fi

  if [[ -z "$QNAP_SHARE" ]]; then
    QNAP_SHARE=$(ask_input "Path della NFS share sul NAS" "/wazuh-archive")
    [[ "$QNAP_SHARE" =~ ^/ ]] || QNAP_SHARE="/$QNAP_SHARE"
  fi

  log_info "Test ping verso $QNAP_HOST..."
  if ping -c 2 -W 2 "$QNAP_HOST" >/dev/null 2>&1; then
    log_ok "$QNAP_HOST risponde al ping"
  else
    log_warn "$QNAP_HOST non risponde al ping (potrebbe avere ICMP bloccato — proseguo)"
  fi

  log_info "Test porte NFS (2049 + 111)..."
  local nfs_ok=0
  for port in 2049 111; do
    if (echo > /dev/tcp/$QNAP_HOST/$port) 2>/dev/null; then
      log_ok "Porta $port aperta"
      nfs_ok=$((nfs_ok+1))
    else
      log_warn "Porta $port chiusa o filtrata"
    fi
  done
  if [[ $nfs_ok -eq 0 ]]; then
    log_error "Nessuna porta NFS raggiungibile. Verifica che il servizio NFS sia attivo sul NAS"
    log_info "Su QNAP: Pannello di controllo → Servizi rete e file → NFS → Abilita"
    ask_yesno "Proseguire comunque (NFSv4 potrebbe funzionare anche se 111/2049 risultano chiuse)?" "Y" || exit 1
  fi
}

# ------------------------------------------------------------------
# Step 4: Mount NFS + fstab
# ------------------------------------------------------------------
setup_nfs_mount() {
  log_step "3/8 Mount NFS persistente"

  mkdir -p "$MOUNT_POINT"
  chmod 755 "$MOUNT_POINT"
  log_ok "Mount point creato: $MOUNT_POINT"

  if mountpoint -q "$MOUNT_POINT"; then
    log_warn "$MOUNT_POINT già montato — smonto e rimonto pulito"
    umount "$MOUNT_POINT" || { log_error "Impossibile smontare"; exit 1; }
  fi

  log_info "Test mount manuale NFSv$NFS_VERSION..."
  if mount -t nfs4 -o "vers=$NFS_VERSION,hard,timeo=600,retrans=2,noatime" \
       "$QNAP_HOST:$QNAP_SHARE" "$MOUNT_POINT"; then
    log_ok "Mount NFS riuscito"
  else
    log_error "Mount NFS fallito. Verifica: 1) NFS host access sul NAS autorizza $(hostname -I | awk '{print $1}') 2) Squash policy = no_root_squash"
    exit 1
  fi

  log_info "Test scrittura..."
  local test_file="$MOUNT_POINT/.wis-install-marker-$(date +%s)"
  if echo "wis-install-test" > "$test_file" 2>/dev/null; then
    log_ok "Scrittura OK"
    rm -f "$test_file" 2>/dev/null || log_warn "Cannot remove test file (potrebbe essere WORM-locked: normale, solo informativo)"
  else
    log_error "Scrittura fallita — verifica Squash NFS"
    exit 1
  fi

  local fstab_line="$QNAP_HOST:$QNAP_SHARE $MOUNT_POINT nfs4 vers=$NFS_VERSION,hard,timeo=600,retrans=2,_netdev,noatime 0 0"
  if grep -q "$QNAP_HOST:$QNAP_SHARE" /etc/fstab; then
    log_info "Entry fstab già presente, sostituisco"
    sed -i "\|$QNAP_HOST:$QNAP_SHARE|d" /etc/fstab
  fi
  echo "$fstab_line" >> /etc/fstab
  log_ok "Entry fstab aggiunta (mount persistente al reboot)"
}

# ------------------------------------------------------------------
# Step 5: Install pacchetto Python
# ------------------------------------------------------------------
install_python_package() {
  log_step "4/8 Installazione pacchetto Python"

  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" /tmp/wazuh-archive

  if [[ -d "$REPO_ROOT/src" ]]; then
    log_info "Copia sorgenti da $REPO_ROOT/src/ → $INSTALL_DIR/"
    cp -r "$REPO_ROOT/src/"* "$INSTALL_DIR/"
  else
    log_error "Directory $REPO_ROOT/src non trovata. Lancia lo script dalla root del repo."
    exit 1
  fi

  if [[ -f "$REPO_ROOT/config/config.yaml.example" ]]; then
    cp "$REPO_ROOT/config/config.yaml.example" "$CONFIG_DIR/"
  fi

  cat > "$BIN_DIR/wazuh-immutable-store" <<'WRAPPER'
#!/bin/bash
PYTHONPATH=/opt/wazuh-immutable-store python3 /opt/wazuh-immutable-store/main.py "$@"
WRAPPER
  chmod +x "$BIN_DIR/wazuh-immutable-store"
  log_ok "Pacchetto installato in $INSTALL_DIR/"
  log_ok "CLI disponibile come: wazuh-immutable-store"
}

# ------------------------------------------------------------------
# Step 6: Generazione chiave GPG + backup cifrato
# ------------------------------------------------------------------
generate_gpg_key() {
  log_step "5/8 Generazione chiave GPG e backup cifrato"
  export GNUPGHOME=/root/.gnupg
  mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

  local existing_fpr=""
  existing_fpr=$(gpg --list-secret-keys --keyid-format=long "$GPG_KEY_EMAIL" 2>/dev/null \
    | awk '/^sec/{getline; gsub(/^[[:space:]]+/,""); print; exit}')

  if [[ -n "$existing_fpr" ]]; then
    log_warn "Chiave GPG per $GPG_KEY_EMAIL già esistente (fingerprint $existing_fpr)"
    if ! ask_yesno "Riutilizzare la chiave esistente?" "Y"; then
      log_error "Per generare una nuova chiave, prima rimuovi la vecchia con: gpg --delete-secret-keys $existing_fpr && gpg --delete-keys $existing_fpr"
      exit 1
    fi
    GPG_FINGERPRINT="$existing_fpr"
  else
    log_info "Generazione chiave $GPG_KEY_TYPE/$GPG_KEY_LENGTH (operazione lenta, 30-90 sec)..."
    cat <<EOF | gpg --batch --gen-key 2>&1 | tail -5
%no-protection
Key-Type: $GPG_KEY_TYPE
Key-Length: $GPG_KEY_LENGTH
Subkey-Type: $GPG_KEY_TYPE
Subkey-Length: $GPG_KEY_LENGTH
Name-Real: $GPG_KEY_NAME
Name-Email: $GPG_KEY_EMAIL
Expire-Date: 0
%commit
EOF
    GPG_FINGERPRINT=$(gpg --list-secret-keys --keyid-format=long "$GPG_KEY_EMAIL" 2>/dev/null \
      | awk '/^sec/{getline; gsub(/^[[:space:]]+/,""); print; exit}')
    [[ -n "$GPG_FINGERPRINT" ]] || { log_error "Generazione chiave fallita"; exit 1; }
    log_ok "Chiave generata: $GPG_FINGERPRINT"
  fi

  log_info "Export chiave pubblica..."
  gpg --armor --export "$GPG_FINGERPRINT" > "$CONFIG_DIR/wazuh-archive-pubkey.asc"
  cp "$CONFIG_DIR/wazuh-archive-pubkey.asc" "$MOUNT_POINT/wazuh-archive-pubkey.asc" 2>/dev/null \
    || log_warn "Pubkey su share fallita (probabilmente WORM ha già lockato file omonimo - ok)"
  log_ok "Chiave pubblica esportata"

  log_info "Backup chiave privata cifrato (AES-256)..."
  BACKUP_PASSPHRASE=$(openssl rand -base64 32 | tr -d '/+=' | head -c 28)
  mkdir -p "$GPG_BACKUP_DIR" && chmod 700 "$GPG_BACKUP_DIR"

  gpg --batch --pinentry-mode loopback --passphrase "" \
      --armor --export-secret-keys "$GPG_FINGERPRINT" \
      > "$GPG_BACKUP_DIR/wazuh-archive-privkey.asc"

  local revoke_src="$GNUPGHOME/openpgp-revocs.d/${GPG_FINGERPRINT}.rev"
  if [[ -f "$revoke_src" ]]; then
    cp "$revoke_src" "$GPG_BACKUP_DIR/wazuh-archive-revoke.asc"
  fi

  for f in wazuh-archive-privkey.asc wazuh-archive-revoke.asc; do
    [[ -f "$GPG_BACKUP_DIR/$f" ]] || continue
    gpg --batch --pinentry-mode loopback --passphrase "$BACKUP_PASSPHRASE" \
        --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-count 65011712 \
        -o "$GPG_BACKUP_DIR/${f}.gpg" "$GPG_BACKUP_DIR/$f"
    shred -u "$GPG_BACKUP_DIR/$f"
  done

  gpg --armor --export "$GPG_FINGERPRINT" > "$GPG_BACKUP_DIR/wazuh-archive-pubkey.asc"
  echo "$GPG_FINGERPRINT" > "$GPG_BACKUP_DIR/wazuh-archive-fingerprint.txt"
  chmod 600 "$GPG_BACKUP_DIR"/*

  log_ok "Backup chiave in $GPG_BACKUP_DIR/ (cifrato AES-256)"

  cat <<EOF

  ${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}
  ${BOLD}${YELLOW}║   PASSPHRASE BACKUP CHIAVE — SALVA IN VAULT AZIENDALE!      ║${NC}
  ${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}

      Fingerprint:  ${BOLD}$GPG_FINGERPRINT${NC}
      Passphrase:   ${BOLD}$BACKUP_PASSPHRASE${NC}

  Questa passphrase NON sarà più mostrata. Salvala subito nel vault aziendale
  insieme ai file in $GPG_BACKUP_DIR/

EOF
  if [[ "$NON_INTERACTIVE" != "yes" ]]; then
    read -r -p "Premi INVIO solo dopo aver salvato la passphrase nel vault..."
  fi
}

# ------------------------------------------------------------------
# Step 7: Configurazione (config.yaml)
# ------------------------------------------------------------------
write_config() {
  log_step "6/8 Generazione configurazione"

  local naming_pattern='wazuh-logs-{date}.tar.gz'
  [[ "$ARCHIVE_INTERVAL" == "hourly" ]] && naming_pattern='wazuh-logs-{date}-{hour}.tar.gz'

  cat > "$CONFIG_DIR/config.yaml" <<EOF
# Wazuh Immutable Store — configurazione generata da install-wizard
# Generata: $(date -Iseconds)
# Host: $(hostname -f 2>/dev/null || hostname) → NAS: $QNAP_HOST:$QNAP_SHARE

wazuh:
  logs_path: /var/ossec/logs/archives
  file_pattern: "archives.json"
  include_alerts: true
  alerts_path: /var/ossec/logs/alerts

qnap:
  host: "$QNAP_HOST"
  export_path: "$QNAP_SHARE"
  mount_point: $MOUNT_POINT
  nfs_version: $NFS_VERSION
  mount_options: "vers=$NFS_VERSION,hard,timeo=600,retrans=2,noatime"

archive:
  compression: $COMPRESSION
  compression_level: $COMPRESSION_LEVEL
  naming_pattern: "$naming_pattern"
  temp_dir: /tmp/wazuh-archive
  interval: $ARCHIVE_INTERVAL

gpg:
  enabled: true
  key_id: "$GPG_FINGERPRINT"
  detached: true

integrity:
  algorithm: sha256
  create_manifest: true
  chain_manifests: true

retention:
  local:
    days_before_archive: 1
    days_keep_local: $DAYS_KEEP_LOCAL
    delete_after_transfer: true
  remote:
    days: $RETENTION_DAYS
    organize_by_date: true

schedule:
  archive_cron: "$([ "$ARCHIVE_INTERVAL" = "hourly" ] && echo "1 * * * *" || echo "0 2 * * *")"
  integrity_check_cron: "0 6 * * 0"
  cleanup_cron: "0 3 * * *"

notifications:
  email:
    enabled: false
  syslog:
    enabled: true
    facility: local0

logging:
  level: INFO
  file: $LOG_DIR/main.log
  max_size: 100
  backup_count: 5
EOF
  chmod 640 "$CONFIG_DIR/config.yaml"
  log_ok "Configurazione scritta in $CONFIG_DIR/config.yaml"
}

# ------------------------------------------------------------------
# Step 8: Systemd units
# ------------------------------------------------------------------
install_systemd() {
  log_step "7/8 Installazione timer systemd"

  cat > "$SYSTEMD_DIR/wazuh-immutable-store.service" <<EOF
[Unit]
Description=Wazuh Immutable Store - archive cycle
After=network-online.target $MOUNT_POINT.mount
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN_DIR/wazuh-immutable-store archive
User=root
Nice=10
EOF

  if [[ "$ARCHIVE_INTERVAL" == "hourly" ]]; then
    cat > "$SYSTEMD_DIR/wazuh-immutable-store.timer" <<'EOF'
[Unit]
Description=Run Wazuh Immutable Store archive hourly

[Timer]
OnCalendar=*-*-* *:01:00
Persistent=true
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
  else
    cat > "$SYSTEMD_DIR/wazuh-immutable-store.timer" <<'EOF'
[Unit]
Description=Run Wazuh Immutable Store archive daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  fi

  cat > "$SYSTEMD_DIR/wazuh-immutable-store-retention.service" <<EOF
[Unit]
Description=Wazuh Immutable Store - retention enforcement

[Service]
Type=oneshot
ExecStart=$BIN_DIR/wazuh-immutable-store retention
User=root
EOF
  cat > "$SYSTEMD_DIR/wazuh-immutable-store-retention.timer" <<'EOF'
[Unit]
Description=Run Wazuh Immutable Store retention daily

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  cat > "$SYSTEMD_DIR/wazuh-immutable-store-verify.service" <<EOF
[Unit]
Description=Wazuh Immutable Store - weekly integrity verify

[Service]
Type=oneshot
ExecStart=$BIN_DIR/wazuh-immutable-store verify
User=root
EOF
  cat > "$SYSTEMD_DIR/wazuh-immutable-store-verify.timer" <<'EOF'
[Unit]
Description=Weekly integrity verify

[Timer]
OnCalendar=Sun *-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now wazuh-immutable-store.timer
  systemctl enable --now wazuh-immutable-store-retention.timer
  systemctl enable --now wazuh-immutable-store-verify.timer
  log_ok "Timer archive, retention, verify abilitati"
}

# ------------------------------------------------------------------
# Step 9: Rolling hash chain
# ------------------------------------------------------------------
install_rolling_hash() {
  [[ "$ENABLE_ROLLING_HASH" == "yes" ]] || { log_info "Rolling hash disabilitato per scelta (--no-rolling)"; return; }
  log_step "8/8 Rolling hash chain (composite head/tail/size, ogni $ROLLING_INTERVAL_MIN min)"

  cat > "$BIN_DIR/wazuh-rolling-hash" <<EOF
#!/bin/bash
# Rolling hash chain dei file Wazuh live — composite hash (head+tail+size)
set -euo pipefail
export GNUPGHOME=/root/.gnupg
GPG_KEY=$GPG_FINGERPRINT
MANIFEST=/var/log/wazuh-rolling-manifest.log

if [ ! -f "\$MANIFEST" ]; then
  cat > "\$MANIFEST" <<HDR
# Wazuh rolling hash chain manifest
# Format: <composite_sha256>  <abs_path>  <size>  <iso_ts>  PREV:<prev_hash>
# composite = sha256( head_1M || 0x00 || tail_1M || 0x00 || ascii(size) )
# Started: \$(date -Iseconds)
HDR
  chmod 600 "\$MANIFEST"
fi

PATHS=(
  "/var/ossec/logs/archives/archives.json"
  "/var/ossec/logs/archives/archives.log"
  "/var/ossec/logs/alerts/alerts.json"
  "/var/ossec/logs/alerts/alerts.log"
)

PREV_HASH=\$(grep -v '^#' "\$MANIFEST" 2>/dev/null | tail -1 | awk '{print \$1}' || echo "")
[ -z "\$PREV_HASH" ] && PREV_HASH="GENESIS"
TS=\$(date -Iseconds)
ADDED=0

for F in "\${PATHS[@]}"; do
  if [ -f "\$F" ]; then
    SIZE=\$(stat -c %s "\$F" 2>/dev/null) || continue
    COMPOSITE=\$( ( head -c 1048576 "\$F"; printf '\0'; tail -c 1048576 "\$F"; printf '\0%s' "\$SIZE" ) | sha256sum | awk '{print \$1}')
    printf "%s  %s  %s  %s  PREV:%s\n" "\$COMPOSITE" "\$F" "\$SIZE" "\$TS" "\$PREV_HASH" >> "\$MANIFEST"
    PREV_HASH="\$COMPOSITE"
    ADDED=\$((ADDED+1))
  fi
done
[ "\$ADDED" -eq 0 ] && printf "# %s  no live log files found  PREV:%s\n" "\$TS" "\$PREV_HASH" >> "\$MANIFEST"

gpg --batch --yes --pinentry-mode loopback --passphrase "" \\
    --output "\${MANIFEST}.sig" --detach-sign "\$MANIFEST" 2>/dev/null
EOF
  chmod +x "$BIN_DIR/wazuh-rolling-hash"

  cat > "$BIN_DIR/wazuh-rolling-verify" <<'EOF'
#!/bin/bash
# Verifica chain + firma GPG del manifest rolling
set -euo pipefail
export GNUPGHOME=/root/.gnupg
MANIFEST=/var/log/wazuh-rolling-manifest.log

echo "=== Verifica firma GPG del manifest ==="
if gpg --batch --verify "${MANIFEST}.sig" "$MANIFEST" 2>&1 | grep -q "Good signature"; then
  echo "  ✓ Firma GPG valida"
else
  echo "  ✗ Firma GPG NON VALIDA — manifest manomesso dopo l'ultima firma"
  gpg --batch --verify "${MANIFEST}.sig" "$MANIFEST" 2>&1 | sed 's/^/    /'
  exit 1
fi

echo
echo "=== Verifica chain di hash ==="
PREV=""
LINE_NO=0
ERRORS=0
while IFS= read -r line; do
  LINE_NO=$((LINE_NO+1))
  HASH=$(echo "$line" | awk '{print $1}')
  PREV_REF=$(echo "$line" | grep -oP 'PREV:\K\S+')
  if [ -n "$PREV" ] && [ "$PREV_REF" != "$PREV" ]; then
    echo "  ✗ Chain rotta alla riga $LINE_NO: expected PREV=$PREV, got PREV=$PREV_REF"
    ERRORS=$((ERRORS+1))
  fi
  PREV="$HASH"
done < <(grep -v '^#' "$MANIFEST")
[ "$ERRORS" -eq 0 ] && echo "  ✓ Chain integra"

echo
TOT=$(grep -cv '^#' "$MANIFEST" || echo 0)
SIZE=$(du -h "$MANIFEST" | awk '{print $1}')
echo "=== Statistiche ==="
echo "  Entry totali:  $TOT"
echo "  Manifest size: $SIZE"
EOF
  chmod +x "$BIN_DIR/wazuh-rolling-verify"

  cat > "$SYSTEMD_DIR/wazuh-rolling-hash.service" <<EOF
[Unit]
Description=Wazuh rolling hash chain of live logs
After=wazuh-manager.service

[Service]
Type=oneshot
ExecStart=$BIN_DIR/wazuh-rolling-hash
User=root
Nice=15
EOF

  cat > "$SYSTEMD_DIR/wazuh-rolling-hash.timer" <<EOF
[Unit]
Description=Run Wazuh rolling hash chain every $ROLLING_INTERVAL_MIN minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${ROLLING_INTERVAL_MIN}min
Persistent=true
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now wazuh-rolling-hash.timer
  "$BIN_DIR/wazuh-rolling-hash"
  log_ok "Rolling hash chain attivo (ogni $ROLLING_INTERVAL_MIN min)"
}

# ------------------------------------------------------------------
# Step 10: Test e summary
# ------------------------------------------------------------------
test_and_summary() {
  log_step "Verifica finale"

  log_info "Test connection..."
  "$BIN_DIR/wazuh-immutable-store" test 2>&1 | sed 's/^/    /' | tail -15

  log_info "Status sistema..."
  "$BIN_DIR/wazuh-immutable-store" status 2>&1 | sed 's/^/    /' | tail -25

  log_info "Timer attivi..."
  systemctl list-timers --no-pager 2>/dev/null | grep -E "wazuh|NEXT" | head -8 | sed 's/^/    /'

  echo
  cat <<EOF

  ${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}
  ${GREEN}${BOLD}║   INSTALLAZIONE COMPLETATA                                   ║${NC}
  ${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}

  ${BOLD}Riepilogo:${NC}
    NAS:               $QNAP_HOST:$QNAP_SHARE → $MOUNT_POINT
    GPG fingerprint:   $GPG_FINGERPRINT
    Backup chiave:     $GPG_BACKUP_DIR/ (cifrato AES-256)
    Archive interval:  $ARCHIVE_INTERVAL
    Retention WORM:    $RETENTION_DAYS giorni
    Retention locale:  $DAYS_KEEP_LOCAL giorni
    Rolling hash:      ogni $ROLLING_INTERVAL_MIN min ($ENABLE_ROLLING_HASH)

  ${BOLD}Comandi utili:${NC}
    sudo wazuh-immutable-store status          ${CYAN}# Health check${NC}
    sudo wazuh-immutable-store verify          ${CYAN}# Verify integrità${NC}
    sudo wazuh-immutable-store list            ${CYAN}# Elenco archivi${NC}
    sudo wazuh-immutable-store archive         ${CYAN}# Run manuale archive${NC}
    sudo wazuh-rolling-verify                  ${CYAN}# Verify rolling chain${NC}
    sudo bash $SCRIPT_DIR_REPO/maintenance.sh  ${CYAN}# Menu manutenzione${NC}

  ${BOLD}TODO operativo:${NC}
    1. Salva la passphrase del backup chiave nel vault aziendale
    2. Trasferisci $GPG_BACKUP_DIR/* in vault Domarc + cassaforte cliente
    3. Considera l'attivazione di auditd su /root/.gnupg/ (hardening)
    4. Verifica il primo run automatico nelle prossime ore

EOF
}

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
main() {
  parse_args "$@"
  check_root
  welcome
  check_os
  check_prerequisites
  gather_input
  setup_nfs_mount
  install_python_package
  generate_gpg_key
  write_config
  install_systemd
  install_rolling_hash
  test_and_summary
}

main "$@"
