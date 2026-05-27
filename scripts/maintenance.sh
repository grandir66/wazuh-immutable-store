#!/bin/bash
#
# Wazuh Immutable Store — Maintenance interactive menu
#
# Strumento interattivo per la gestione e manutenzione completa
# della soluzione Wazuh Immutable Store.
#
# Uso: sudo bash scripts/maintenance.sh
#
set -uo pipefail

# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

# ------------------------------------------------------------------
# Paths standard
# ------------------------------------------------------------------
CONFIG_FILE="/etc/wazuh-immutable-store/config.yaml"
INSTALL_DIR="/opt/wazuh-immutable-store"
LOG_DIR="/var/log/wazuh-immutable-store"
ROLLING_MANIFEST="/var/log/wazuh-rolling-manifest.log"
GPG_BACKUP_DIR="/root/gpg-backup"
EXPORT_DIR="/var/log/wazuh-immutable-store/exports"

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_root() {
  [[ $EUID -eq 0 ]] || { log_error "Eseguire come root (sudo $0)"; exit 1; }
}

press_enter() {
  echo
  read -r -p "$(echo -e "${DIM}Premi INVIO per tornare al menu...${NC}")"
}

ask_yesno() {
  local prompt="$1" default="${2:-N}" var
  while true; do
    if [[ "$default" =~ ^[Yy] ]]; then
      read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [Y/n]: ")" var
      var="${var:-Y}"
    else
      read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [y/N]: ")" var
      var="${var:-N}"
    fi
    case "$var" in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "  Rispondere y o n" ;;
    esac
  done
}

require_file() {
  [[ -f "$1" ]] || { log_error "File non trovato: $1"; return 1; }
}

# Get value from config.yaml (simple yaml flat-key read)
get_config() {
  local key="$1"
  awk -v k="$key" 'BEGIN{found=0} $0 ~ "^[[:space:]]*"k":" {sub(/^[^:]*:[[:space:]]*/, ""); gsub(/^["'\'']|["'\'']$/, ""); print; exit}' "$CONFIG_FILE" 2>/dev/null
}

set_config() {
  local key="$1" value="$2"
  if grep -qE "^[[:space:]]*${key}:" "$CONFIG_FILE"; then
    sed -i "s|^\([[:space:]]*${key}:\).*|\1 ${value}|" "$CONFIG_FILE"
  else
    log_warn "Chiave $key non trovata in $CONFIG_FILE"
  fi
}

# ------------------------------------------------------------------
# Menu rendering
# ------------------------------------------------------------------
banner() {
  clear
  local host="$(hostname -s 2>/dev/null || echo "?")"
  cat <<BANNER
${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════╗
║   Wazuh Immutable Store — Maintenance Console                    ║
║   Host: $host$(printf '%*s' $((57 - ${#host})) '')║
╚══════════════════════════════════════════════════════════════════╝${NC}
BANNER
}

main_menu() {
  while true; do
    banner
    cat <<MENU

  ${BOLD}1)${NC}  Stato del sistema (health check completo)
  ${BOLD}2)${NC}  Configurazione (retention, schedule, compressione)
  ${BOLD}3)${NC}  Gestione chiavi GPG (info, export, rotazione, revoca, backup)
  ${BOLD}4)${NC}  Archive manuale (dry-run o run reale)
  ${BOLD}5)${NC}  Verifica integrità (manifest archive, rolling chain, WORM test)
  ${BOLD}6)${NC}  Recovery / Browse / Search archivi
  ${BOLD}7)${NC}  Manutenzione storage (cleanup, espansione share, rotation Wazuh)
  ${BOLD}8)${NC}  Diagnostica (NFS, GPG, disco, Wazuh, journal)
  ${BOLD}9)${NC}  Esporta report / informazioni sistema
  ${BOLD}H)${NC}  Hardening server (lancia harden-wazuh.sh)
  ${BOLD}I)${NC}  Indexer OpenSearch (ISM policy, indici, cluster)
  ${BOLD}0)${NC}  Esci

MENU
    read -r -p "$(echo -e "${BOLD}>>> Seleziona [0-9,H,I]: ${NC}")" choice
    case "$choice" in
      1) menu_status ;;
      2) menu_config ;;
      3) menu_gpg ;;
      4) menu_archive ;;
      5) menu_verify ;;
      6) menu_recovery ;;
      7) menu_maintenance ;;
      8) menu_diagnostics ;;
      9) menu_export ;;
      H|h) menu_hardening ;;
      I|i) menu_indexer ;;
      0) clear; log_info "Bye."; exit 0 ;;
      *) log_warn "Opzione non valida"; sleep 1 ;;
    esac
  done
}

# ========================================================================
# H. HARDENING
# ========================================================================
menu_hardening() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Hardening server ═══${NC}

  Riferimenti:
    ${DIM}docs/HARDENING.md${NC}     — Checklist completa con compliance mapping
    ${DIM}scripts/harden-wazuh.sh${NC} — Script idempotente Layer 1+2

  ${BOLD}1)${NC}  Esegui hardening completo (Layer 1+2, interattivo)
  ${BOLD}2)${NC}  Esegui solo Layer 1 (quick wins: UFW, SSH, NTP, fail2ban, patches)
  ${BOLD}3)${NC}  Esegui solo Layer 2 (sysctl, mount, auditd, AIDE, FIM, PAM)
  ${BOLD}4)${NC}  Dry-run (mostra cosa farebbe, non applica)
  ${BOLD}5)${NC}  Stato hardening corrente (auto-check)
  ${BOLD}6)${NC}  Visualizza HARDENING.md (less)
  ${BOLD}0)${NC}  Torna al menu principale

EOF
    read -r -p ">>> [0-6]: " c
    local script="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/harden-wazuh.sh"
    [[ -x "$script" ]] || script="/opt/wazuh-immutable-store-scripts/harden-wazuh.sh"
    case "$c" in
      1) [[ -x "$script" ]] && bash "$script" || log_error "harden-wazuh.sh non trovato"; press_enter ;;
      2) [[ -x "$script" ]] && bash "$script" --only layer1 || log_error "harden-wazuh.sh non trovato"; press_enter ;;
      3) [[ -x "$script" ]] && bash "$script" --only layer2 || log_error "harden-wazuh.sh non trovato"; press_enter ;;
      4) [[ -x "$script" ]] && bash "$script" --dry-run || log_error "harden-wazuh.sh non trovato"; press_enter ;;
      5) hardening_status ;;
      6) less "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../docs/HARDENING.md" 2>/dev/null \
         || less /opt/wazuh-immutable-store-docs/HARDENING.md 2>/dev/null \
         || log_error "HARDENING.md non trovato (cerca in scripts/../docs/)" ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

hardening_status() {
  banner
  echo -e "${BOLD}═══ Stato hardening corrente (auto-check) ═══${NC}\n"

  local pass=0 fail=0

  echo -e "${BOLD}A) UFW firewall:${NC}"
  if ufw status 2>/dev/null | head -1 | grep -q "active"; then
    log_ok "ATTIVO"; pass=$((pass+1))
  else
    log_warn "DISATTIVO o non installato"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}B) SSH hardening:${NC}"
  if [[ -f /etc/ssh/sshd_config.d/99-harden.conf ]]; then
    log_ok "config 99-harden.conf presente"
    sshd -T 2>/dev/null | grep -E "permitrootlogin|passwordauthentication|maxauthtries" | sed 's/^/    /'
    pass=$((pass+1))
  else
    log_warn "config 99-harden.conf NON presente"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}C) Unattended-upgrades:${NC}"
  if systemctl is-enabled unattended-upgrades 2>/dev/null | grep -q enabled; then
    log_ok "ATTIVO"; pass=$((pass+1))
  else
    log_warn "NON attivo"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}D) fail2ban:${NC}"
  if systemctl is-active fail2ban 2>/dev/null | grep -q active; then
    log_ok "ATTIVO"; pass=$((pass+1))
    fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Banned" | sed 's/^/    /' || true
  else
    log_warn "NON attivo"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}E) NTP chrony:${NC}"
  if chronyc tracking 2>/dev/null | grep -q "Leap status.*Normal"; then
    log_ok "Sync OK"; pass=$((pass+1))
  else
    log_warn "Non sincronizzato o non installato"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}F) Sysctl hardening:${NC}"
  if [[ -f /etc/sysctl.d/99-wazuh-hardening.conf ]]; then
    log_ok "config 99-wazuh-hardening.conf presente"
    sysctl -n kernel.randomize_va_space kernel.kptr_restrict fs.suid_dumpable 2>/dev/null | paste -d= - <(echo -e "randomize_va_space\nkptr_restrict\nsuid_dumpable") | sed 's/^/    /'
    pass=$((pass+1))
  else
    log_warn "config sysctl NON presente"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}G) Mount options /tmp:${NC}"
  if mount | grep '/tmp ' | grep -q noexec; then
    log_ok "/tmp con noexec,nosuid,nodev"; pass=$((pass+1))
  else
    log_warn "/tmp SENZA noexec"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}H) Auditd con watch:${NC}"
  if auditctl -l 2>/dev/null | grep -q gpg_key_access; then
    log_ok "watch gpg_key_access attivo"; pass=$((pass+1))
  else
    log_warn "watch GPG NON attivo"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}I) AIDE:${NC}"
  if [[ -f /var/lib/aide/aide.db ]]; then
    log_ok "database AIDE presente ($(du -h /var/lib/aide/aide.db | cut -f1))"; pass=$((pass+1))
  else
    log_warn "AIDE non inizializzato"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}J) Wazuh FIM self-monitoring:${NC}"
  if grep -q "/root/.gnupg" /var/ossec/etc/ossec.conf 2>/dev/null; then
    log_ok "FIM su /root/.gnupg configurato"; pass=$((pass+1))
  else
    log_warn "FIM self-monitoring NON configurato"; fail=$((fail+1))
  fi

  echo -e "\n${BOLD}L) PAM lockout:${NC}"
  if grep -q faillock /etc/pam.d/common-auth 2>/dev/null; then
    log_ok "pam_faillock configurato"; pass=$((pass+1))
  else
    log_warn "pam_faillock NON configurato"; fail=$((fail+1))
  fi

  echo
  echo "════════════════════════════════════════════════"
  echo -e "  Risultato: ${GREEN}$pass passati${NC} / ${RED}$fail mancanti${NC} su 11 check"
  if [[ $fail -gt 0 ]]; then
    echo -e "  Esegui: ${CYAN}sudo bash $(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/harden-wazuh.sh${NC}"
  fi
  press_enter
}

# ========================================================================
# 1. STATUS
# ========================================================================
menu_status() {
  banner
  echo -e "${BOLD}═══ Stato del sistema ═══${NC}\n"

  echo -e "${CYAN}┌─ Config ─────────────────────────────────────────────┐${NC}"
  if [[ -f "$CONFIG_FILE" ]]; then
    echo "  Config:        $CONFIG_FILE"
    echo "  NAS host:      $(get_config host)"
    echo "  NAS share:     $(get_config export_path)"
    echo "  Mount point:   $(get_config mount_point)"
    echo "  Interval:      $(get_config interval)"
    echo "  Retention WORM: $(get_config days) giorni"
    echo "  GPG key:       $(get_config key_id)"
  else
    log_warn "Config non presente: $CONFIG_FILE"
  fi
  echo

  echo -e "${CYAN}┌─ Servizio applicativo ───────────────────────────────┐${NC}"
  if command -v wazuh-immutable-store >/dev/null 2>&1; then
    wazuh-immutable-store status 2>&1 | sed 's/^/  /'
  else
    log_warn "CLI wazuh-immutable-store non installata"
  fi
  echo

  echo -e "${CYAN}┌─ Timer systemd ──────────────────────────────────────┐${NC}"
  systemctl list-timers --no-pager 2>/dev/null | grep -E "wazuh|NEXT" | head -10 | sed 's/^/  /'
  echo

  echo -e "${CYAN}┌─ Rolling hash manifest ──────────────────────────────┐${NC}"
  if [[ -f "$ROLLING_MANIFEST" ]]; then
    local entries size last
    entries=$(grep -cv '^#' "$ROLLING_MANIFEST" 2>/dev/null || echo 0)
    size=$(du -h "$ROLLING_MANIFEST" | awk '{print $1}')
    last=$(grep -v '^#' "$ROLLING_MANIFEST" | tail -1 | awk '{print $4}')
    echo "  Manifest:      $ROLLING_MANIFEST"
    echo "  Entry totali:  $entries"
    echo "  Size:          $size"
    echo "  Ultima entry:  $last"
  else
    log_warn "Manifest rolling non presente"
  fi
  echo

  echo -e "${CYAN}┌─ Disco / mount ──────────────────────────────────────┐${NC}"
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  if mountpoint -q "$mp"; then
    df -h "$mp" | tail -1 | awk '{printf "  Share WORM:    %s used / %s total (%s)\n", $3, $2, $5}'
  else
    log_warn "Mount $mp non attivo"
  fi
  df -h /var/ossec/logs 2>/dev/null | tail -1 | awk '{printf "  /var (logs):   %s used / %s total (%s)\n", $3, $2, $5}'

  press_enter
}

# ========================================================================
# 2. CONFIGURAZIONE
# ========================================================================
menu_config() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Configurazione ═══${NC}

  ${BOLD}1)${NC}  Modifica retention WORM (giorni)
  ${BOLD}2)${NC}  Modifica retention locale (giorni)
  ${BOLD}3)${NC}  Modifica interval archive (hourly/daily)
  ${BOLD}4)${NC}  Modifica compressione (gzip/bz2/xz + livello 1-9)
  ${BOLD}5)${NC}  Modifica NAS host/share (cambio NAS)
  ${BOLD}6)${NC}  Visualizza config completa (cat config.yaml)
  ${BOLD}7)${NC}  Edita config.yaml in editor (nano/vi)
  ${BOLD}0)${NC}  Torna al menu principale

EOF
    read -r -p ">>> [0-7]: " c
    case "$c" in
      1) cfg_retention_worm ;;
      2) cfg_retention_local ;;
      3) cfg_archive_interval ;;
      4) cfg_compression ;;
      5) cfg_nas ;;
      6) less "$CONFIG_FILE" ;;
      7) ${EDITOR:-nano} "$CONFIG_FILE" ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

cfg_retention_worm() {
  local cur new
  cur=$(get_config days)
  log_info "Retention attuale: $cur giorni"
  log_warn "Nota: la retention WORM sul NAS è bloccata a livello firmware e può solo essere ALLUNGATA, mai ridotta. Questo parametro nello script controlla solo quando rimuovere i file dal NAS (operazione che il WORM rigetterà se la retention NAS non è scaduta)."
  read -r -p "Nuova retention (giorni) [$cur]: " new
  new="${new:-$cur}"
  if [[ "$new" =~ ^[0-9]+$ ]] && [[ $new -gt 0 ]]; then
    set_config days "$new"
    log_ok "Retention impostata a $new giorni"
  else
    log_error "Valore non valido"
  fi
  press_enter
}

cfg_retention_local() {
  local cur new
  cur=$(get_config days_keep_local)
  log_info "Retention locale attuale: $cur giorni"
  read -r -p "Nuovi giorni di cleanup locale [$cur]: " new
  new="${new:-$cur}"
  if [[ "$new" =~ ^[0-9]+$ ]]; then
    set_config days_keep_local "$new"
    log_ok "Retention locale impostata a $new giorni"
  else
    log_error "Valore non valido"
  fi
  press_enter
}

cfg_archive_interval() {
  local cur new
  cur=$(get_config interval)
  log_info "Interval attuale: $cur"
  log_info "Opzioni: hourly (1h finestra esposizione) | daily (24h)"
  read -r -p "Nuovo interval [$cur]: " new
  new="${new:-$cur}"
  if [[ "$new" =~ ^(hourly|daily)$ ]]; then
    set_config interval "$new"
    if [[ "$new" == "hourly" ]]; then
      set_config naming_pattern '"wazuh-logs-{date}-{hour}.tar.gz"'
      mkdir -p /etc/systemd/system/wazuh-immutable-store.timer.d
      cat > /etc/systemd/system/wazuh-immutable-store.timer.d/hourly.conf <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* *:01:00
Persistent=true
EOF
    else
      set_config naming_pattern '"wazuh-logs-{date}.tar.gz"'
      rm -f /etc/systemd/system/wazuh-immutable-store.timer.d/hourly.conf 2>/dev/null
    fi
    systemctl daemon-reload
    systemctl restart wazuh-immutable-store.timer
    log_ok "Interval cambiato a $new; timer aggiornato"
  else
    log_error "Valore non valido (hourly o daily)"
  fi
  press_enter
}

cfg_compression() {
  local cur_algo cur_lvl
  cur_algo=$(get_config compression)
  cur_lvl=$(get_config compression_level)
  log_info "Compressione attuale: $cur_algo livello $cur_lvl"
  read -r -p "Algoritmo (gzip/bz2/xz) [$cur_algo]: " new_algo
  read -r -p "Livello (1-9) [$cur_lvl]: " new_lvl
  new_algo="${new_algo:-$cur_algo}"
  new_lvl="${new_lvl:-$cur_lvl}"
  if [[ "$new_algo" =~ ^(gzip|bz2|xz)$ ]] && [[ "$new_lvl" =~ ^[1-9]$ ]]; then
    set_config compression "$new_algo"
    set_config compression_level "$new_lvl"
    log_ok "Compressione impostata: $new_algo livello $new_lvl"
  else
    log_error "Valori non validi"
  fi
  press_enter
}

cfg_nas() {
  log_warn "Cambio NAS: questa operazione richiede umount + remount con nuove credenziali NFS"
  ask_yesno "Procedere?" "N" || { press_enter; return; }
  local cur_host cur_share cur_mp new_host new_share
  cur_host=$(get_config host); cur_share=$(get_config export_path); cur_mp=$(get_config mount_point)
  read -r -p "Nuovo IP/hostname NAS [$cur_host]: " new_host
  read -r -p "Nuovo path share [$cur_share]: " new_share
  new_host="${new_host:-$cur_host}"
  new_share="${new_share:-$cur_share}"
  [[ "$new_share" =~ ^/ ]] || new_share="/$new_share"
  log_info "Stop timer..."
  systemctl stop wazuh-immutable-store.timer wazuh-rolling-hash.timer 2>/dev/null
  log_info "Umount $cur_mp..."
  umount "$cur_mp" 2>/dev/null || true
  log_info "Aggiorno fstab..."
  sed -i "\|$cur_host:$cur_share|d" /etc/fstab
  echo "$new_host:$new_share $cur_mp nfs4 vers=4,hard,timeo=600,retrans=2,_netdev,noatime 0 0" >> /etc/fstab
  log_info "Test mount nuovo NAS..."
  if mount "$cur_mp"; then
    log_ok "Mount nuovo NAS riuscito"
    set_config host "\"$new_host\""
    set_config export_path "\"$new_share\""
    systemctl start wazuh-immutable-store.timer wazuh-rolling-hash.timer 2>/dev/null
  else
    log_error "Mount fallito — verifica IP/share/host access del nuovo NAS"
  fi
  press_enter
}

# ========================================================================
# 3. GPG
# ========================================================================
menu_gpg() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Gestione chiavi GPG ═══${NC}

  ${BOLD}1)${NC}  Mostra info chiave (fingerprint, UID, expire)
  ${BOLD}2)${NC}  Export chiave pubblica (file .asc)
  ${BOLD}3)${NC}  Export backup chiave privata + cert revoca (cifrato AES-256)
  ${BOLD}4)${NC}  Verifica firma di un archivio specifico
  ${BOLD}5)${NC}  Genera NUOVO certificato di revoca (sovrascrive il vecchio)
  ${BOLD}6)${NC}  Rotazione chiave (genera nuova chiave + overlap 30gg)
  ${BOLD}7)${NC}  REVOCA EMERGENZA chiave attuale (importa cert revoca)
  ${BOLD}8)${NC}  Test signing (firma un file dummy + verify)
  ${BOLD}0)${NC}  Torna al menu principale

EOF
    read -r -p ">>> [0-8]: " c
    case "$c" in
      1) gpg_show_info ;;
      2) gpg_export_pub ;;
      3) gpg_backup_priv ;;
      4) gpg_verify_archive ;;
      5) gpg_gen_revoke ;;
      6) gpg_rotate ;;
      7) gpg_revoke_emergency ;;
      8) gpg_test_signing ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

gpg_show_info() {
  export GNUPGHOME=/root/.gnupg
  local fpr; fpr=$(get_config key_id)
  echo -e "${BOLD}═══ Info chiave GPG ═══${NC}\n"
  echo "Fingerprint config: $fpr"
  echo
  gpg --list-keys --with-fingerprint --keyid-format=long "$fpr" 2>&1
  echo
  gpg --list-secret-keys --keyid-format=long "$fpr" 2>&1
  press_enter
}

gpg_export_pub() {
  export GNUPGHOME=/root/.gnupg
  local fpr out
  fpr=$(get_config key_id)
  out="${EXPORT_DIR}/wazuh-archive-pubkey-$(date +%Y%m%d-%H%M%S).asc"
  mkdir -p "$EXPORT_DIR"
  gpg --armor --export "$fpr" > "$out"
  log_ok "Chiave pubblica esportata in: $out"
  echo
  log_info "Esempio uso per verifica indipendente:"
  echo "    gpg --import $out"
  echo "    gpg --verify <archivio>.tar.gz.sig <archivio>.tar.gz"
  press_enter
}

gpg_backup_priv() {
  export GNUPGHOME=/root/.gnupg
  local fpr; fpr=$(get_config key_id)
  local stamp; stamp=$(date +%Y%m%d-%H%M%S)
  local outdir="$EXPORT_DIR/gpg-backup-$stamp"
  mkdir -p "$outdir" && chmod 700 "$outdir"

  log_info "Genero passphrase forte per backup..."
  local passphrase; passphrase=$(openssl rand -base64 32 | tr -d '/+=' | head -c 28)

  log_info "Export chiave privata..."
  gpg --batch --pinentry-mode loopback --passphrase "" \
      --armor --export-secret-keys "$fpr" > "$outdir/wazuh-archive-privkey.asc"

  log_info "Copia cert revoca pre-generato..."
  local revoke_src="/root/.gnupg/openpgp-revocs.d/${fpr}.rev"
  if [[ -f "$revoke_src" ]]; then
    cp "$revoke_src" "$outdir/wazuh-archive-revoke.asc"
  else
    log_warn "Cert revoca non trovato in $revoke_src — usa opzione 5 per generarlo"
  fi

  log_info "Cifratura AES-256..."
  for f in wazuh-archive-privkey.asc wazuh-archive-revoke.asc; do
    [[ -f "$outdir/$f" ]] || continue
    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-count 65011712 \
        -o "$outdir/${f}.gpg" "$outdir/$f"
    shred -u "$outdir/$f"
  done

  gpg --armor --export "$fpr" > "$outdir/wazuh-archive-pubkey.asc"
  echo "$fpr" > "$outdir/wazuh-archive-fingerprint.txt"
  chmod 600 "$outdir"/*

  log_ok "Backup completato in: $outdir/"
  echo
  cat <<EOF

  ${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}
  ${BOLD}${YELLOW}║   PASSPHRASE — SALVA SUBITO IN VAULT, NON SARÀ RIPETUTA      ║${NC}
  ${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}

      Fingerprint: ${BOLD}$fpr${NC}
      Passphrase:  ${BOLD}$passphrase${NC}
      Cartella:    $outdir

  Hashes SHA-256 dei file (per audit trail):
EOF
  sha256sum "$outdir"/* 2>/dev/null | awk '{printf "      %s  %s\n", $1, $2}'
  press_enter
}

gpg_verify_archive() {
  local fpr; fpr=$(get_config key_id)
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  local sigfile
  read -r -p "Path completo dell'archivio .tar.gz da verificare: " archive
  [[ -f "$archive" ]] || { log_error "File non trovato"; press_enter; return; }
  sigfile="${archive}.sig"
  [[ -f "$sigfile" ]] || { log_error "File firma .sig non trovato"; press_enter; return; }
  echo
  GNUPGHOME=/root/.gnupg gpg --batch --verify "$sigfile" "$archive" 2>&1
  echo
  if [[ -f "${archive}.sha256" ]]; then
    log_info "Verifica anche SHA-256..."
    (cd "$(dirname "$archive")" && sha256sum -c "$(basename "${archive}.sha256")") 2>&1
  fi
  press_enter
}

gpg_gen_revoke() {
  export GNUPGHOME=/root/.gnupg
  local fpr; fpr=$(get_config key_id)
  local out="$EXPORT_DIR/wazuh-archive-revoke-$(date +%Y%m%d-%H%M%S).asc"
  mkdir -p "$EXPORT_DIR"
  log_warn "Genero un nuovo certificato di revoca per la chiave $fpr"
  log_info "Reason: 1 = key compromised (default)"
  ask_yesno "Procedere?" "Y" || { press_enter; return; }
  gpg --batch --pinentry-mode loopback --passphrase "" \
      --command-fd 0 --status-fd 2 \
      --gen-revoke "$fpr" > "$out" 2>/dev/null <<'INP'
y
1
Revoke certificate generated via maintenance.sh
y
INP
  if [[ -s "$out" ]]; then
    chmod 600 "$out"
    log_ok "Certificato di revoca generato: $out"
    log_warn "Custodisci SEPARATAMENTE dalla chiave privata (vault + cassaforte)"
  else
    log_error "Generazione fallita"
  fi
  press_enter
}

gpg_rotate() {
  log_warn "Rotazione chiave: operazione delicata."
  log_info "Generà nuova chiave RSA 4096 con UID versionato + lascerà overlap 30gg."
  log_info "Nuova chiave firmerà gli archivi NUOVI. Vecchia chiave resta per verifica archivi storici."
  ask_yesno "Procedere?" "N" || { press_enter; return; }

  export GNUPGHOME=/root/.gnupg
  local cur_fpr; cur_fpr=$(get_config key_id)
  local new_uid_email="wazuh-archive-$(date +%Y%m)@$(hostname -s)"
  log_info "UID nuova chiave: $new_uid_email"
  cat <<EOF | gpg --batch --gen-key 2>&1 | tail -5
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Wazuh Archive Signer
Name-Email: $new_uid_email
Expire-Date: 0
%commit
EOF

  local new_fpr
  new_fpr=$(gpg --list-secret-keys --keyid-format=long "$new_uid_email" 2>/dev/null \
    | awk '/^sec/{getline; gsub(/^[[:space:]]+/,""); print; exit}')
  [[ -n "$new_fpr" ]] || { log_error "Generazione fallita"; press_enter; return; }
  log_ok "Nuova chiave generata: $new_fpr"

  set_config key_id "\"$new_fpr\""
  log_ok "Config aggiornata, nuova chiave attiva"
  log_info "Backup PRIMA della rotazione (opzione 3): consigliato fare backup della nuova chiave subito"

  press_enter
}

gpg_revoke_emergency() {
  cat <<EOF

  ${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}
  ${RED}${BOLD}║              REVOCA EMERGENZA CHIAVE GPG                     ║${NC}
  ${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}

  Questa operazione importerà il certificato di revoca e marcherà
  la chiave attuale come REVOCATA. Dopo la revoca:
    - Tutti gli archivi futuri firmati con questa chiave saranno
      considerati non validi dai sistemi di verifica
    - Dovrai generare e deployare una nuova chiave subito dopo

  Continuare solo in caso di COMPROMISE CONFERMATO della chiave.

EOF
  ask_yesno "Sei SICURO di voler revocare?" "N" || { press_enter; return; }
  read -r -p "Path del certificato di revoca (.asc): " revoke_file
  [[ -f "$revoke_file" ]] || { log_error "File non trovato"; press_enter; return; }
  export GNUPGHOME=/root/.gnupg
  gpg --import "$revoke_file" 2>&1
  log_warn "Stop dei timer (no nuovi archive firmati)..."
  systemctl stop wazuh-immutable-store.timer wazuh-rolling-hash.timer 2>/dev/null
  log_ok "Chiave revocata. Genera nuova chiave (opzione 6) prima di riavviare i timer."
  press_enter
}

gpg_test_signing() {
  export GNUPGHOME=/root/.gnupg
  local fpr; fpr=$(get_config key_id)
  local tmp; tmp=$(mktemp /tmp/wis-sign-test-XXXXXX.txt)
  echo "Test signing $(date -Iseconds)" > "$tmp"
  log_info "Firma di un file dummy..."
  if gpg --batch --pinentry-mode loopback --passphrase "" \
       --detach-sign --output "${tmp}.sig" "$tmp"; then
    log_ok "Firma generata"
    if gpg --verify "${tmp}.sig" "$tmp" 2>&1 | grep -q "Good signature"; then
      log_ok "Verifica firma OK"
    else
      log_error "Verifica firma FALLITA"
    fi
  else
    log_error "Firma fallita"
  fi
  rm -f "$tmp" "${tmp}.sig"
  press_enter
}

# ========================================================================
# 4. ARCHIVE
# ========================================================================
menu_archive() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Archive ═══${NC}

  ${BOLD}1)${NC}  Dry-run archive (cosa farebbe il prossimo ciclo)
  ${BOLD}2)${NC}  Esegui archive ORA (run reale)
  ${BOLD}3)${NC}  Esegui rolling hash ORA
  ${BOLD}4)${NC}  Vedi journal ultimo archive
  ${BOLD}5)${NC}  Lista archivi (LIMIT ultimi 30)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-5]: " c
    case "$c" in
      1) wazuh-immutable-store archive --dry-run 2>&1 | tail -30; press_enter ;;
      2) ask_yesno "Lanciare archive REALE ora?" "Y" && wazuh-immutable-store archive 2>&1 | tail -30; press_enter ;;
      3) /usr/local/bin/wazuh-rolling-hash && /usr/local/bin/wazuh-rolling-verify; press_enter ;;
      4) journalctl -u wazuh-immutable-store.service --no-pager -n 50; press_enter ;;
      5) wazuh-immutable-store list 2>&1 | tail -30; press_enter ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

# ========================================================================
# 5. VERIFY
# ========================================================================
menu_verify() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Verifica integrità ═══${NC}

  ${BOLD}1)${NC}  Verify manifest archive (GPG + SHA-256 + chain)
  ${BOLD}2)${NC}  Verify rolling chain (manifest live)
  ${BOLD}3)${NC}  Verify firma di un archivio specifico
  ${BOLD}4)${NC}  Test WORM: tenta delete di un archivio (deve fallire)
  ${BOLD}5)${NC}  Test WORM: scrivi marker, attendi auto-lock, tenta delete
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-5]: " c
    case "$c" in
      1) wazuh-immutable-store verify 2>&1 | tail -20; press_enter ;;
      2) /usr/local/bin/wazuh-rolling-verify; press_enter ;;
      3) gpg_verify_archive ;;
      4) verify_worm_existing ;;
      5) verify_worm_marker ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

verify_worm_existing() {
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  local f; f=$(find "$mp" -name "wazuh-logs-*.tar.gz" -not -name "*.sig" -not -name "*.sha256" -mmin +10 2>/dev/null | head -1)
  if [[ -z "$f" ]]; then
    log_warn "Nessun archivio vecchio >10 min trovato (necessario per test WORM dopo auto-lock)"
    press_enter; return
  fi
  log_info "Target test: $f"
  log_info "Tentativo rm (deve fallire se WORM attivo)..."
  if rm "$f" 2>&1; then
    log_warn "DELETE RIUSCITO — WORM NON ATTIVO o auto-lock non scaduto"
  else
    log_ok "DELETE BLOCCATO = WORM ATTIVO ✓"
  fi
  press_enter
}

verify_worm_marker() {
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  local marker="$mp/.worm-test-$(date +%s).txt"
  log_info "Scrivo marker su $marker"
  echo "WORM test $(date -Iseconds)" > "$marker"
  log_info "Auto-lock standard ~5 min. Attendere 6 min e poi tentare rm manualmente:"
  log_info "  sudo rm $marker"
  log_info "  (deve fallire con 'Operation not permitted')"
  press_enter
}

# ========================================================================
# 6. RECOVERY
# ========================================================================
menu_recovery() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Recovery / Browse / Search ═══${NC}

  ${BOLD}1)${NC}  Recover archivi per intervallo date
  ${BOLD}2)${NC}  Browse interattivo
  ${BOLD}3)${NC}  Search per pattern (regex)
  ${BOLD}4)${NC}  Export in formato JSON/CSV
  ${BOLD}5)${NC}  Lista archivi (con filtro date)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-5]: " c
    case "$c" in
      1) rec_interval ;;
      2) wazuh-immutable-store browse 2>&1; press_enter ;;
      3) read -r -p "Pattern: " p; wazuh-immutable-store search --pattern "$p" 2>&1 | head -40; press_enter ;;
      4) rec_export ;;
      5) wazuh-immutable-store list 2>&1 | tail -50; press_enter ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

rec_interval() {
  read -r -p "Data inizio (YYYY-MM-DD): " s
  read -r -p "Data fine   (YYYY-MM-DD): " e
  local out="/tmp/wis-recover-$(date +%s)"
  mkdir -p "$out"
  wazuh-immutable-store recover --start "$s" --end "$e" --output "$out" 2>&1 | tail -10
  log_ok "Recovery in: $out"
  press_enter
}

rec_export() {
  read -r -p "Data inizio (YYYY-MM-DD): " s
  read -r -p "Data fine   (YYYY-MM-DD): " e
  read -r -p "Formato (json/csv): " fmt
  local out="/tmp/wis-export-$(date +%s).$fmt"
  wazuh-immutable-store export --start "$s" --end "$e" --format "$fmt" --output "$out" 2>&1 | tail -10
  log_ok "Export in: $out"
  press_enter
}

# ========================================================================
# 7. MANUTENZIONE
# ========================================================================
menu_maintenance() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Manutenzione storage ═══${NC}

  ${BOLD}1)${NC}  Cleanup archivi locali oltre retention (wazuh-immutable-store)
  ${BOLD}2)${NC}  Forza rotation file live Wazuh (stop + mv + restart)
  ${BOLD}3)${NC}  Mostra istruzioni espansione share NAS
  ${BOLD}4)${NC}  Reset rolling manifest (cancella e ricrea)
  ${BOLD}5)${NC}  Restart timer (immutable + rolling)
  ${BOLD}6)${NC}  Disabilita logall (riduce ~40% volume)
  ${DIM}— Cleanup sistema (avanzato) —${NC}
  ${BOLD}7)${NC}  Cleanup Wazuh logs locali >N giorni (.gz già su WORM)
  ${BOLD}8)${NC}  Journald vacuum (cap a N MB + config persistente)
  ${BOLD}9)${NC}  Setup logrotate per syslog remoto (Mikrotik etc.)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-9]: " c
    case "$c" in
      1) wazuh-immutable-store retention 2>&1 | tail -20; press_enter ;;
      2) maint_rotate_wazuh ;;
      3) maint_expand_instructions ;;
      4) maint_reset_manifest ;;
      5) systemctl restart wazuh-immutable-store.timer wazuh-rolling-hash.timer; log_ok "Timer riavviati"; press_enter ;;
      6) maint_disable_logall ;;
      7) maint_cleanup_wazuh_old_logs ;;
      8) maint_journald_vacuum ;;
      9) maint_remote_syslog_logrotate ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

maint_cleanup_wazuh_old_logs() {
  cat <<EOF

  ${BOLD}═══ Cleanup Wazuh logs locali >N giorni ═══${NC}

  Cancella i file .gz e .sum in /var/ossec/logs/{archives,alerts}/ più
  vecchi di N giorni. SICURO solo se i log sono già su WORM (default sì,
  se wazuh-immutable-store ha girato regolarmente).

EOF
  local days; days=$(ask_yesno "Verificare prima la copertura WORM?" "Y" && echo "verify" || echo "skip")
  read -r -p "Cancella file più vecchi di quanti giorni? [30]: " n
  n="${n:-30}"
  [[ "$n" =~ ^[0-9]+$ ]] || { log_error "N giorni deve essere un numero"; press_enter; return; }

  echo
  echo "── Inventario pre-cleanup ──"
  local count_gz count_sum size_before
  count_gz=$(find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.gz" -mtime +$n 2>/dev/null | wc -l)
  count_sum=$(find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.sum" -mtime +$n 2>/dev/null | wc -l)
  size_before=$(find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.gz" -mtime +$n -exec du -cb {} + 2>/dev/null | tail -1 | awk '{print $1}')
  echo "  File .gz da cancellare: $count_gz"
  echo "  File .sum da cancellare: $count_sum"
  echo "  Spazio stimato: $(numfmt --to=iec-i --suffix=B ${size_before:-0})"
  echo
  echo "  Sample:"
  find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.gz" -mtime +$n 2>/dev/null | head -3 | sed 's/^/    /'

  if [[ "$days" == "verify" ]]; then
    echo
    echo "── Verifica copertura WORM ──"
    local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
    local worm_oldest worm_newest
    worm_oldest=$(find "$mp" -name "wazuh-logs-*.tar.gz" -not -name "*.sig" -not -name "*.sha256" 2>/dev/null | sort | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
    worm_newest=$(find "$mp" -name "wazuh-logs-*.tar.gz" -not -name "*.sig" -not -name "*.sha256" 2>/dev/null | sort | tail -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
    echo "  Range WORM: $worm_oldest → $worm_newest"
    echo "  I file da cancellare sono compresi in questo range?"
  fi

  echo
  ask_yesno "Procedere con cancellazione?" "N" || { press_enter; return; }
  find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.gz" -mtime +$n -delete 2>/dev/null
  find /var/ossec/logs/archives /var/ossec/logs/alerts -name "*.sum" -mtime +$n -delete 2>/dev/null
  log_ok "Cleanup completato"
  echo
  df -h /var | tail -1
  press_enter
}

maint_journald_vacuum() {
  cat <<EOF

  ${BOLD}═══ Journald vacuum + cap persistente ═══${NC}

  Riduce la dimensione di /var/log/journal/ e imposta un limite massimo
  permanente in /etc/systemd/journald.conf per evitare la ricrescita.

EOF
  echo "Spazio attuale journal:"
  journalctl --disk-usage 2>&1 | sed 's/^/  /'
  echo
  read -r -p "Limite massimo journal [500M]: " maxuse
  maxuse="${maxuse:-500M}"
  ask_yesno "Procedere con vacuum a $maxuse + config persistente?" "Y" || { press_enter; return; }

  echo
  echo "── Vacuum immediato ──"
  journalctl --vacuum-size=$maxuse 2>&1 | tail -3

  echo
  echo "── Config persistente in /etc/systemd/journald.conf ──"
  if grep -q "^SystemMaxUse=" /etc/systemd/journald.conf 2>/dev/null; then
    sed -i "s|^SystemMaxUse=.*|SystemMaxUse=$maxuse|" /etc/systemd/journald.conf
  else
    cp /etc/systemd/journald.conf /etc/systemd/journald.conf.bak-$(date +%Y%m%d-%H%M%S)
    if grep -q "^#SystemMaxUse=" /etc/systemd/journald.conf 2>/dev/null; then
      sed -i "s|^#SystemMaxUse=.*|SystemMaxUse=$maxuse|" /etc/systemd/journald.conf
    else
      echo "SystemMaxUse=$maxuse" >> /etc/systemd/journald.conf
    fi
    systemctl restart systemd-journald
  fi
  grep "^SystemMaxUse=" /etc/systemd/journald.conf
  log_ok "Journal cap impostato a $maxuse"
  press_enter
}

maint_remote_syslog_logrotate() {
  cat <<EOF

  ${BOLD}═══ Setup logrotate per /var/log/remote/ ═══${NC}

  Configura logrotate per i log syslog raccolti da host esterni
  (es. router Mikrotik via UDP 514). Rotazione giornaliera + compress.

EOF
  if [[ ! -d /var/log/remote ]]; then
    log_warn "/var/log/remote non esiste — non sembra ci sia rsyslog configurato per log remoti"
    press_enter; return
  fi
  echo "Stato attuale:"
  du -sh /var/log/remote 2>/dev/null
  echo "Top sotto-directory:"
  du -sh /var/log/remote/* 2>/dev/null | sort -rh | head -5
  echo
  read -r -p "Retention in giorni [90]: " days
  days="${days:-90}"
  [[ "$days" =~ ^[0-9]+$ ]] || { log_error "Giorni deve essere un numero"; press_enter; return; }

  ask_yesno "Procedere con setup logrotate + cleanup file >${days}gg?" "Y" || { press_enter; return; }

  cat > /etc/logrotate.d/remote-syslog <<LOGROT
# Logrotate per log syslog raccolti da host esterni
# Generato da maintenance.sh, ${days}gg retention
/var/log/remote/*/*.log {
    daily
    rotate $days
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
    su syslog syslog
}
LOGROT
  log_ok "Config logrotate creata: /etc/logrotate.d/remote-syslog"

  echo
  echo "── Cleanup immediato file >${days}gg ──"
  local count; count=$(find /var/log/remote -type f -mtime +${days} 2>/dev/null | wc -l)
  echo "  File da cancellare: $count"
  if [[ $count -gt 0 ]]; then
    find /var/log/remote -type f -mtime +${days} -delete 2>/dev/null
    log_ok "Cleanup completato"
  fi
  echo
  echo "── Compress file >7gg non ancora compressi ──"
  local compressed=0
  for f in $(find /var/log/remote -name "*.log" -mtime +7 -size +1M 2>/dev/null); do
    gzip "$f" 2>/dev/null && compressed=$((compressed+1))
  done
  log_ok "$compressed file compressi"
  echo
  du -sh /var/log/remote 2>/dev/null
  press_enter
}

maint_rotate_wazuh() {
  log_warn "Forza rotation = stop Wazuh + rename file live + restart"
  log_warn "Downtime atteso: 10-30 secondi"
  ask_yesno "Procedere?" "N" || { press_enter; return; }
  systemctl stop wazuh-manager
  for F in /var/ossec/logs/archives/archives.{json,log} /var/ossec/logs/alerts/alerts.{json,log}; do
    [[ -f "$F" ]] && mv "$F" "${F}.forced-rotate-$(date +%Y%m%d-%H%M%S)"
  done
  systemctl start wazuh-manager
  log_ok "Rotation forzata. I vecchi file restano in /var/ossec/logs/* con suffix .forced-rotate-*"
  log_info "Verranno archiviati al prossimo ciclo orario."
  press_enter
}

maint_expand_instructions() {
  cat <<EOF

  ${BOLD}═══ Espansione share NAS — istruzioni manuali (QNAP QuTS hero) ═══${NC}

  Sul NAS, via web UI:

  ${BOLD}1.${NC} Storage & Snapshots → click sul volume → vedi "Available capacity"
     • Se >1 TB libero: vai al passo 3
     • Altrimenti: passo 2

  ${BOLD}2.${NC} Storage & Snapshots → Manage → Expand Volume
     • Aumenta la size del volume (ZFS espansione live, no downtime)

  ${BOLD}3.${NC} Pannello di controllo → Cartelle condivise → seleziona la share
     • Modifica proprietà → Storage → Total capacity → aumenta valore
     • Apply (istantaneo, no remount necessario)

  ${BOLD}4.${NC} Verifica dal Wazuh:
     ${CYAN}df -h $(get_config mount_point)${NC}
     Deve mostrare la nuova size

  ${YELLOW}Nota:${NC} l'espansione NON altera la retention WORM né l'auto-lock.

EOF
  press_enter
}

maint_reset_manifest() {
  log_warn "Reset rolling manifest = cancella manifest e firma, ricrea da zero"
  ask_yesno "Procedere?" "N" || { press_enter; return; }
  shred -u "$ROLLING_MANIFEST" "${ROLLING_MANIFEST}.sig" 2>/dev/null
  /usr/local/bin/wazuh-rolling-hash
  log_ok "Manifest resettato"
  /usr/local/bin/wazuh-rolling-verify
  press_enter
}

maint_disable_logall() {
  log_warn "Disabilita <logall>yes</logall> (mantiene <logall_json>yes</logall_json>)"
  log_info "Effetto: riduzione ~40% volume log. Perdi il file .log testuale."
  ask_yesno "Procedere?" "N" || { press_enter; return; }
  cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.pre-disable-logall-$(date +%Y%m%d)
  sed -i 's|<logall>yes</logall>|<logall>no</logall>|' /var/ossec/etc/ossec.conf
  systemctl restart wazuh-manager
  log_ok "logall disabilitato + manager riavviato"
  press_enter
}

# ========================================================================
# 8. DIAGNOSTICA
# ========================================================================
menu_diagnostics() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Diagnostica ═══${NC}

  ${BOLD}1)${NC}  Test NFS (ping NAS + showmount + write test)
  ${BOLD}2)${NC}  Test GPG signing (firma+verify dummy file)
  ${BOLD}3)${NC}  Disk usage breakdown
  ${BOLD}4)${NC}  Stato Wazuh manager (wazuh-control status)
  ${BOLD}5)${NC}  Journal completo wazuh-immutable-store
  ${BOLD}6)${NC}  Journal completo wazuh-rolling-hash
  ${BOLD}7)${NC}  EPS Wazuh (stima eventi/sec)
  ${BOLD}8)${NC}  Top consumer disco (/var dettaglio)
  ${BOLD}9)${NC}  Stato cluster OpenSearch (health + indici)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-9]: " c
    case "$c" in
      1) diag_nfs ;;
      2) gpg_test_signing ;;
      3) diag_disk ;;
      4) /var/ossec/bin/wazuh-control status 2>&1; press_enter ;;
      5) journalctl -u wazuh-immutable-store.service --no-pager -n 100; press_enter ;;
      6) journalctl -u wazuh-rolling-hash.service --no-pager -n 100; press_enter ;;
      7) diag_eps ;;
      8) diag_top_disk ;;
      9) idx_cluster_quick_status ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

diag_top_disk() {
  echo -e "${BOLD}═══ Top consumer disco ═══${NC}\n"
  echo "── Disco principale ──"
  df -h / /var 2>/dev/null | sort -u | tail -3
  echo
  echo "── Top-level /var ──"
  du -sh /var/* 2>/dev/null | sort -rh | head -10
  echo
  echo "── /var/lib/* ──"
  du -sh /var/lib/* 2>/dev/null | sort -rh | head -8
  echo
  echo "── /var/log/* ──"
  du -sh /var/log/* 2>/dev/null | sort -rh | head -10
  echo
  echo "── /var/ossec/* ──"
  du -sh /var/ossec/* 2>/dev/null | sort -rh | head -8
  echo
  echo "── /var/ossec/queue/* (Wazuh queue) ──"
  du -sh /var/ossec/queue/* 2>/dev/null | sort -rh | head -8
  echo
  echo "── /var/log/journal (journald) ──"
  journalctl --disk-usage 2>&1
  press_enter
}

diag_nfs() {
  local host; host=$(get_config host)
  local share; share=$(get_config export_path)
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  echo "Ping $host:"
  ping -c 2 -W 2 "$host" 2>&1 | tail -3
  echo
  echo "showmount -e $host:"
  showmount -e "$host" 2>&1 | head -5
  echo
  echo "Mount status:"
  mount | grep "$mp" || echo "  Non montato"
  echo
  echo "Write test:"
  local t="$mp/.diag-test-$(date +%s)"
  if echo test > "$t" 2>&1; then
    echo "  ✓ Scrittura OK"
    rm "$t" 2>/dev/null
  else
    echo "  ✗ Scrittura fallita"
  fi
  press_enter
}

diag_disk() {
  echo -e "${BOLD}═══ Disk usage ═══${NC}\n"
  df -h | grep -E "^Filesystem|/var|/mnt" | head -10
  echo
  echo "/var/ossec/logs/:"
  du -sh /var/ossec/logs/* 2>/dev/null | sort -h
  echo
  local mp; mp=$(get_config mount_point); mp=${mp:-/mnt/qnap-wazuh}
  echo "Top 10 file su $mp:"
  find "$mp" -type f -printf "%s %p\n" 2>/dev/null | sort -rn | head -10 | awk '{ printf "  %10.1f MB  %s\n", $1/1024/1024, $2 }'
  press_enter
}

diag_eps() {
  local f="/var/ossec/logs/archives/archives.json"
  [[ -f "$f" ]] || { log_warn "File live non trovato"; press_enter; return; }
  echo "Stima EPS sugli ultimi 1MB di $f..."
  local lines size
  lines=$(tail -c 1048576 "$f" | wc -l)
  size=$(stat -c %s "$f")
  echo "  File size totale:  $(numfmt --to=iec-i --suffix=B $size)"
  echo "  Eventi negli ultimi 1MB:  $lines"
  echo "  Bytes/evento medio:  $((1048576/lines))"
  echo "  (per EPS reale, calcola: $lines diviso il delta tempo tra primo e ultimo evento)"
  press_enter
}

# ========================================================================
# 9. EXPORT REPORT
# ========================================================================
menu_export() {
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ Esportazione / Report ═══${NC}

  ${BOLD}1)${NC}  Report stato sistema (Markdown)
  ${BOLD}2)${NC}  Export config.yaml completo
  ${BOLD}3)${NC}  Backup completo (config + chiavi cifrate)
  ${BOLD}4)${NC}  Report archive list (CSV)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-4]: " c
    case "$c" in
      1) export_report_md ;;
      2) export_config ;;
      3) export_full_backup ;;
      4) export_archive_list ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

export_report_md() {
  mkdir -p "$EXPORT_DIR"
  local out="$EXPORT_DIR/status-report-$(date +%Y%m%d-%H%M%S).md"
  {
    echo "# Wazuh Immutable Store — Status Report"
    echo
    echo "**Host:** \`$(hostname -f 2>/dev/null || hostname)\`  "
    echo "**Generato:** $(date -Iseconds)  "
    echo
    echo "## Configurazione"
    echo
    echo '```yaml'
    [[ -f "$CONFIG_FILE" ]] && cat "$CONFIG_FILE"
    echo '```'
    echo
    echo "## Stato servizio"
    echo
    echo '```'
    wazuh-immutable-store status 2>&1
    echo '```'
    echo
    echo "## Timer systemd"
    echo
    echo '```'
    systemctl list-timers --no-pager | grep -E "wazuh|NEXT" | head -10
    echo '```'
    echo
    echo "## Disk usage"
    echo
    echo '```'
    df -h | grep -E "^Filesystem|/var|/mnt" | head -5
    echo '```'
    echo
    echo "## Rolling hash chain"
    echo
    if [[ -f "$ROLLING_MANIFEST" ]]; then
      echo "- Entries: $(grep -cv '^#' $ROLLING_MANIFEST)"
      echo "- Manifest size: $(du -h $ROLLING_MANIFEST | awk '{print $1}')"
      echo "- Ultima entry: $(grep -v '^#' $ROLLING_MANIFEST | tail -1 | awk '{print $4}')"
    fi
    echo
    echo "## GPG key"
    echo
    echo '```'
    GNUPGHOME=/root/.gnupg gpg --list-keys --keyid-format=long "$(get_config key_id)" 2>&1
    echo '```'
  } > "$out"
  log_ok "Report generato: $out"
  press_enter
}

export_config() {
  mkdir -p "$EXPORT_DIR"
  local out="$EXPORT_DIR/config-$(date +%Y%m%d-%H%M%S).yaml"
  cp "$CONFIG_FILE" "$out"
  log_ok "Config esportata: $out"
  press_enter
}

export_full_backup() {
  log_info "Backup completo = config + chiavi cifrate + script custom"
  ask_yesno "Procedere?" "Y" || { press_enter; return; }
  local stamp; stamp=$(date +%Y%m%d-%H%M%S)
  local out="$EXPORT_DIR/full-backup-$stamp"
  mkdir -p "$out" && chmod 700 "$out"

  cp "$CONFIG_FILE" "$out/" 2>/dev/null
  cp -r /etc/wazuh-immutable-store/wazuh-archive-pubkey.asc "$out/" 2>/dev/null

  gpg_backup_priv_silent "$out"

  cp /etc/systemd/system/wazuh-immutable-store*.{service,timer} "$out/" 2>/dev/null
  cp /etc/systemd/system/wazuh-rolling-hash.{service,timer} "$out/" 2>/dev/null
  cp /usr/local/bin/wazuh-rolling-hash "$out/" 2>/dev/null
  cp /usr/local/bin/wazuh-rolling-verify "$out/" 2>/dev/null

  tar -czf "${out}.tar.gz" -C "$EXPORT_DIR" "$(basename "$out")"
  rm -rf "$out"
  log_ok "Bundle completo: ${out}.tar.gz"
  press_enter
}

gpg_backup_priv_silent() {
  local outdir="$1"
  export GNUPGHOME=/root/.gnupg
  local fpr; fpr=$(get_config key_id)
  local passphrase; passphrase=$(openssl rand -base64 32 | tr -d '/+=' | head -c 28)
  gpg --batch --pinentry-mode loopback --passphrase "" --armor --export-secret-keys "$fpr" > "$outdir/privkey.asc"
  local revoke_src="/root/.gnupg/openpgp-revocs.d/${fpr}.rev"
  [[ -f "$revoke_src" ]] && cp "$revoke_src" "$outdir/revoke.asc"
  for f in privkey.asc revoke.asc; do
    [[ -f "$outdir/$f" ]] || continue
    gpg --batch --pinentry-mode loopback --passphrase "$passphrase" \
        --symmetric --cipher-algo AES256 \
        -o "$outdir/${f}.gpg" "$outdir/$f"
    shred -u "$outdir/$f"
  done
  echo "$passphrase" > "$outdir/PASSPHRASE-DELETE-AFTER-VAULT.txt"
  chmod 600 "$outdir"/*
  echo
  echo -e "  ${YELLOW}${BOLD}PASSPHRASE backup: $passphrase${NC}"
  echo -e "  ${YELLOW}File temp: $outdir/PASSPHRASE-DELETE-AFTER-VAULT.txt${NC}"
  echo -e "  ${YELLOW}Sposta in vault e CANCELLA il file temp!${NC}"
}

export_archive_list() {
  mkdir -p "$EXPORT_DIR"
  local out="$EXPORT_DIR/archive-list-$(date +%Y%m%d-%H%M%S).csv"
  wazuh-immutable-store list --format json 2>/dev/null | python3 -c "
import json,sys,csv
data=json.load(sys.stdin)
w=csv.writer(sys.stdout)
w.writerow(['name','size_mb','location','created_at'])
for a in data:
    w.writerow([a.get('name','?'), a.get('size_mb','?'), a.get('location','?'), a.get('created_at','?')])
" > "$out" 2>/dev/null || log_warn "Export json non disponibile, uso fallback"
  log_ok "Lista esportata: $out"
  press_enter
}

# ========================================================================
# I. INDEXER OPENSEARCH (ISM, indici, cluster)
# ========================================================================
# Usa cert-based auth (admin.pem / admin-key.pem). Funziona out-of-the-box
# su tutti i Wazuh manager con OpenSearch installato in modalità standard.

IDX_CERT="/etc/wazuh-indexer/certs/admin.pem"
IDX_KEY="/etc/wazuh-indexer/certs/admin-key.pem"
IDX_HOST="https://localhost:9200"

idx_curl() {
  curl -sk --cert "$IDX_CERT" --key "$IDX_KEY" "$@"
}

idx_check_auth() {
  if [[ ! -f "$IDX_CERT" ]] || [[ ! -f "$IDX_KEY" ]]; then
    log_error "Cert admin OpenSearch non trovati in /etc/wazuh-indexer/certs/"
    return 1
  fi
  local health; health=$(idx_curl "$IDX_HOST/_cluster/health" 2>&1)
  if echo "$health" | grep -q "status"; then
    return 0
  else
    log_error "Connessione OpenSearch fallita: $health" | head -3
    return 1
  fi
}

menu_indexer() {
  idx_check_auth || { press_enter; return; }
  while true; do
    banner
    cat <<EOF

  ${BOLD}═══ OpenSearch Indexer (ISM + indici + cluster) ═══${NC}

  ${BOLD}1)${NC}  Cluster health + statistiche
  ${BOLD}2)${NC}  Lista indici (top per dimensione)
  ${BOLD}3)${NC}  Aggregato indici per tipo (alerts/states/monitoring/...)
  ${BOLD}4)${NC}  Lista ISM policy esistenti
  ${BOLD}5)${NC}  Verifica policy ISM su un indice specifico
  ${DIM}— ISM management (modifiche) —${NC}
  ${BOLD}6)${NC}  Crea policy ISM 'wazuh-alerts-Ngg' + attach a indici
  ${BOLD}7)${NC}  Stima risparmio per retention (30/60/90/180/365gg)
  ${BOLD}8)${NC}  Delete retroattivo indici alerts >N giorni
  ${BOLD}9)${NC}  Fix cluster yellow (number_of_replicas=0 single-node)
  ${BOLD}0)${NC}  Torna

EOF
    read -r -p ">>> [0-9]: " c
    case "$c" in
      1) idx_cluster_status ;;
      2) idx_list_indices ;;
      3) idx_aggregate_by_type ;;
      4) idx_list_policies ;;
      5) idx_explain_policy ;;
      6) idx_create_alerts_policy ;;
      7) idx_estimate_retention ;;
      8) idx_delete_old_alerts ;;
      9) idx_fix_yellow ;;
      0) return ;;
      *) sleep 1 ;;
    esac
  done
}

idx_cluster_status() {
  echo -e "${BOLD}═══ Cluster health ═══${NC}\n"
  idx_curl "$IDX_HOST/_cluster/health?pretty" 2>&1 | head -20
  echo
  echo -e "${BOLD}═══ Stats nodes ═══${NC}\n"
  idx_curl "$IDX_HOST/_cat/nodes?v&h=name,heap.percent,ram.percent,disk.used_percent,load_1m" 2>&1
  echo
  echo -e "${BOLD}═══ Shards unassigned (causa yellow/red) ═══${NC}\n"
  idx_curl "$IDX_HOST/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason" 2>&1 | grep -E "UNASSIGNED|INITIAL" | head -10 || echo "  (nessuno)"
  press_enter
}

idx_cluster_quick_status() {
  # Versione sintetica chiamata anche da menu diagnostica
  idx_check_auth || { press_enter; return; }
  echo -e "${BOLD}═══ OpenSearch quick status ═══${NC}\n"
  idx_curl "$IDX_HOST/_cluster/health?pretty" 2>&1 | head -10
  echo
  echo "Indici attivi (totale):"
  idx_curl "$IDX_HOST/_cat/indices?h=index" 2>&1 | wc -l
  press_enter
}

idx_list_indices() {
  echo -e "${BOLD}═══ Indici (top 30 per dimensione) ═══${NC}\n"
  idx_curl "$IDX_HOST/_cat/indices?v&bytes=g&s=store.size:desc" 2>&1 | head -31
  press_enter
}

idx_aggregate_by_type() {
  echo -e "${BOLD}═══ Aggregato per tipo ═══${NC}\n"
  idx_curl "$IDX_HOST/_cat/indices?h=index,store.size&bytes=b" 2>&1 | \
    awk '{
      n=split($1, p, "-"); type=p[1]"-"p[2]
      sizes[type] += $2; counts[type]++
    } END {
      for (t in sizes) printf "  %-50s  %3d indici  %10.2f GB\n", t, counts[t], sizes[t]/1024/1024/1024
    }' | sort -k4 -rn
  press_enter
}

idx_list_policies() {
  echo -e "${BOLD}═══ ISM policy ═══${NC}\n"
  idx_curl "$IDX_HOST/_plugins/_ism/policies?pretty" 2>&1 | python3 -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print(f'  Policies totali: {d.get(\"total_policies\", 0)}')
  for p in d.get('policies', [])[:20]:
    pid = p.get('_id', '?')
    pol = p.get('policy', {})
    desc = pol.get('description', '')
    states = ','.join([s['name'] for s in pol.get('states', [])])
    print(f'')
    print(f'  ID: {pid}')
    print(f'  Description: {desc[:80]}')
    print(f'  States: {states}')
    for t in pol.get('ism_template', []):
      print(f'  Template pattern: {t.get(\"index_patterns\", [])} priority={t.get(\"priority\", 0)}')
except Exception as e:
  print(f'  Errore parsing: {e}')
" 2>&1
  press_enter
}

idx_explain_policy() {
  read -r -p "Pattern indice (es. wazuh-alerts-4.x-2026.05.27): " idx
  [[ -z "$idx" ]] && { press_enter; return; }
  echo
  idx_curl "$IDX_HOST/_plugins/_ism/explain/$idx?pretty" 2>&1 | head -30
  press_enter
}

idx_create_alerts_policy() {
  cat <<EOF

  ${BOLD}═══ Crea policy ISM wazuh-alerts-Ngg ═══${NC}

  Crea una ISM policy che cancella automaticamente gli indici
  wazuh-alerts-* più vecchi di N giorni. Si applica:
    - Nuovi indici futuri (tramite ism_template)
    - Indici esistenti (tramite POST /_plugins/_ism/add)

EOF
  read -r -p "Retention in giorni [90]: " days
  days="${days:-90}"
  [[ "$days" =~ ^[0-9]+$ ]] || { log_error "Giorni deve essere numerico"; press_enter; return; }
  local policy_id="wazuh-alerts-${days}d"

  echo
  log_info "Creo policy: $policy_id (delete dopo ${days}d)"
  ask_yesno "Procedere?" "Y" || { press_enter; return; }

  local tmpf; tmpf=$(mktemp)
  cat > "$tmpf" <<JSON
{
  "policy": {
    "description": "Wazuh alerts ${days}-day retention (auto-delete >${days}d)",
    "default_state": "hot",
    "states": [
      {"name": "hot", "actions": [], "transitions": [
        {"state_name": "delete", "conditions": {"min_index_age": "${days}d"}}
      ]},
      {"name": "delete", "actions": [{"delete": {}}], "transitions": []}
    ],
    "ism_template": [
      {"index_patterns": ["wazuh-alerts-*"], "priority": 100}
    ]
  }
}
JSON
  echo
  echo "── PUT policy ──"
  idx_curl -X PUT "$IDX_HOST/_plugins/_ism/policies/$policy_id" \
    -H 'Content-Type: application/json' -d @"$tmpf" 2>&1 | head -5
  rm -f "$tmpf"

  echo
  log_info "Attach policy a indici esistenti wazuh-alerts-*"
  ask_yesno "Attach a indici già esistenti?" "Y" || { press_enter; return; }
  idx_curl -X POST "$IDX_HOST/_plugins/_ism/add/wazuh-alerts-*" \
    -H 'Content-Type: application/json' \
    -d "{\"policy_id\": \"$policy_id\"}" 2>&1 | python3 -c "
import json,sys
d=json.loads(sys.stdin.read())
print(f'  updated_indices: {d.get(\"updated_indices\", 0)}')
print(f'  failures: {d.get(\"failures\", False)}')
"
  press_enter
}

idx_estimate_retention() {
  cat <<EOF

  ${BOLD}═══ Stima risparmio per retention ═══${NC}

EOF
  local tmpf; tmpf=$(mktemp)
  idx_curl "$IDX_HOST/_cat/indices/wazuh-alerts-*?h=index,store.size&bytes=b" > "$tmpf" 2>&1
  python3 <<PYEOF
import re
from datetime import datetime, timedelta
today = datetime.utcnow()
buckets = {30: 0, 60: 0, 90: 0, 180: 0, 365: 0}
count_per_bucket = {k: 0 for k in buckets}
total = 0; n_idx = 0
with open('$tmpf') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) < 2: continue
        idx = parts[0]
        try: size = int(parts[1])
        except: continue
        total += size; n_idx += 1
        m = re.search(r'(\d{4})\.(\d{2})\.(\d{2})', idx)
        if not m: continue
        try:
            d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            age = (today - d).days
            for cutoff in buckets:
                if age > cutoff:
                    buckets[cutoff] += size
                    count_per_bucket[cutoff] += 1
        except: pass

print(f"  Totale wazuh-alerts-*: {total/1024**3:.2f} GB ({n_idx} indici)\n")
print(f"  {'Retention':>12s}  {'Indici cancellati':>20s}  {'Spazio liberato':>17s}  {'Rimane':>13s}")
print(f"  {'-'*12}  {'-'*20}  {'-'*17}  {'-'*13}")
for r in [30, 60, 90, 180, 365]:
    n = count_per_bucket[r]
    saved = buckets[r] / 1024**3
    remaining = (total - buckets[r]) / 1024**3
    pct = (saved/(total/1024**3)*100) if total else 0
    print(f"  {r:>7} gg     {n:>20d}  {saved:>13.2f} GB ({pct:>3.0f}%)  {remaining:>10.2f} GB")
PYEOF
  rm -f "$tmpf"
  press_enter
}

idx_delete_old_alerts() {
  cat <<EOF

  ${BOLD}═══ Delete retroattivo indici alerts >N giorni ═══${NC}

  ${YELLOW}⚠ Operazione distruttiva.${NC} Cancella indici OpenSearch
  permanentemente. Gli alert restano comunque su WORM (tar.gz
  giornaliero), ma perdi velocità di query per quelle date.

EOF
  read -r -p "Cancella indici alerts più vecchi di quanti giorni? [90]: " days
  days="${days:-90}"
  [[ "$days" =~ ^[0-9]+$ ]] || { log_error "Giorni deve essere numerico"; press_enter; return; }

  local tmpf; tmpf=$(mktemp)
  idx_curl "$IDX_HOST/_cat/indices/wazuh-alerts-*?h=index,store.size&bytes=b" > "$tmpf" 2>&1
  local todelf; todelf=$(mktemp)
  python3 <<PYEOF > "$todelf"
import re
from datetime import datetime
today = datetime.utcnow()
total = 0
with open('$tmpf') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) < 2: continue
        idx = parts[0]
        try: size = int(parts[1])
        except: continue
        m = re.search(r'(\d{4})\.(\d{2})\.(\d{2})', idx)
        if not m: continue
        d = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if (today - d).days > $days:
            print(idx)
PYEOF
  local count; count=$(wc -l < "$todelf")
  echo
  echo "  Indici da cancellare: $count"
  echo "  Sample (primi 3):"
  head -3 "$todelf" | sed 's/^/    /'
  echo "  Sample (ultimi 3):"
  tail -3 "$todelf" | sed 's/^/    /'
  rm -f "$tmpf"

  echo
  if [[ $count -eq 0 ]]; then
    log_ok "Nessun indice da cancellare"
    rm -f "$todelf"
    press_enter; return
  fi

  ask_yesno "Procedere con cancellazione $count indici?" "N" || { rm -f "$todelf"; press_enter; return; }

  cp "$todelf" "/root/wazuh-ism-cleanup-$(date +%Y%m%d-%H%M%S).list"
  log_info "Backup lista in /root/wazuh-ism-cleanup-*.list"

  local deleted=0 batch=() BATCH_SIZE=50
  while IFS= read -r idx; do
    batch+=("$idx")
    if [ ${#batch[@]} -ge $BATCH_SIZE ]; then
      local LIST=$(IFS=,; echo "${batch[*]}")
      local resp; resp=$(idx_curl -X DELETE "$IDX_HOST/$LIST" 2>&1)
      if echo "$resp" | grep -q '"acknowledged":true'; then
        deleted=$((deleted + ${#batch[@]}))
        echo "  ✓ batch $deleted/$count ok"
      else
        log_warn "Batch fallito: $resp" | head -1
      fi
      batch=()
    fi
  done < "$todelf"
  # Ultimo batch
  if [ ${#batch[@]} -gt 0 ]; then
    local LIST=$(IFS=,; echo "${batch[*]}")
    local resp; resp=$(idx_curl -X DELETE "$IDX_HOST/$LIST" 2>&1)
    if echo "$resp" | grep -q '"acknowledged":true'; then
      deleted=$((deleted + ${#batch[@]}))
      echo "  ✓ batch finale $deleted/$count ok"
    fi
  fi
  rm -f "$todelf"
  log_ok "Cancellati $deleted / $count indici"
  echo
  df -h /var | tail -1
  press_enter
}

idx_fix_yellow() {
  cat <<EOF

  ${BOLD}═══ Fix cluster yellow (number_of_replicas=0 single-node) ═══${NC}

  Su cluster single-node, le repliche non possono essere allocate
  (servirebbe un secondo nodo). Imposta number_of_replicas=0 su tutti
  gli indici per portare il cluster da yellow a green.

EOF
  ask_yesno "Procedere?" "Y" || { press_enter; return; }
  idx_curl -X PUT "$IDX_HOST/_all/_settings" \
    -H 'Content-Type: application/json' \
    -d '{"index": {"number_of_replicas": 0}}' 2>&1 | head -2
  sleep 2
  echo
  echo "Cluster health dopo:"
  idx_curl "$IDX_HOST/_cluster/health?pretty" 2>&1 | head -6
  press_enter
}

# ========================================================================
# MAIN
# ========================================================================
check_root
[[ -f "$CONFIG_FILE" ]] || { log_error "Config non presente: $CONFIG_FILE — lancia prima scripts/install-wizard.sh"; exit 1; }
mkdir -p "$EXPORT_DIR"
main_menu
