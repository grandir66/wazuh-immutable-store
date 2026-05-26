#!/bin/bash
#
# Wazuh Immutable Store — Server Hardening Script
#
# Applica un set strutturato di hardening (Layer 1 + Layer 2) al server
# che ospita Wazuh manager. Idempotente, con backup automatico dei file
# modificati e prompt di conferma per ogni step.
#
# Uso:
#   sudo bash scripts/harden-wazuh.sh                # interattivo
#   sudo bash scripts/harden-wazuh.sh --auto         # senza prompt (YES a tutto)
#   sudo bash scripts/harden-wazuh.sh --dry-run      # mostra cosa farebbe
#   sudo bash scripts/harden-wazuh.sh --only LAYER   # solo "layer1" o "layer2"
#   sudo bash scripts/harden-wazuh.sh --skip ABCDEF  # salta gli step elencati
#
# Layer 1 (Quick wins, ~1 ora, blocca 80% degli attacchi opportunistici):
#   A) UFW firewall con allowlist Wazuh
#   B) SSH hardening (sshd_config.d/99-harden.conf)
#   C) unattended-upgrades per security patches
#   D) fail2ban per SSH
#   E) NTP sync (chrony)
#
# Layer 2 (Hardening standard, ~mezza giornata):
#   F) Kernel hardening via sysctl
#   G) Mount options noexec/nosuid su /tmp, /dev/shm
#   H) auditd con regole CIS + watch su GPG key / Wazuh config
#   I) AIDE file integrity monitoring
#   J) Wazuh agent self-monitoring (FIM su /root/.gnupg, /etc/wazuh-immutable-store)
#   K) Disable servizi inutili
#   L) PAM lockout policy
#
# Pre-check critici prima di applicare:
#   - Almeno una chiave SSH pubblica autorizzata per l'utente sudo non-root
#   - Versione OS riconosciuta (Ubuntu 22.04+ / Debian 12+ / RHEL 8+)
#   - Wazuh manager presente in /var/ossec
#
# Backup: ogni file modificato viene copiato con suffix .pre-harden-YYYYMMDD-HHMMSS
# Rollback: dopo modifiche critiche (sshd, fstab, sysctl), test funzionale
#           prima di considerare lo step completato.
#
set -uo pipefail

# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ------------------------------------------------------------------
# Globals
# ------------------------------------------------------------------
AUTO="no"
DRY_RUN="no"
ONLY=""
SKIP=""
STAMP=$(date +%Y%m%d-%H%M%S)
SSH_USER_DEFAULT="dts"
LAN_NETWORK_DEFAULT="172.16.0.0/16"
DA_IPAM_IP=""
APPLIED=()
SKIPPED=()
FAILED=()

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo; echo -e "${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
log_dry()   { echo -e "${DIM}[DRY-RUN] $*${NC}"; }

ask_yesno() {
  local prompt="$1" default="${2:-Y}" var
  if [[ "$AUTO" == "yes" ]]; then
    [[ "$default" =~ ^[YySs] ]] && return 0 || return 1
  fi
  if [[ "$default" =~ ^[Yy] ]]; then
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [Y/n]: ")" var
    var="${var:-Y}"
  else
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [y/N]: ")" var
    var="${var:-N}"
  fi
  case "$var" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

ask_input() {
  local prompt="$1" default="${2:-}" var
  if [[ "$AUTO" == "yes" ]]; then echo "$default"; return; fi
  if [[ -n "$default" ]]; then
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC} [${default}]: ")" var
    echo "${var:-$default}"
  else
    read -r -p "$(echo -e "${BOLD}? ${prompt}${NC}: ")" var
    echo "$var"
  fi
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "cp $f ${f}.pre-harden-$STAMP"
    return
  fi
  cp "$f" "${f}.pre-harden-$STAMP"
  log_info "Backup: $f → ${f}.pre-harden-$STAMP"
}

run_or_dry() {
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "$*"
    return 0
  fi
  eval "$@"
}

# ------------------------------------------------------------------
# CLI args
# ------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --auto) AUTO="yes"; shift ;;
      --dry-run) DRY_RUN="yes"; shift ;;
      --only) ONLY="$2"; shift 2 ;;
      --skip) SKIP="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Opzione sconosciuta: $1"; usage; exit 1 ;;
    esac
  done
}

usage() {
  cat <<USAGE
Wazuh Server Hardening Script

Uso:
  sudo bash $0                       # interattivo (default)
  sudo bash $0 --auto                # non-interattivo, YES a tutto
  sudo bash $0 --dry-run             # mostra cosa farebbe, non applica
  sudo bash $0 --only layer1         # applica solo Layer 1 (A-E)
  sudo bash $0 --only layer2         # applica solo Layer 2 (F-L)
  sudo bash $0 --skip BD             # salta gli step B e D

Step disponibili:
  Layer 1 — A (UFW), B (SSH), C (unattended), D (fail2ban), E (NTP)
  Layer 2 — F (sysctl), G (mount), H (auditd), I (AIDE), J (FIM Wazuh),
            K (disable services), L (PAM lockout)
USAGE
}

should_run() {
  local letter="$1" layer="$2"
  [[ "$SKIP" == *"$letter"* ]] && return 1
  if [[ -n "$ONLY" ]]; then
    case "$ONLY" in
      layer1) [[ "$layer" == "1" ]] || return 1 ;;
      layer2) [[ "$layer" == "2" ]] || return 1 ;;
      *) return 0 ;;
    esac
  fi
  return 0
}

# ------------------------------------------------------------------
# Pre-flight checks
# ------------------------------------------------------------------
preflight() {
  log_step "Pre-flight checks"

  # Root
  if [[ $EUID -ne 0 ]]; then
    log_error "Eseguire come root (sudo $0)"
    exit 1
  fi
  log_ok "Esecuzione come root"

  # OS detection
  if [[ ! -f /etc/os-release ]]; then
    log_error "OS non riconosciuto"
    exit 1
  fi
  . /etc/os-release
  log_info "OS rilevato: ${PRETTY_NAME:-$ID $VERSION_ID}"
  case "$ID" in
    ubuntu|debian) ;;
    *) log_warn "Distribuzione $ID non testata, proseguo a rischio dell'utente" ;;
  esac

  # Wazuh manager presente
  if [[ ! -d /var/ossec ]]; then
    log_warn "Wazuh manager non rilevato in /var/ossec — alcuni step potrebbero non applicarsi"
    ask_yesno "Continuare comunque?" "N" || exit 1
  else
    log_ok "Wazuh manager rilevato"
  fi

  # Chiave SSH per utente non-root (per evitare lockout dopo SSH harden)
  SSH_USER=$(ask_input "Utente SSH non-root con accesso" "$SSH_USER_DEFAULT")
  if [[ ! -d "/home/$SSH_USER/.ssh" ]] || [[ ! -f "/home/$SSH_USER/.ssh/authorized_keys" ]]; then
    log_error "Utente $SSH_USER non ha ~/.ssh/authorized_keys"
    log_error "Lo step B (SSH harden) disabiliterà PasswordAuthentication → rischio LOCKOUT"
    ask_yesno "Procedere comunque (a tuo rischio)?" "N" || exit 1
  else
    local key_count
    key_count=$(grep -c "^ssh-" "/home/$SSH_USER/.ssh/authorized_keys" 2>/dev/null || echo 0)
    if [[ $key_count -lt 1 ]]; then
      log_error "Nessuna chiave pubblica trovata in /home/$SSH_USER/.ssh/authorized_keys"
      exit 1
    fi
    log_ok "Utente $SSH_USER ha $key_count chiave/i SSH autorizzate"
  fi

  # LAN network (per UFW rules)
  LAN_NETWORK=$(ask_input "Subnet LAN per allowlist firewall (CIDR)" "$LAN_NETWORK_DEFAULT")

  # IP DA-IPAM cliente (per allowlist API/indexer)
  DA_IPAM_IP=$(ask_input "IP del DA-IPAM cliente (vuoto per non aprire 55000/9200)" "")

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_warn "MODALITÀ DRY-RUN: nessuna modifica reale verrà applicata"
  fi
  if [[ "$AUTO" == "yes" ]]; then
    log_warn "MODALITÀ AUTO: nessun prompt, YES su tutto"
  fi
}

# ==================================================================
# LAYER 1
# ==================================================================

step_a_ufw() {
  should_run "A" "1" || { SKIPPED+=("A"); return; }
  log_step "A) UFW firewall"

  if ! command -v ufw >/dev/null 2>&1; then
    log_info "Installo ufw..."
    run_or_dry "apt-get install -y ufw" || { FAILED+=("A"); return; }
  fi

  local status
  status=$(ufw status 2>/dev/null | head -1)
  log_info "Stato attuale UFW: $status"

  if [[ "$status" == *"active"* ]]; then
    log_warn "UFW già attivo. Vuoi ridefinire le regole?"
    ask_yesno "Procedere con riconfig?" "N" || { SKIPPED+=("A"); return; }
  else
    log_warn "Sto per abilitare UFW con regole strette. Se applichi via SSH e le regole sono sbagliate, perdi accesso!"
    ask_yesno "Procedere?" "Y" || { SKIPPED+=("A"); return; }
  fi

  run_or_dry "ufw --force reset"
  run_or_dry "ufw default deny incoming"
  run_or_dry "ufw default allow outgoing"
  run_or_dry "ufw allow from $LAN_NETWORK to any port 22 proto tcp comment 'SSH LAN'"
  run_or_dry "ufw allow from $LAN_NETWORK to any port 1514 comment 'Wazuh agent events'"
  run_or_dry "ufw allow from $LAN_NETWORK to any port 1515 proto tcp comment 'Wazuh enrollment'"
  run_or_dry "ufw allow from $LAN_NETWORK to any port 443 proto tcp comment 'Dashboard'"
  if [[ -n "$DA_IPAM_IP" ]]; then
    run_or_dry "ufw allow from $DA_IPAM_IP to any port 55000 proto tcp comment 'API solo da DA-IPAM'"
    run_or_dry "ufw allow from $DA_IPAM_IP to any port 9200 proto tcp comment 'Indexer solo da DA-IPAM'"
  fi
  run_or_dry "ufw --force enable"

  log_ok "UFW configurato"
  if [[ "$DRY_RUN" != "yes" ]]; then ufw status verbose | sed 's/^/    /'; fi
  APPLIED+=("A")
}

step_b_ssh() {
  should_run "B" "1" || { SKIPPED+=("B"); return; }
  log_step "B) SSH hardening"

  local conf="/etc/ssh/sshd_config.d/99-harden.conf"
  if [[ -f "$conf" ]]; then
    log_warn "Config harden SSH già presente: $conf"
    ask_yesno "Sovrascrivere?" "N" || { SKIPPED+=("B"); return; }
  fi

  log_warn "Sto per disabilitare PasswordAuthentication, root login, e tightening generale di SSH."
  log_warn "Utente abilitato: $SSH_USER (verificato presenza chiave pubblica nel preflight)"
  ask_yesno "Procedere?" "Y" || { SKIPPED+=("B"); return; }

  backup_file "/etc/ssh/sshd_config"
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "scrittura $conf"
  else
    cat > "$conf" <<EOF
# Hardening generato da harden-wazuh.sh il $STAMP
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $SSH_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PrintMotd no
Banner /etc/ssh/banner
EOF
    cat > /etc/ssh/banner <<EOF
*****************************************************************
ATTENZIONE: accesso autorizzato esclusivamente a personale Domarc.
Ogni attivita' viene tracciata e analizzata.
Accessi non autorizzati saranno perseguiti a termini di legge.
*****************************************************************
EOF
  fi

  log_info "Test sshd_config..."
  if [[ "$DRY_RUN" != "yes" ]] && ! sshd -t 2>&1; then
    log_error "sshd_config NON valido — rollback config"
    rm -f "$conf"
    FAILED+=("B")
    return
  fi

  log_info "Restart sshd (la TUA sessione attuale resta attiva)..."
  run_or_dry "systemctl restart ssh"

  log_ok "SSH hardening applicato"
  log_warn "Apri una NUOVA sessione SSH PRIMA di chiudere questa, per verificare che la chiave funzioni!"
  APPLIED+=("B")
}

step_c_unattended() {
  should_run "C" "1" || { SKIPPED+=("C"); return; }
  log_step "C) Unattended-upgrades (security patches)"

  if dpkg -l | grep -q "^ii  unattended-upgrades"; then
    log_info "unattended-upgrades già installato"
  else
    run_or_dry "apt-get install -y unattended-upgrades apt-listchanges" || { FAILED+=("C"); return; }
  fi

  if [[ "$DRY_RUN" != "yes" ]]; then
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  fi

  # Verifica che Wazuh stack non sia in scope (non upgrade automatici)
  if ! apt-mark showhold | grep -q wazuh; then
    log_warn "wazuh-{manager,indexer,dashboard,filebeat} non sono in 'hold' — rischio upgrade rotti"
    ask_yesno "Eseguire apt-mark hold ora?" "Y" && \
      run_or_dry "apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true"
  else
    log_ok "Pacchetti Wazuh sono in apt-mark hold (no upgrade automatici)"
  fi

  log_ok "Unattended-upgrades configurati per security patches"
  APPLIED+=("C")
}

step_d_fail2ban() {
  should_run "D" "1" || { SKIPPED+=("D"); return; }
  log_step "D) fail2ban per SSH"

  if ! command -v fail2ban-client >/dev/null 2>&1; then
    run_or_dry "apt-get install -y fail2ban" || { FAILED+=("D"); return; }
  fi

  if [[ "$DRY_RUN" != "yes" ]]; then
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
banaction = ufw

[sshd]
enabled = true
mode = aggressive
EOF
  fi
  run_or_dry "systemctl enable --now fail2ban"

  log_ok "fail2ban configurato (3 tentativi/10min → ban 1h via UFW)"
  APPLIED+=("D")
}

step_e_ntp() {
  should_run "E" "1" || { SKIPPED+=("E"); return; }
  log_step "E) NTP sync (chrony)"

  if ! command -v chronyc >/dev/null 2>&1; then
    run_or_dry "apt-get install -y chrony" || { FAILED+=("E"); return; }
  fi
  run_or_dry "systemctl enable --now chrony"

  if [[ "$DRY_RUN" != "yes" ]]; then
    sleep 3
    log_info "Stato sync:"
    chronyc tracking 2>&1 | head -8 | sed 's/^/    /'
  fi
  log_ok "Chrony attivo (timestamp affidabili per chain integrity)"
  APPLIED+=("E")
}

# ==================================================================
# LAYER 2
# ==================================================================

step_f_sysctl() {
  should_run "F" "2" || { SKIPPED+=("F"); return; }
  log_step "F) Kernel hardening (sysctl)"

  local conf="/etc/sysctl.d/99-wazuh-hardening.conf"
  if [[ -f "$conf" ]]; then
    log_warn "Config sysctl harden già presente"
    ask_yesno "Sovrascrivere?" "N" || { SKIPPED+=("F"); return; }
  fi

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "scrittura $conf con regole kernel hardening"
  else
    cat > "$conf" <<EOF
# Wazuh server kernel hardening — generato da harden-wazuh.sh il $STAMP
# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# Network
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_timestamps = 0
EOF
    if ! sysctl --system >/tmp/sysctl-output.log 2>&1; then
      log_error "Errore applicando sysctl, vedi /tmp/sysctl-output.log"
      mv "$conf" "${conf}.failed"
      FAILED+=("F")
      return
    fi
  fi
  log_ok "Sysctl kernel hardening applicato"
  APPLIED+=("F")
}

step_g_mount() {
  should_run "G" "2" || { SKIPPED+=("G"); return; }
  log_step "G) Mount options /tmp /dev/shm (noexec,nosuid,nodev)"

  log_warn "ATTENZIONE: wazuh-immutable-store usa /tmp/wazuh-archive come temp dir!"
  log_warn "Se applichi noexec su /tmp, devi cambiare 'temp_dir' in config.yaml a /var/tmp/wazuh-archive"
  ask_yesno "Procedere comunque (e ricordare di modificare config.yaml)?" "N" || { SKIPPED+=("G"); return; }

  backup_file "/etc/fstab"
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "modifica /etc/fstab per /tmp e /dev/shm"
  else
    if ! grep -q "^tmpfs.*/tmp" /etc/fstab; then
      echo "tmpfs   /tmp        tmpfs   defaults,noexec,nosuid,nodev,size=2G   0 0" >> /etc/fstab
      log_info "Aggiunta riga /tmp in fstab"
    fi
    if ! grep -q "^tmpfs.*/dev/shm" /etc/fstab; then
      echo "tmpfs   /dev/shm    tmpfs   defaults,noexec,nosuid,nodev,size=512M 0 0" >> /etc/fstab
      log_info "Aggiunta riga /dev/shm in fstab"
    fi
    log_warn "Modifiche applicabili solo dopo REBOOT (oppure umount/mount manuale)"

    # Aggiorna config wazuh-immutable-store
    if [[ -f /etc/wazuh-immutable-store/config.yaml ]]; then
      if grep -q "/tmp/wazuh-archive" /etc/wazuh-immutable-store/config.yaml; then
        backup_file "/etc/wazuh-immutable-store/config.yaml"
        sed -i 's|/tmp/wazuh-archive|/var/tmp/wazuh-archive|' /etc/wazuh-immutable-store/config.yaml
        mkdir -p /var/tmp/wazuh-archive
        log_ok "config.yaml aggiornato: temp_dir → /var/tmp/wazuh-archive"
      fi
    fi
  fi
  log_ok "Mount options fstab aggiornati (effettive al reboot)"
  APPLIED+=("G")
}

step_h_auditd() {
  should_run "H" "2" || { SKIPPED+=("H"); return; }
  log_step "H) auditd con watch su materiali sensibili"

  if ! command -v auditd >/dev/null 2>&1; then
    run_or_dry "apt-get install -y auditd" || { FAILED+=("H"); return; }
  fi

  local rules="/etc/audit/rules.d/99-wazuh-watch.rules"
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "scrittura $rules con regole CIS-like"
  else
    cat > "$rules" <<EOF
# Wazuh server audit rules — generato da harden-wazuh.sh il $STAMP

# GPG key (compromise = compromise totale della chain)
-w /root/.gnupg/ -p rwxa -k gpg_key_access
-w /etc/wazuh-immutable-store/ -p rwxa -k wis_config

# Wazuh manager config + agent keys
-w /var/ossec/etc/ossec.conf -p wa -k wazuh_config
-w /var/ossec/etc/client.keys -p wa -k wazuh_agent_keys
-w /var/ossec/etc/local_internal_options.conf -p wa -k wazuh_internal

# Sudo + privilege escalation
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Cron / scheduled tasks
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Systemd units (per evitare backdoor via servizi)
-w /etc/systemd/system/ -p wa -k systemd

# Lock immutabile audit config (rimuoverlo richiede reboot)
-e 2
EOF
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
  fi
  log_ok "auditd configurato (verifica con: sudo ausearch -k gpg_key_access)"
  APPLIED+=("H")
}

step_i_aide() {
  should_run "I" "2" || { SKIPPED+=("I"); return; }
  log_step "I) AIDE — file integrity monitoring"

  if ! command -v aide >/dev/null 2>&1; then
    run_or_dry "apt-get install -y aide" || { FAILED+=("I"); return; }
  fi

  log_warn "AIDE init richiede 15-30 minuti per il primo baseline. Vuoi avviarlo in background?"
  ask_yesno "Avvia AIDE init in background?" "Y" || { SKIPPED+=("I"); return; }

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "aideinit (background) + setup cron daily check"
  else
    nohup bash -c '
      aideinit 2>&1
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
      echo "AIDE baseline complete: $(date -Iseconds)" >> /var/log/aide-init.log
    ' >/dev/null 2>&1 &
    log_info "aideinit lanciato in background (PID $!) — vedi log: /var/log/aide-init.log"

    # Crontab giornaliera
    cat > /etc/cron.d/aide <<EOF
# AIDE daily integrity check
0 4 * * * root /usr/bin/aide --check > /var/log/aide.log 2>&1
EOF
  fi
  log_ok "AIDE init in corso + cron giornaliero schedulato (04:00)"
  APPLIED+=("I")
}

step_j_wazuh_fim() {
  should_run "J" "2" || { SKIPPED+=("J"); return; }
  log_step "J) Wazuh agent self-monitoring (FIM su /root/.gnupg, config)"

  if [[ ! -f /var/ossec/etc/ossec.conf ]]; then
    log_warn "Wazuh manager non rilevato, skip"
    SKIPPED+=("J"); return
  fi

  if grep -q "/root/.gnupg" /var/ossec/etc/ossec.conf; then
    log_info "FIM già configurato su /root/.gnupg"
  else
    log_warn "Aggiungo direttive FIM per /root/.gnupg, /etc/wazuh-immutable-store, /etc/ssh, /etc/sudoers.d"
    ask_yesno "Procedere?" "Y" || { SKIPPED+=("J"); return; }

    backup_file "/var/ossec/etc/ossec.conf"
    if [[ "$DRY_RUN" == "yes" ]]; then
      log_dry "patch ossec.conf con direttive FIM"
    else
      # Inserisce direttive prima di </syscheck>
      sed -i '/<\/syscheck>/i\
    <!-- Wazuh server self-monitoring (added by harden-wazuh.sh) -->\
    <directories check_all="yes" realtime="yes">/root/.gnupg,/etc/wazuh-immutable-store,/etc/ssh,/etc/sudoers.d</directories>\
    <directories check_all="yes">/usr/local/bin,/opt/wazuh-immutable-store,/etc/systemd/system</directories>' \
        /var/ossec/etc/ossec.conf
      systemctl restart wazuh-manager
    fi
  fi
  log_ok "FIM self-monitoring configurato"
  APPLIED+=("J")
}

step_k_disable_services() {
  should_run "K" "2" || { SKIPPED+=("K"); return; }
  log_step "K) Disable servizi inutili"

  local services_to_check=(snapd apport ModemManager bluetooth cups avahi-daemon)
  local to_disable=()

  for svc in "${services_to_check[@]}"; do
    if systemctl is-enabled "$svc" 2>/dev/null | grep -q enabled; then
      to_disable+=("$svc")
    fi
  done

  if [[ ${#to_disable[@]} -eq 0 ]]; then
    log_ok "Nessun servizio inutile attivo"
    APPLIED+=("K"); return
  fi

  log_warn "Servizi che propongo di disabilitare: ${to_disable[*]}"
  ask_yesno "Disabilitare tutti?" "Y" || { SKIPPED+=("K"); return; }

  for svc in "${to_disable[@]}"; do
    run_or_dry "systemctl disable --now $svc"
    log_info "Disabilitato: $svc"
  done
  log_ok "Servizi inutili disabilitati"
  APPLIED+=("K")
}

step_l_pam_lockout() {
  should_run "L" "2" || { SKIPPED+=("L"); return; }
  log_step "L) PAM lockout policy (5 falliti → 15 min lock)"

  local pamfile="/etc/pam.d/common-auth"
  [[ -f "$pamfile" ]] || pamfile="/etc/pam.d/system-auth"
  [[ -f "$pamfile" ]] || { log_warn "File PAM non trovato"; SKIPPED+=("L"); return; }

  if grep -q "pam_faillock.so" "$pamfile"; then
    log_info "pam_faillock già configurato"
    APPLIED+=("L"); return
  fi

  log_warn "Aggiungo pam_faillock a $pamfile"
  ask_yesno "Procedere?" "Y" || { SKIPPED+=("L"); return; }

  backup_file "$pamfile"
  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "patch PAM per faillock"
  else
    # Inserisce in cima al file (prima della prima auth line)
    sed -i '0,/^auth/{s|^auth|auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900\nauth|}' "$pamfile"
    # Aggiunge anche in fondo
    if ! grep -q "pam_faillock.so authsucc" "$pamfile"; then
      echo "auth    sufficient    pam_faillock.so authsucc" >> "$pamfile"
    fi
  fi
  log_ok "PAM lockout policy applicata"
  APPLIED+=("L")
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
final_summary() {
  log_step "Summary"

  cat <<EOF

  ${BOLD}Step applicati con successo:${NC}     ${GREEN}${APPLIED[*]:-nessuno}${NC}
  ${BOLD}Step skippati:${NC}                   ${YELLOW}${SKIPPED[*]:-nessuno}${NC}
  ${BOLD}Step falliti:${NC}                    ${RED}${FAILED[*]:-nessuno}${NC}

EOF

  cat <<EOF
  ${BOLD}Backup file modificati:${NC}
EOF
  find / -name "*.pre-harden-$STAMP" 2>/dev/null | head -15 | sed 's/^/    /'

  cat <<EOF

  ${BOLD}${YELLOW}TODO post-hardening:${NC}
    1. Apri una NUOVA sessione SSH per verificare che la chiave funzioni
       (NON chiudere questa sessione finché non hai la conferma)
    2. Reboot pianificato per applicare le modifiche fstab (step G se applicato)
    3. AIDE init in background (step I): verifica completamento in /var/log/aide-init.log
    4. Test funzionali:
       sudo wazuh-immutable-store status
       sudo wazuh-rolling-verify
       sudo ufw status verbose
       sudo systemctl status fail2ban auditd chrony
    5. Salva i file .pre-harden-* in posto sicuro (sono i backup per rollback)

  ${BOLD}Per audit/compliance:${NC}
    Documento: docs/HARDENING.md descrive ogni step + verifica indipendente

EOF

  if [[ ${#FAILED[@]} -gt 0 ]]; then
    log_error "Alcuni step sono falliti. Rivedi gli errori prima di considerare il sistema hardened."
    exit 2
  fi
}

# ==================================================================
# MAIN
# ==================================================================
main() {
  parse_args "$@"
  preflight

  # Layer 1
  step_a_ufw
  step_b_ssh
  step_c_unattended
  step_d_fail2ban
  step_e_ntp

  # Layer 2
  step_f_sysctl
  step_g_mount
  step_h_auditd
  step_i_aide
  step_j_wazuh_fim
  step_k_disable_services
  step_l_pam_lockout

  final_summary
}

main "$@"
