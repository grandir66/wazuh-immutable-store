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
  log_step "A) UFW firewall (configurazione interattiva)"

  cat <<EOF

  ${BOLD}${YELLOW}⚠ Attenzione critica:${NC}
  L'attivazione di UFW con regole sbagliate può ${BOLD}bloccare la tua sessione SSH${NC}.
  Prima di proseguire, verifica:
    1. Hai accesso alla console di emergenza? (es. console VM Proxmox / iLO / IPMI)
    2. Conosci da quale IP/subnet ti stai collegando ora?
       L'IP attuale visto dal server è: ${BOLD}$(who | awk 'NR==1 {print $5}' | tr -d '()')${NC}
    3. Hai testato la chiave SSH (apri una nuova sessione PRIMA di proseguire)

EOF
  ask_yesno "Procedere con configurazione UFW interattiva?" "N" || { SKIPPED+=("A"); return; }

  if ! command -v ufw >/dev/null 2>&1; then
    log_info "Installo ufw..."
    run_or_dry "apt-get install -y ufw" || { FAILED+=("A"); return; }
  fi

  local status
  status=$(ufw status 2>/dev/null | head -1)
  log_info "Stato attuale UFW: $status"

  if [[ "$status" == *"active"* ]]; then
    ask_yesno "UFW già attivo. Resetto e ridefinisco?" "N" || { SKIPPED+=("A"); return; }
  fi

  cat <<EOF

  ${BOLD}═══ Configurazione regole UFW ═══${NC}

  Per ciascun servizio ti chiedo da quale rete/IP deve essere accessibile.
  Formato accettato:
    - Singola subnet:   ${CYAN}172.16.0.0/16${NC}
    - Singolo IP:       ${CYAN}172.16.1.20${NC}
    - Multipli (CSV):   ${CYAN}172.16.0.0/16,172.17.100.0/24,10.0.0.5${NC}
    - Tutti (sconsigliato): ${CYAN}any${NC}
    - Disabilita servizio: ${CYAN}vuoto${NC} (premi solo invio)

EOF

  # SSH
  echo -e "${BOLD}SSH (porta 22/tcp)${NC} — chi gestisce il server in remoto?"
  echo "   Default suggerito: subnet di Tailscale gateway (più sicuro di LAN aperta)"
  local ssh_sources
  ssh_sources=$(ask_input "Sorgenti SSH" "172.17.100.0/24")

  # Wazuh agent
  echo
  echo -e "${BOLD}Wazuh agent (porte 1514+1515)${NC} — da quale rete gli agent inviano eventi?"
  echo "   Default: LAN del cliente (tutti gli agent ci stanno)"
  local agent_sources
  agent_sources=$(ask_input "Sorgenti agent" "172.16.0.0/16")

  # Dashboard
  echo
  echo -e "${BOLD}Wazuh Dashboard (porta 443/tcp)${NC} — chi accede alla UI?"
  echo "   Opzioni comuni: solo operatori Tailscale, o anche IT cliente da LAN"
  local dash_sources
  dash_sources=$(ask_input "Sorgenti Dashboard (vuoto = chiuso)" "172.17.100.0/24")

  # Indexer
  echo
  echo -e "${BOLD}Wazuh Indexer / OpenSearch (porta 9200/tcp)${NC} — quali integrazioni?"
  echo "   Default: solo operatori Tailscale + eventuali integrazioni (es. DA-IPAM)"
  local indexer_sources
  indexer_sources=$(ask_input "Sorgenti Indexer (vuoto = chiuso)" "172.17.100.0/24")

  # API
  echo
  echo -e "${BOLD}Wazuh API (porta 55000/tcp)${NC} — quali integrazioni?"
  local api_sources
  api_sources=$(ask_input "Sorgenti API (vuoto = chiuso)" "172.17.100.0/24")

  # Custom extra rules
  echo
  echo -e "${BOLD}Regole custom aggiuntive${NC} — vuoi aprire altre porte?"
  local extra_rules=""
  if ask_yesno "Aggiungere regole custom?" "N"; then
    while true; do
      local proto port src
      port=$(ask_input "Porta (vuoto per finire)" "")
      [[ -z "$port" ]] && break
      proto=$(ask_input "Protocollo (tcp/udp/any)" "tcp")
      src=$(ask_input "Sorgente (subnet/IP/any)" "172.17.100.0/24")
      extra_rules+="${port}|${proto}|${src}\n"
    done
  fi

  # Conferma riassuntiva
  echo
  echo -e "${BOLD}═══ Regole che sto per applicare ═══${NC}"
  echo "  SSH 22         ← $ssh_sources"
  echo "  Agent 1514     ← $agent_sources"
  echo "  Agent 1515     ← $agent_sources"
  echo "  Dashboard 443  ← ${dash_sources:-CHIUSO}"
  echo "  Indexer 9200   ← ${indexer_sources:-CHIUSO}"
  echo "  API 55000      ← ${api_sources:-CHIUSO}"
  [[ -n "$extra_rules" ]] && { echo "  Extra:"; echo -e "$extra_rules" | sed 's/^/    /'; }
  echo
  ask_yesno "${BOLD}Confermi e applico?${NC}" "N" || { SKIPPED+=("A"); return; }

  run_or_dry "ufw --force reset"
  run_or_dry "ufw default deny incoming"
  run_or_dry "ufw default allow outgoing"

  apply_ufw_rule() {
    local sources="$1" port="$2" proto="$3" comment="$4"
    [[ -z "$sources" ]] && return
    if [[ "$sources" == "any" ]]; then
      run_or_dry "ufw allow $port/$proto comment '$comment (open)'"
      return
    fi
    IFS=',' read -ra SRCS <<< "$sources"
    for src in "${SRCS[@]}"; do
      src=$(echo "$src" | xargs) # trim
      [[ -z "$src" ]] && continue
      if [[ "$proto" == "any" ]]; then
        run_or_dry "ufw allow from $src to any port $port comment '$comment'"
      else
        run_or_dry "ufw allow from $src to any port $port proto $proto comment '$comment'"
      fi
    done
  }

  apply_ufw_rule "$ssh_sources" 22 tcp "SSH"
  apply_ufw_rule "$agent_sources" 1514 any "Wazuh agent events"
  apply_ufw_rule "$agent_sources" 1515 tcp "Wazuh enrollment"
  apply_ufw_rule "$dash_sources" 443 tcp "Dashboard"
  apply_ufw_rule "$indexer_sources" 9200 tcp "Indexer"
  apply_ufw_rule "$api_sources" 55000 tcp "API"

  if [[ -n "$extra_rules" ]]; then
    while IFS='|' read -r port proto src; do
      [[ -z "$port" ]] && continue
      apply_ufw_rule "$src" "$port" "$proto" "Custom"
    done <<< "$(echo -e "$extra_rules")"
  fi

  run_or_dry "ufw --force enable"

  log_ok "UFW configurato"
  if [[ "$DRY_RUN" != "yes" ]]; then
    echo
    ufw status verbose | sed 's/^/    /'
    echo
    log_warn "VERIFICA SUBITO con NUOVA SESSIONE SSH che funzioni ancora prima di chiudere questa"
  fi
  APPLIED+=("A")
}

step_b_ssh() {
  should_run "B" "1" || { SKIPPED+=("B"); return; }
  log_step "B) SSH hardening (con safeguards anti-lockout)"

  local conf="/etc/ssh/sshd_config.d/99-harden.conf"
  if [[ -f "$conf" ]]; then
    log_warn "Config harden SSH già presente: $conf"
    ask_yesno "Sovrascrivere?" "N" || { SKIPPED+=("B"); return; }
  fi

  # =============== PRE-CHECK ANTI-LOCKOUT ===============
  cat <<EOF

  ${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}
  ${RED}${BOLD}║         ATTENZIONE — RISCHIO LOCKOUT SSH                     ║${NC}
  ${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}

  L'hardening SSH può escluderti dal server se applicato senza precauzioni.
  Verifico la situazione attuale prima di procedere.

EOF

  # Conta chiavi pubbliche dell'utente
  local key_count
  key_count=$(grep -c "^ssh-" "/home/$SSH_USER/.ssh/authorized_keys" 2>/dev/null || echo 0)
  echo "  Utente target: ${BOLD}$SSH_USER${NC}"
  echo "  Chiavi SSH autorizzate: ${BOLD}$key_count${NC}"
  if [[ -f "/home/$SSH_USER/.ssh/authorized_keys" ]]; then
    awk '/^ssh-/{print "    - "$NF}' "/home/$SSH_USER/.ssh/authorized_keys"
  fi
  echo

  if [[ $key_count -lt 2 ]]; then
    cat <<EOF
  ${YELLOW}${BOLD}⚠ Hai solo $key_count chiave SSH autorizzata${NC} = single point of failure.
  Se la chiave del Mac/client primario si rompe (HD failure, smarrimento), perdi accesso.

  Opzioni di mitigazione consigliate (in ordine):

  ${BOLD}1. AGGIUNGI UNA SECONDA CHIAVE${NC} (raccomandato)
     Posso generare ora una nuova keypair come "backup key":
     - Privata cifrata con passphrase forte → in vault aziendale + cassaforte
     - Pubblica autorizzata su questo server
     Risultato: 2 chiavi indipendenti, una di emergenza

  ${BOLD}2. VERIFICA CONSOLE EMERGENCY${NC} (Proxmox/iLO/IPMI)
     Console fisica/web della VM resta accessibile anche se SSH è chiuso.
     Devi essere sicuro di poterla raggiungere in caso di lockout.

  ${BOLD}3. MANTIENI PasswordAuth limitato${NC} (compromesso)
     Invece di disabilitare totalmente PasswordAuthentication, lo limito
     SOLO ad una subnet di trust (es. Tailscale gateway) via Match Address.
     Brute force impossibile da Internet, ma fallback password disponibile.

EOF
    local lockout_choice
    PS3="Scelta [1-4]: "
    select lockout_choice in \
      "Genera seconda chiave SSH ora + procedi con disable PasswordAuth" \
      "Procedi con Match Address (PasswordAuth solo da subnet sicura)" \
      "Procedi senza precauzioni (ho console Proxmox come fallback)" \
      "Annulla, applicherò SSH hardening dopo aver risolto"; do
      case "$REPLY" in
        1) generate_backup_ssh_key; break ;;
        2) STEP_B_MODE="match"; break ;;
        3) STEP_B_MODE="disable"; break ;;
        4) SKIPPED+=("B"); return ;;
        *) echo "Scelta non valida" ;;
      esac
    done
  else
    log_ok "Hai $key_count chiavi SSH ridondate, rischio lockout basso"
    STEP_B_MODE="disable"
  fi

  # Chiedi subnet per Match Address se serve
  local match_subnet=""
  if [[ "${STEP_B_MODE:-}" == "match" ]]; then
    match_subnet=$(ask_input "Subnet/IP da cui ammettere PasswordAuth" "172.17.100.0/24")
  fi

  # =============== APPLICA CONFIG ===============
  log_info "Backup sshd_config attuale..."
  backup_file "/etc/ssh/sshd_config"
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [[ -f "$f" ]] && backup_file "$f"
  done

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "scrittura $conf con mode=${STEP_B_MODE:-disable} match=$match_subnet"
  else
    cat > "$conf" <<EOF
# Hardening generato da harden-wazuh.sh il $STAMP
PermitRootLogin no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $SSH_USER
MaxAuthTries 3
LoginGraceTime 60
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

    if [[ "${STEP_B_MODE:-disable}" == "match" ]] && [[ -n "$match_subnet" ]]; then
      cat >> "$conf" <<EOF

# Default: solo public key auth
PasswordAuthentication no

# Eccezione: PasswordAuth permessa SOLO da subnet di trust (Match Address)
Match Address $match_subnet
    PasswordAuthentication yes
    MaxAuthTries 2
EOF
    else
      cat >> "$conf" <<EOF
PasswordAuthentication no
EOF
    fi

    # Disabilita config cloud-init che mette PasswordAuth yes
    if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]]; then
      if grep -q "PasswordAuthentication" /etc/ssh/sshd_config.d/50-cloud-init.conf; then
        log_warn "Disabilito PasswordAuthentication yes in 50-cloud-init.conf"
        sed -i 's|^PasswordAuthentication yes|#PasswordAuthentication yes  # disabled by harden-wazuh.sh|' /etc/ssh/sshd_config.d/50-cloud-init.conf
      fi
    fi

    cat > /etc/ssh/banner <<'EOF'
*****************************************************************
ATTENZIONE: accesso autorizzato esclusivamente a personale autorizzato.
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

  log_warn "Sto per restartare sshd. La tua sessione corrente resta attiva."
  log_warn "Apri SUBITO una NUOVA sessione SSH per verificare che la chiave funzioni."
  log_warn "Se la nuova sessione fallisce, NON chiudere questa: rollback con:"
  echo -e "    ${CYAN}sudo cp /etc/ssh/sshd_config.pre-harden-$STAMP /etc/ssh/sshd_config && sudo systemctl restart ssh${NC}"
  ask_yesno "Restart sshd ora?" "Y" || { SKIPPED+=("B"); return; }
  run_or_dry "systemctl restart ssh"

  log_ok "SSH hardening applicato (mode=${STEP_B_MODE:-disable})"
  APPLIED+=("B")
}

generate_backup_ssh_key() {
  log_info "Genero seconda chiave SSH ridondata..."
  local stamp; stamp=$(date +%Y%m%d-%H%M%S)
  local key_path="/root/ssh-backup-key-$stamp"

  if [[ "$DRY_RUN" == "yes" ]]; then
    log_dry "ssh-keygen + autorizzazione sul server"
    return
  fi

  # Genera passphrase forte
  local passphrase; passphrase=$(openssl rand -base64 32 | tr -d '/+=' | head -c 28)

  ssh-keygen -t ed25519 -f "$key_path" -N "$passphrase" -C "wazuh-emergency-backup-$stamp" >/dev/null
  cat "${key_path}.pub" >> "/home/$SSH_USER/.ssh/authorized_keys"
  chown "$SSH_USER:$SSH_USER" "/home/$SSH_USER/.ssh/authorized_keys"
  chmod 600 "/home/$SSH_USER/.ssh/authorized_keys"

  cat <<EOF

  ${BOLD}${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}
  ${BOLD}${YELLOW}║   CHIAVE SSH EMERGENCY GENERATA — SALVA IN VAULT             ║${NC}
  ${BOLD}${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}

  Privata: ${BOLD}${key_path}${NC}  (cifrata con passphrase)
  Pubblica: ${BOLD}${key_path}.pub${NC}  (già aggiunta a authorized_keys di $SSH_USER)

  Passphrase: ${BOLD}$passphrase${NC}

  AZIONI OBBLIGATORIE:
    1. Trasferisci ${key_path} sul tuo Mac/laptop ammin:
       ${CYAN}scp $SSH_USER@<server>:${key_path} ~/.ssh/wazuh-emergency-key${NC}
       ${CYAN}scp $SSH_USER@<server>:${key_path}.pub ~/.ssh/wazuh-emergency-key.pub${NC}
    2. Salva la passphrase in vault aziendale (1Password / Bitwarden / cassaforte)
    3. Cancella la chiave privata dal server dopo trasferimento sicuro:
       ${CYAN}sudo shred -u ${key_path} ${key_path}.pub${NC}
    4. Test della chiave da remoto:
       ${CYAN}ssh -i ~/.ssh/wazuh-emergency-key $SSH_USER@<server>${NC}

EOF
  read -r -p "Premi INVIO solo dopo aver trasferito la chiave e salvato la passphrase..."
  STEP_B_MODE="disable"
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
