# Wazuh Server — Hardening Checklist

> Guida operativa per l'hardening di un server Linux che ospita Wazuh Manager + Indexer + Dashboard. Pensata per essere consegnata insieme alla soluzione Wazuh Immutable Store. Allineata a CIS Benchmarks e DISA STIG dove applicabile.

---

## Indice

1. [Principi guida](#1-principi-guida)
2. [Inventario superficie d'attacco](#2-inventario-superficie-dattacco)
3. [Layer 1 — Quick wins](#3-layer-1--quick-wins-1-ora-blocca-80-degli-attacchi-opportunistici)
4. [Layer 2 — Hardening standard](#4-layer-2--hardening-standard-mezza-giornata)
5. [Layer 3 — Advanced (compliance-grade)](#5-layer-3--advanced-compliance-grade)
6. [Verifica indipendente per auditor](#6-verifica-indipendente-per-auditor)
7. [Mappatura controlli CIS / STIG](#7-mappatura-controlli-cis--stig)
8. [Cose da NON fare](#8-cose-da-non-fare)

---

## 0. Decisioni operative pre-hardening

Gli step A (firewall) e B (SSH) sono **i più rischiosi** dell'intero processo: applicati senza precauzioni, possono causare il **lockout completo** dal server. Prima di eseguirli, è obbligatorio rispondere alle 4 domande seguenti.

### Domanda 1 — Hai un canale di accesso di emergenza fuori da SSH?

Devi sapere come entrare nel server se SSH smette di funzionare. Opzioni:

| Canale emergency | Come usarlo |
|---|---|
| **Console VM Proxmox** (se il server è virtualizzato) | Login web UI Proxmox del cliente → seleziona VM → tab Console → noVNC/spice |
| **iLO/iDRAC/IPMI** (server fisico HP/Dell/Supermicro) | Connessione out-of-band sul management port dedicato |
| **Console fisica** (server on-prem) | Tastiera+monitor sull'host fisico |
| **Bastion host alternativo** | SSH a un secondo server della stessa LAN, da cui poi raggiungere il Wazuh |

Se nessuno è disponibile o accessibile, **non applicare lo step B** in modalità "disable" (vai con "match address").

### Domanda 2 — Quante chiavi SSH autorizzate ci sono per l'utente sudo?

Verifica:

```bash
grep -c '^ssh-' /home/<UTENTE>/.ssh/authorized_keys
```

- **1 sola chiave** = single point of failure. Se il dispositivo che la ospita si rompe, sei fuori. Genera una seconda "break glass key" prima di procedere (lo script `harden-wazuh.sh` offre l'opzione automatica con backup AES-256 in vault).
- **2+ chiavi indipendenti** = OK, puoi procedere con disable totale di PasswordAuth.

### Domanda 3 — Da quale IP/subnet ti stai collegando?

L'IP visto dal server determina quali subnet devi consentire nelle regole UFW per non bloccarti. Verifica:

```bash
who | awk 'NR==1 {print $5}' | tr -d '()'
# oppure:
ss -tnp state established 'sport = :22'
```

Casi comuni:

- IP nella **LAN dello stesso cliente** (`172.16.x.x` se quello è il subnet) → `ufw allow from 172.16.0.0/16 to any port 22 proto tcp`
- IP del **subnet router Tailscale** (`100.64.x.x` o NAT interno tipo `172.17.100.x`) → `ufw allow from 172.17.100.0/24 to any port 22 proto tcp`
- **Mai chiudere SSH** prima di aver mappato il tuo IP attuale di accesso.

### Domanda 4 — Vuoi PasswordAuth disabilitata totalmente o limitata?

Tre modi di gestire PasswordAuthentication:

| Modalità | Sicurezza | Resilienza | Raccomandato per |
|---|---|---|---|
| **Disable totale** (`PasswordAuthentication no`) | ★★★ | ★ (solo chiave) | Ambienti con 2+ chiavi e console emergency confermata |
| **Match Address** (password OK solo da subnet di trust) | ★★ | ★★★ | Ambienti operativi (Domarc IT) con singola chiave, fallback comodo |
| **Lasciare yes con MaxAuthTries 3 + fail2ban aggressive** | ★ | ★★★ | Solo se non puoi cambiare nulla, ma combinato con fail2ban è accettabile |

Lo script `harden-wazuh.sh` ora chiede esplicitamente quale modalità preferisci e offre la generazione automatica della chiave backup.

### Pre-flight checklist (obbligatorio prima di applicare A o B)

- [ ] Console emergency identificata e accessibile (Proxmox/iLO/IPMI/altro)
- [ ] Almeno una **NUOVA** sessione SSH aperta da test parallelo (per verificare config sshd dopo restart senza chiudere quella corrente)
- [ ] IP/subnet di provenienza identificato e annotato
- [ ] Chiavi SSH autorizzate contate (≥1 verificato funzionante)
- [ ] Se PasswordAuth viene disabilitata: 2+ chiavi presenti, oppure console emergency confermata
- [ ] Hai a portata di mano i comandi di rollback (anche scritti su carta):
  ```bash
  sudo cp /etc/ssh/sshd_config.pre-harden-* /etc/ssh/sshd_config
  sudo systemctl restart ssh
  sudo ufw disable
  ```

---

## 1. Principi guida

- **Minimizzazione della superficie d'attacco**: disabilita tutto ciò che non serve. Un servizio in ascolto inutilizzato è una porta d'ingresso potenziale.
- **Defense in depth**: nessun controllo è perfetto. Combinare firewall + intrusion detection + integrity monitoring riduce il rischio anche in caso di bypass di uno strato.
- **Auditabilità**: ogni modifica al sistema deve essere tracciata. Le evidenze devono essere conservate in modo immutabile (cosa che Wazuh stesso garantisce sui propri log).
- **Reversibilità sicura**: ogni modifica di hardening produce backup dei file originali con timestamp, per consentire rollback.
- **Compatibilità con Wazuh**: alcuni hardening "standard" rompono Wazuh (es. SELinux enforcing senza policy custom, mount `/var/log` read-only). La checklist tiene conto di queste eccezioni.

---

## 2. Inventario superficie d'attacco

Prima di applicare hardening, mappare cosa è esposto:

```bash
# Porte in ascolto
sudo ss -tlnp | sort

# Servizi systemd attivi
systemctl list-units --type=service --state=running

# Utenti con shell di login
awk -F: '$7 !~ /(nologin|false)/ {print $1, $7}' /etc/passwd

# Utenti con privilegi sudo
getent group sudo wheel 2>/dev/null

# Cron job e scheduled tasks
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l
for u in $(awk -F: '{print $1}' /etc/passwd); do crontab -u "$u" -l 2>/dev/null && echo "  -- $u --"; done

# Tutti i pacchetti installati con servizi di rete
dpkg --get-selections | grep -i -E "ssh|nfs|apache|nginx|mysql|postgres|samba|ftp"
```

Su un server Wazuh tipico ti aspetti in ascolto:

| Porta | Servizio | Origine ammessa |
|---|---|---|
| `22/tcp` | sshd | Operatori autorizzati (rete privata o VPN) |
| `1514/tcp+udp` | wazuh-remoted | Agent autorizzati |
| `1515/tcp` | wazuh-authd | Agent in enrollment iniziale |
| `55000/tcp` | wazuh-apid | Integrazioni autorizzate (es. DA-IPAM) |
| `9200/tcp` | wazuh-indexer (OpenSearch) | Integrazioni autorizzate |
| `9300/tcp` | wazuh-indexer (cluster transport) | Solo nodes del cluster |
| `443/tcp` | wazuh-dashboard | Operatori autorizzati |

Tutto il resto in ascolto va investigato.

---

## 3. Layer 1 — Quick wins (1 ora, blocca 80% degli attacchi opportunistici)

### A) Firewall stateful con allowlist

**Obiettivo**: tutto il traffico in ingresso negato di default, eccetto whitelist esplicita.

**Tool**: UFW (frontend di iptables/nftables).

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <LAN_CIDR> to any port 22 proto tcp
sudo ufw allow from <LAN_CIDR> to any port 1514
sudo ufw allow from <LAN_CIDR> to any port 1515 proto tcp
sudo ufw allow from <LAN_CIDR> to any port 443 proto tcp
sudo ufw allow from <INTEGRATION_IP> to any port 55000 proto tcp
sudo ufw allow from <INTEGRATION_IP> to any port 9200 proto tcp
sudo ufw enable
```

**Verifica**: `sudo ufw status verbose`

**Backout**: `sudo ufw disable` ripristina lo stato precedente.

### B) SSH hardening

**Obiettivo**: forzare autenticazione a chiave, disabilitare features non necessarie.

**Pre-requisito critico**: assicurarsi che l'utente operativo (es. `dts`) abbia `~/.ssh/authorized_keys` con almeno una chiave pubblica valida prima di disabilitare PasswordAuthentication.

```bash
sudo tee /etc/ssh/sshd_config.d/99-harden.conf > /dev/null <<EOF
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers <SSH_USER>
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
EOF
sudo sshd -t && sudo systemctl restart ssh
```

**Verifica**: aprire una NUOVA sessione SSH senza chiudere la corrente.

**Backout**: `sudo rm /etc/ssh/sshd_config.d/99-harden.conf && sudo systemctl restart ssh`

### C) Unattended-upgrades per security patches

**Obiettivo**: applicare automaticamente patch di sicurezza del SO (NON Wazuh, NON applicativi gestiti).

```bash
sudo apt install -y unattended-upgrades apt-listchanges
sudo dpkg-reconfigure -plow unattended-upgrades
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

**Verifica**: `sudo cat /etc/apt/apt.conf.d/50unattended-upgrades` — deve avere security source abilitata. `apt-mark showhold` mostra Wazuh in hold.

### D) Fail2ban per SSH brute-force

**Obiettivo**: bannare automaticamente IP che falliscono 3+ tentativi di login in 10 minuti.

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
banaction = ufw

[sshd]
enabled = true
mode = aggressive
EOF
sudo systemctl enable --now fail2ban
```

**Verifica**: `sudo fail2ban-client status sshd`

### E) NTP sync (chrony)

**Obiettivo**: garantire timestamp accurati. La hash chain crittografica dipende da timestamp coerenti.

```bash
sudo apt install -y chrony
sudo systemctl enable --now chrony
chronyc tracking      # verifica offset e source
chronyc sources -v
```

**Output atteso**: `Leap status: Normal`, offset `< 100 ms`.

---

## 4. Layer 2 — Hardening standard (mezza giornata)

### F) Kernel hardening (sysctl)

**Obiettivo**: parametri kernel resistenti a tecniche di exploit comuni.

```bash
sudo tee /etc/sysctl.d/99-wazuh-hardening.conf <<EOF
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_timestamps = 0
EOF
sudo sysctl --system
```

**Verifica**: `sudo sysctl kernel.randomize_va_space` deve restituire `2`.

### G) Mount options per `/tmp` e `/dev/shm`

**Obiettivo**: prevenire esecuzione di binari dropped in directory world-writable.

```bash
# Aggiungi a /etc/fstab:
tmpfs   /tmp        tmpfs   defaults,noexec,nosuid,nodev,size=2G   0 0
tmpfs   /dev/shm    tmpfs   defaults,noexec,nosuid,nodev,size=512M 0 0
```

⚠️ **Wazuh Immutable Store usa `/tmp/wazuh-archive`** come directory temporanea per la compressione. Se applichi `noexec` su `/tmp`, devi cambiare `temp_dir` in `/etc/wazuh-immutable-store/config.yaml` a `/var/tmp/wazuh-archive` (path scrivibile senza noexec).

**Verifica post-reboot**: `mount | grep '/tmp '` deve mostrare `noexec,nosuid,nodev`.

### H) Audit daemon (auditd) con regole CIS

**Obiettivo**: log immutabile di ogni accesso ai materiali sensibili (chiave GPG, config Wazuh, sudoers).

```bash
sudo apt install -y auditd
sudo tee /etc/audit/rules.d/99-wazuh-watch.rules <<EOF
-w /root/.gnupg/ -p rwxa -k gpg_key_access
-w /etc/wazuh-immutable-store/ -p rwxa -k wis_config
-w /var/ossec/etc/ossec.conf -p wa -k wazuh_config
-w /var/ossec/etc/client.keys -p wa -k wazuh_agent_keys
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/cron.d/ -p wa -k cron
-e 2
EOF
sudo augenrules --load
sudo systemctl restart auditd
```

**Verifica**: `sudo ausearch -k gpg_key_access` elenca tutti gli accessi alla chiave GPG. Wazuh agent locale legge queste regole e le inoltra come alert.

### I) AIDE — file integrity baseline

**Obiettivo**: rilevare modifiche non autorizzate a binari di sistema, librerie, config.

```bash
sudo apt install -y aide
sudo aideinit    # 15-30 minuti, in background con nohup se possibile
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo tee /etc/cron.d/aide <<EOF
0 4 * * * root /usr/bin/aide --check > /var/log/aide.log 2>&1
EOF
```

**Verifica**: `sudo aide --check` (può richiedere minuti). Output atteso: `All files match AIDE database. Looks okay!`.

### J) Wazuh agent locale self-monitoring

**Obiettivo**: il Wazuh manager monitora se stesso (FIM real-time su materiali sensibili).

Modifica `/var/ossec/etc/ossec.conf`, dentro `<syscheck>`:

```xml
<directories check_all="yes" realtime="yes">/root/.gnupg,/etc/wazuh-immutable-store,/etc/ssh,/etc/sudoers.d</directories>
<directories check_all="yes">/usr/local/bin,/opt/wazuh-immutable-store,/etc/systemd/system</directories>
```

Restart manager: `sudo systemctl restart wazuh-manager`.

**Verifica**: modifica un file in `/etc/wazuh-immutable-store/` e verifica che generi alert nella dashboard Wazuh.

### K) Disabilita servizi inutili

**Obiettivo**: ridurre attack surface.

```bash
# Esempi tipicamente disabilitabili su un Wazuh server senza GUI/Bluetooth/Stampa:
sudo systemctl disable --now snapd apport ModemManager bluetooth cups avahi-daemon
```

Valuta caso per caso. **Non disabilitare** mai: `ssh`, `chrony`, `wazuh-*`, `ufw`, `cron`, `systemd*`, `networkd`, `resolved`, `fail2ban`, `auditd`.

### L) PAM lockout (5 falliti → 15 min lock)

**Obiettivo**: rallentare attacchi brute-force su login locale.

Modifica `/etc/pam.d/common-auth`:

```
auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900
auth    [success=1 default=bad]  pam_unix.so
auth    [default=die]    pam_faillock.so authfail deny=5 unlock_time=900
auth    sufficient    pam_faillock.so authsucc
```

**Verifica**: 5 tentativi falliti consecutivi → l'utente è bloccato per 900 secondi (`sudo faillock --user <utente>`).

---

## 5. Layer 3 — Advanced (compliance-grade)

### M) Hardware token per chiave GPG (YubiKey)

Risolve il gap "chiave senza passphrase" mantenendo l'automazione. La chiave privata non risiede MAI sul filesystem: vive solo nel chip OpenPGP del token. La firma richiede touch del token (o PIN cached da TPM).

Costo indicativo: 2 token YubiKey 5 NFC ridondati ~110 EUR. Setup: 1 giornata.

### N) `chattr +i` su file critici di configurazione

**Obiettivo**: rendere immutabili anche per root certi file (richiede `chattr -i` prima di modificarli).

```bash
sudo chattr +i /etc/wazuh-immutable-store/config.yaml
sudo chattr +i /etc/wazuh-immutable-store/wazuh-archive-pubkey.asc
sudo chattr +i /etc/sudoers /etc/sudoers.d/*
sudo chattr +i /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*
```

**Verifica**: `lsattr /etc/sudoers` mostra `i` flag. Tentativo di `sudo rm` fallisce con "Operation not permitted".

### O) AppArmor profile per `wazuh-immutable-store`

Profilo restrittivo: solo i path strettamente necessari. Genera profilo interattivo:

```bash
sudo aa-genprof /opt/wazuh-immutable-store/main.py
# segui i prompt
sudo aa-enforce /etc/apparmor.d/opt.wazuh-immutable-store.main.py
```

### P) Encryption a riposo (LUKS / ZFS native encryption)

Se il server è una VM: encryption a livello hypervisor (Proxmox supporta ZFS native encryption sui dataset). In caso di furto del disco fisico, dati illeggibili senza chiave master.

### Q) Forwarding out-of-band degli alert critici

Wazuh stesso può inoltrare via email gli alert ≥10 a un mailbox esterno. Cosi anche se un attaccante compromette il Wazuh, il SOC esterno riceve l'evidence.

```xml
<global>
  <email_notification>yes</email_notification>
  <smtp_server>mail.cliente.it</smtp_server>
  <email_from>wazuh@cliente.it</email_from>
  <email_to>soc@cliente.it</email_to>
  <email_alert_level>10</email_alert_level>
</global>
```

### R) Snapshot Proxmox + backup off-site (PBS)

- Snapshot Proxmox quotidiani con retention 30 giorni
- Replica via Proxmox Backup Server verso location off-site
- Test restore documentato semestralmente

### S) Penetration test annuale

Quando il setup è stabile, considerare un PT esterno una volta l'anno. Evidenza ad alto valore per audit.

---

## 6. Verifica indipendente per auditor

Set di comandi che un auditor terzo può eseguire sul server per validare lo stato di hardening:

```bash
# A — Firewall attivo con allowlist
sudo ufw status verbose

# B — SSH config attesa
sshd -T | grep -E "permitrootlogin|passwordauthentication|maxauthtries|allowusers"
# Atteso: no, no, 3, <utente specifico>

# C — Unattended-upgrades attivo
sudo systemctl is-enabled unattended-upgrades

# D — Fail2ban attivo, sshd jail attivo
sudo fail2ban-client status
sudo fail2ban-client status sshd

# E — NTP sync funzionante
chronyc tracking | grep "Leap status"
# Atteso: Normal

# F — Sysctl hardening attivo
sysctl kernel.randomize_va_space kernel.kptr_restrict fs.suid_dumpable
# Atteso: 2, 2, 0

# G — Mount options /tmp
mount | grep '/tmp '
# Atteso: noexec,nosuid,nodev

# H — Auditd attivo + regole caricate
sudo auditctl -l | grep -E "gpg_key_access|wazuh_config"
sudo aureport -k

# I — AIDE database presente
ls -la /var/lib/aide/aide.db

# J — Wazuh FIM su materiali sensibili
sudo grep -A2 syscheck /var/ossec/etc/ossec.conf | grep -E "gnupg|wazuh-immutable"

# K — Servizi inutili disabilitati
systemctl list-unit-files --state=enabled | grep -E "snapd|cups|bluetooth"
# Atteso: vuoto (o solo servizi giustificati)

# L — PAM lockout attivo
grep faillock /etc/pam.d/common-auth

# Wazuh self-monitoring funzionante
sudo wazuh-immutable-store status
sudo /var/ossec/bin/wazuh-control status
```

---

## 7. Mappatura controlli CIS / STIG

| Controllo | CIS Benchmark Ubuntu 22.04/24.04 | DISA STIG |
|---|---|---|
| Firewall enabled | 3.5.1.1 | UBTU-22-213040 |
| Disable wireless interfaces | 3.1.2 | — |
| TCP SYN cookies | 3.3.6 | UBTU-22-253015 |
| ASLR enabled | 1.5.3 | UBTU-22-411015 |
| ptrace_scope restricted | 1.5.2 | — |
| `/tmp` noexec | 1.1.2.3 | UBTU-22-411040 |
| SSH PermitRootLogin no | 5.2.7 | UBTU-22-255040 |
| SSH PasswordAuthentication no | 5.2.16 | UBTU-22-255100 |
| SSH MaxAuthTries 3 | 5.2.12 | — |
| Auditd installed and enabled | 4.1.1.1 | UBTU-22-654010 |
| File integrity monitoring (AIDE) | 1.4.1 | UBTU-22-411055 |
| Account lockout policy | 5.4.2 | UBTU-22-411050 |
| Unattended-upgrades security | 1.9 | — |
| Disable USB storage | 1.1.10 | UBTU-22-411035 (opzionale) |
| Sudo logging | 5.3.5 | UBTU-22-255005 |

---

## 8. Cose da NON fare

❌ **Cambiare porta SSH da 22**: security by obscurity, inutile. Spezza solo l'automation.

❌ **Disabilitare l'utente `dts` (o equivalente)**: rischio lockout completo se la chiave SSH di root non funziona.

❌ **`chattr +i /var/ossec/...`**: Wazuh ha bisogno di scrivere lì. Romperesti il manager.

❌ **`noexec` su `/var`**: rompe il package manager (apt installa script lì).

❌ **Bloccare outbound completo**: Wazuh manager ha bisogno di scaricare vulnerability feed, OpenSearch ha bisogno di sync, ecc.

❌ **Abilitare SELinux su Ubuntu**: incompatibile. Usa AppArmor (già attivo).

❌ **Mettere SELinux enforcing su RHEL senza policy custom per Wazuh**: blocca servizi.

❌ **Disabilitare `cron`**: AIDE, unattended-upgrades, backup ne dipendono.

❌ **Modificare manualmente `/etc/passwd`/`/etc/shadow`**: usa `useradd`, `userdel`, `passwd`.

❌ **Cancellare `/var/ossec/etc/client.keys`**: tutti gli agent perdono trust con il manager.

❌ **`apt full-upgrade` senza fare snapshot prima**: rischio rottura Wazuh stack.

---

## Riferimenti

- CIS Ubuntu 22.04 Benchmark v2.0.0
- DISA Ubuntu 22.04 STIG V1R1
- NIST SP 800-53 Rev. 5 (controlli SI-7, AC-7, AU-2, CM-6)
- Wazuh Security Guide: <https://documentation.wazuh.com/current/user-manual/securing/index.html>
- Script automatizzato: `scripts/harden-wazuh.sh` di questo repository

## Licenza

MIT License — vedi `LICENSE` del repository.
