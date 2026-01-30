# Wazuh Immutable Store

Sistema di archiviazione immutabile per log Wazuh su QNAP NAS con supporto WORM (Write Once Read Many).

## Indice

- [Caratteristiche](#caratteristiche)
- [Architettura](#architettura)
- [Requisiti](#requisiti)
- [Installazione](#installazione)
- [Configurazione QNAP](#configurazione-qnap)
- [Utilizzo](#utilizzo)
- [Recupero e Consultazione Log](#recupero-e-consultazione-log)
- [Automazione](#automazione)
- [Troubleshooting](#troubleshooting)

---

## Caratteristiche

| Funzionalità | Descrizione |
|--------------|-------------|
| **Archiviazione Immutabile** | Integrazione con QNAP WORM per garantire che i log non possano essere modificati o eliminati |
| **Firma Digitale GPG** | Ogni archivio è firmato digitalmente per garantire autenticità |
| **Hash Chain SHA256** | Manifest con hash concatenati per rilevare qualsiasi manomissione |
| **Compressione Efficiente** | Supporto gzip, bz2, xz con livelli configurabili |
| **Retention Flessibile** | Policy separate per storage locale e remoto |
| **Recovery Completo** | Tool per recuperare e consultare log archiviati |
| **Automazione** | Servizi systemd per archiviazione, pulizia e verifica automatiche |

---

## Architettura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SERVER WAZUH                                   │
│                                                                          │
│  /var/ossec/logs/archives/          /tmp/wazuh-archive/                 │
│         │                                   │                            │
│         ▼                                   ▼                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │
│  │   Wazuh     │───▶│ Compressor  │───▶│ GPG Signer  │                  │
│  │   Logs      │    │ (gzip/bz2)  │    │ + SHA256    │                  │
│  └─────────────┘    └─────────────┘    └─────────────┘                  │
│                                               │                          │
│                                               ▼                          │
│                                    ┌─────────────────┐                   │
│                                    │ Transfer Agent  │                   │
│                                    │     (NFS)       │                   │
│                                    └────────┬────────┘                   │
└─────────────────────────────────────────────┼────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            QNAP NAS                                      │
│                                                                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    Volume WORM                                     │  │
│  │  /wazuh-archive/                                                   │  │
│  │    ├── 2025/                                                       │  │
│  │    │   ├── 01/                                                     │  │
│  │    │   │   ├── wazuh-logs-2025-01-30.tar.gz                       │  │
│  │    │   │   ├── wazuh-logs-2025-01-30.tar.gz.sig    (firma GPG)    │  │
│  │    │   │   └── wazuh-logs-2025-01-30.tar.gz.sha256 (checksum)     │  │
│  │    │   └── 02/                                                     │  │
│  │    └── manifests/                                                  │  │
│  │        └── manifest.log  (chain di hash)                           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Retention: 7 anni (WORM impedisce eliminazione anticipata)             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Requisiti

### Server Wazuh
- Linux (Debian/Ubuntu, RHEL/CentOS)
- Python 3.8+
- Wazuh Manager installato
- Connettività di rete verso QNAP

### QNAP NAS
- QTS 5.0 o superiore
- Supporto WORM (disponibile su modelli business)
- Servizio NFS abilitato
- Spazio storage sufficiente per la retention desiderata

### Pacchetti richiesti (installati automaticamente)
- `nfs-common` - Client NFS
- `gnupg` - Firma digitale
- `python3-yaml` - Parsing configurazione

---

## Installazione

### 1. Clona il repository

```bash
git clone https://github.com/grandir66/wazuh-immutable-store.git
cd wazuh-immutable-store
```

### 2. Esegui l'installer

```bash
sudo ./scripts/install.sh
```

L'installer:
- Verifica e installa le dipendenze mancanti
- Copia i file in `/opt/wazuh-immutable-store/`
- Installa i servizi systemd
- Crea le directory necessarie

### 3. Esegui il wizard di configurazione

```bash
sudo wazuh-immutable-store setup
```

Il wizard ti guiderà nella configurazione di:
- Percorsi log Wazuh
- Connessione NFS al QNAP
- Algoritmo di compressione
- Firma GPG (opzionale ma consigliata)
- Policy di retention
- Schedulazione

---

## Configurazione QNAP

### 1. Creazione Volume WORM

1. Accedi all'interfaccia web QNAP
2. Vai su **Storage & Snapshots** → **Storage/Snapshots**
3. Click **Create** → **New Volume**
4. Seleziona **Thick Volume**
5. **Abilita WORM**:
   - Retention Period: 2555 giorni (7 anni) o come richiesto
   - Modalità: **Enterprise** (consigliata)
6. Completa la creazione

### 2. Creazione Shared Folder

1. Vai su **Control Panel** → **Shared Folders**
2. Click **Create** → **Shared Folder**
3. Configura:
   - Nome: `wazuh-archive`
   - Volume: Seleziona il volume WORM
   - Path: `/wazuh-archive`

### 3. Configurazione Export NFS

1. Seleziona la cartella `wazuh-archive`
2. Click **Edit** → **NFS host access**
3. Aggiungi regola:

```
┌─────────────────────────────────────────────────┐
│  Host/IP:    [IP del server Wazuh]              │
│  Permission: Read/Write                          │
│  Squash:     No mapping (IMPORTANTE!)            │
│  Security:   sys (AUTH_SYS)                      │
└─────────────────────────────────────────────────┘
```

4. Abilita NFS: **Control Panel** → **Network & File Services** → **NFS Service**

### 4. Mount sul server Wazuh

```bash
# Test mount manuale
sudo mount -t nfs -o vers=3,hard,intr,rsize=65536,wsize=65536 \
    IP_QNAP:/wazuh-archive /mnt/qnap-wazuh

# Verifica
df -h /mnt/qnap-wazuh
echo "test" > /mnt/qnap-wazuh/test.txt && rm /mnt/qnap-wazuh/test.txt

# Mount permanente (aggiungi a /etc/fstab)
echo "IP_QNAP:/wazuh-archive /mnt/qnap-wazuh nfs vers=3,hard,intr,rsize=65536,wsize=65536,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a
```

---

## Utilizzo

### Comandi Disponibili

| Comando | Descrizione |
|---------|-------------|
| `wazuh-immutable-store setup` | Wizard di configurazione iniziale |
| `wazuh-immutable-store status` | Mostra stato del sistema |
| `wazuh-immutable-store test` | Testa connessione NFS e permessi |
| `wazuh-immutable-store archive` | Esegue archiviazione |
| `wazuh-immutable-store archive --dry-run` | Simula archiviazione senza modifiche |
| `wazuh-immutable-store list` | Lista archivi disponibili |
| `wazuh-immutable-store verify` | Verifica integrità archivi |
| `wazuh-immutable-store retention` | Esegue pulizia secondo policy |
| `wazuh-immutable-store recover` | Recupera log da archivi |
| `wazuh-immutable-store browse` | Consulta log archiviati |
| `wazuh-immutable-store search` | Cerca nei log archiviati |

### Esempi

```bash
# Verifica stato sistema
wazuh-immutable-store status

# Test connessione (esegui sempre prima di archive)
wazuh-immutable-store test

# Archiviazione manuale
wazuh-immutable-store archive

# Lista archivi in formato tabella
wazuh-immutable-store list

# Lista archivi in JSON
wazuh-immutable-store list --format json

# Verifica integrità
wazuh-immutable-store verify
```

---

## Recupero e Consultazione Log

### Recupero per intervallo di date

Recupera tutti i log archiviati in un intervallo di date:

```bash
# Recupera log di gennaio 2025
wazuh-immutable-store recover \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --output /tmp/recovery-gennaio

# Recupera senza verificare le firme (più veloce)
wazuh-immutable-store recover \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --output /tmp/recovery \
    --no-verify
```

### Consultazione interattiva

Naviga e consulta i log archiviati:

```bash
# Avvia browser interattivo
wazuh-immutable-store browse

# Consulta un giorno specifico
wazuh-immutable-store browse --date 2025-01-30

# Consulta con filtro per agente
wazuh-immutable-store browse --date 2025-01-30 --agent "server-web-01"
```

### Ricerca nei log

Cerca eventi specifici nei log archiviati:

```bash
# Cerca per pattern
wazuh-immutable-store search --pattern "authentication failure"

# Cerca in un intervallo di date
wazuh-immutable-store search \
    --pattern "rule.id:5710" \
    --start 2025-01-01 \
    --end 2025-01-31

# Cerca e salva risultati
wazuh-immutable-store search \
    --pattern "srcip:192.168.1.100" \
    --output /tmp/search-results.json
```

### Esportazione log

Esporta log in vari formati:

```bash
# Esporta in JSON
wazuh-immutable-store export \
    --start 2025-01-30 \
    --end 2025-01-30 \
    --format json \
    --output /tmp/logs-export.json

# Esporta in CSV
wazuh-immutable-store export \
    --start 2025-01-30 \
    --end 2025-01-30 \
    --format csv \
    --output /tmp/logs-export.csv
```

---

## Automazione

### Attivazione Timer Systemd

```bash
# Abilita archiviazione giornaliera (ore 02:00)
sudo systemctl enable --now wazuh-immutable-store.timer

# Abilita pulizia retention (ore 03:00)
sudo systemctl enable --now wazuh-immutable-store-retention.timer

# Abilita verifica settimanale (domenica ore 06:00)
sudo systemctl enable --now wazuh-immutable-store-verify.timer
```

### Verifica Timer Attivi

```bash
systemctl list-timers | grep wazuh
```

Output atteso:
```
NEXT                        LEFT          LAST   PASSED  UNIT                                  ACTIVATES
Thu 2025-01-30 02:00:00 CET 8h left       Wed…   15h ago wazuh-immutable-store.timer           wazuh-immutable-store.service
Thu 2025-01-30 03:00:00 CET 9h left       Wed…   14h ago wazuh-immutable-store-retention.timer wazuh-immutable-store-retention.service
Sun 2025-02-02 06:00:00 CET 3 days left   Sun…   6 days  wazuh-immutable-store-verify.timer    wazuh-immutable-store-verify.service
```

### Monitoraggio

```bash
# Log in tempo reale
sudo journalctl -u wazuh-immutable-store -f

# Stato ultimo run
sudo systemctl status wazuh-immutable-store.service

# Esecuzione manuale
sudo systemctl start wazuh-immutable-store.service
```

---

## Struttura Archivi

### File generati

Ogni ciclo di archiviazione produce:

```
wazuh-logs-2025-01-30.tar.gz        # Archivio compresso
wazuh-logs-2025-01-30.tar.gz.sig    # Firma GPG (se abilitata)
wazuh-logs-2025-01-30.tar.gz.sha256 # Checksum SHA256
```

### Contenuto archivio

```
wazuh-logs-2025-01-30.tar.gz
├── 2025/
│   └── jan/
│       └── 30/
│           ├── archives.json       # Log in formato JSON
│           └── archives.log        # Log in formato testo
└── manifest.json                   # Manifest interno con checksum file
```

### Chain di Integrità

Il file `manifest.log` contiene una catena di hash:

```
abc123...  wazuh-logs-2025-01-28.tar.gz  1024000  2025-01-28T02:00:00  PREV:GENESIS
def456...  wazuh-logs-2025-01-29.tar.gz  1048576  2025-01-29T02:00:00  PREV:abc123...
ghi789...  wazuh-logs-2025-01-30.tar.gz  1073152  2025-01-30T02:00:00  PREV:def456...
```

Qualsiasi modifica rompe la catena e viene rilevata dal comando `verify`.

---

## Troubleshooting

### Errore "Permission denied" su NFS

```bash
# Verifica mount
mount | grep qnap

# Sul QNAP verifica:
# 1. L'IP del server Wazuh è nell'export NFS
# 2. Squash è impostato su "No mapping" o "Map root to admin"
# Control Panel → Shared Folders → Edit → NFS host access
```

### Errore "mount.nfs: Protocol not supported"

NFSv4 non supportato, usa NFSv3:

```bash
sudo mount -t nfs -o vers=3,hard,intr IP_QNAP:/wazuh-archive /mnt/qnap-wazuh
```

### Errore "Connection refused"

```bash
# Verifica connettività
ping IP_QNAP

# Verifica export NFS
showmount -e IP_QNAP

# Sul QNAP verifica:
# - NFS Service abilitato
# - Firewall permette porte 111, 2049
```

### Errore "Stale file handle"

```bash
# Rimonta il filesystem
sudo umount -f /mnt/qnap-wazuh
sudo mount -a
```

### Verifica fallita

```bash
# Esegui verifica dettagliata
wazuh-immutable-store verify -v

# Se la chain è rotta, i log potrebbero essere stati manomessi
# Confronta con backup o contatta il supporto
```

### Log di debug

```bash
# Esegui con output verboso
wazuh-immutable-store archive -v

# Visualizza log completi
sudo journalctl -u wazuh-immutable-store --no-pager
```

---

## Configurazione

Il file di configurazione si trova in `/etc/wazuh-immutable-store/config.yaml`.

### Esempio completo

```yaml
# Sorgente log Wazuh
wazuh:
  logs_path: /var/ossec/logs/archives
  file_pattern: archives.json
  include_alerts: true
  alerts_path: /var/ossec/logs/alerts

# Connessione QNAP
qnap:
  host: 192.168.16.26
  export_path: /wazuh-archive
  mount_point: /mnt/qnap-wazuh
  nfs_version: 3
  mount_options: hard,intr,rsize=65536,wsize=65536

# Impostazioni archivio
archive:
  compression: gzip
  compression_level: 6
  naming_pattern: wazuh-logs-{date}.tar.gz
  temp_dir: /tmp/wazuh-archive
  interval: daily

# Firma GPG
gpg:
  enabled: true
  key_id: ABCD1234EFGH5678
  detached: true

# Integrità
integrity:
  algorithm: sha256
  create_manifest: true
  chain_manifests: true

# Retention
retention:
  local:
    days_before_archive: 1
    days_keep_local: 7
    delete_after_transfer: true
  remote:
    days: 2555  # 7 anni
    organize_by_date: true

# Schedulazione
schedule:
  archive_cron: "0 2 * * *"
  integrity_check_cron: "0 6 * * 0"
  cleanup_cron: "0 3 * * *"
```

---

## Compliance

Il sistema è progettato per supportare requisiti di compliance:

| Standard | Requisito | Come viene soddisfatto |
|----------|-----------|------------------------|
| **GDPR** | Conservazione dati | Retention configurabile fino a 10+ anni |
| **PCI-DSS** | Integrità log | WORM + firma GPG + hash chain |
| **ISO 27001** | Audit trail | Log non modificabili, verificabili |
| **NIS2** | Sicurezza eventi | Archiviazione immutabile su storage dedicato |

---

## Licenza

MIT License - vedi [LICENSE](LICENSE)

---

## Supporto

- **Issues**: https://github.com/grandir66/wazuh-immutable-store/issues
- **Documentazione QNAP**: [docs/QNAP_SETUP.md](docs/QNAP_SETUP.md)
