# Wazuh Immutable Store

Sistema di archiviazione immutabile per log Wazuh su QNAP NAS con supporto WORM.

## Caratteristiche

- **Archiviazione Immutabile**: Integrazione con QNAP WORM per garantire immutabilità dei log
- **Firma Digitale**: Supporto GPG per firma e verifica degli archivi
- **Chain di Integrità**: Manifest con hash concatenati per rilevare manomissioni
- **Retention Flessibile**: Policy configurabili per retention locale e remota
- **Recovery Completo**: Tool per recupero e verifica archivi
- **Automazione**: Servizi systemd per operazioni schedulate

## Architettura

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WAZUH SERVER                                │
│  /var/ossec/logs/archives/                                          │
│         │                                                           │
│         ▼                                                           │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │ Log Collector   │───▶│ Compressor +    │───▶│ GPG Signer      │ │
│  │                 │    │ SHA256          │    │                 │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘ │
│                                   │                                 │
└───────────────────────────────────┼─────────────────────────────────┘
                                    │
                                    ▼ (NFS + WORM)
┌─────────────────────────────────────────────────────────────────────┐
│                           QNAP NAS                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Volume WORM - /wazuh-archive/                               │   │
│  │   └── 2025/01/                                              │   │
│  │       ├── wazuh-logs-2025-01-30.tar.gz                     │   │
│  │       ├── wazuh-logs-2025-01-30.tar.gz.sig                 │   │
│  │       └── wazuh-logs-2025-01-30.tar.gz.sha256              │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Requisiti

- **Server**: Linux con Wazuh Manager
- **Python**: 3.8+
- **Pacchetti**: gnupg, nfs-common
- **QNAP**: QTS 5.0+ con supporto WORM

## Installazione

### 1. Clona il repository

```bash
git clone https://github.com/your-repo/wazuh-immutable-store.git
cd wazuh-immutable-store
```

### 2. Esegui l'installer

```bash
sudo ./scripts/install.sh
```

### 3. Configura il sistema

```bash
sudo wazuh-immutable-store setup
```

Il wizard ti guiderà nella configurazione di:
- Percorsi log Wazuh
- Connessione NFS al QNAP
- Firma GPG
- Policy di retention
- Schedulazione

### 4. Configura il QNAP

Segui la guida dettagliata in [docs/QNAP_SETUP.md](docs/QNAP_SETUP.md) per:
- Creare volume WORM
- Configurare export NFS
- Impostare permessi

### 5. Abilita i servizi

```bash
sudo systemctl enable --now wazuh-immutable-store.timer
sudo systemctl enable --now wazuh-immutable-store-retention.timer
sudo systemctl enable --now wazuh-immutable-store-verify.timer
```

## Utilizzo

### Comandi Disponibili

```bash
# Mostra stato sistema
wazuh-immutable-store status

# Esegui archiviazione manuale
wazuh-immutable-store archive

# Esegui con dry-run (senza modifiche)
wazuh-immutable-store archive --dry-run

# Esegui ciclo retention
wazuh-immutable-store retention

# Verifica integrità archivi
wazuh-immutable-store verify

# Lista archivi disponibili
wazuh-immutable-store list
wazuh-immutable-store list --format json

# Recupera archivi
wazuh-immutable-store recover \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --output /tmp/recovery
```

### Verifica Stato

```bash
# Stato servizi systemd
systemctl status wazuh-immutable-store.timer
systemctl list-timers wazuh-immutable-store*

# Log operazioni
journalctl -u wazuh-immutable-store -f
```

## Configurazione

Il file di configurazione si trova in `/etc/wazuh-immutable-store/config.yaml`.

### Esempio Configurazione

```yaml
wazuh:
  logs_path: /var/ossec/logs/archives
  include_alerts: true

qnap:
  host: "192.168.1.100"
  export_path: "/wazuh-archive"
  mount_point: /mnt/qnap-wazuh
  nfs_version: 4

archive:
  compression: gzip
  compression_level: 6
  interval: daily

gpg:
  enabled: true
  key_id: "YOUR_KEY_ID"

retention:
  local:
    days_keep_local: 7
    delete_after_transfer: true
  remote:
    days: 2555  # 7 anni
```

## Struttura Archivi

Ogni archivio include:

```
wazuh-logs-2025-01-30.tar.gz       # Archivio compresso
wazuh-logs-2025-01-30.tar.gz.sig   # Firma GPG
wazuh-logs-2025-01-30.tar.gz.sha256 # Checksum SHA256
```

Contenuto archivio:
```
├── 2025/
│   └── jan/
│       └── 30/
│           ├── archives.json
│           └── archives.log
└── manifest.json                  # Manifest interno
```

## Manifest Chain

Il sistema mantiene un manifest con hash concatenati:

```
abc123...  wazuh-logs-2025-01-28.tar.gz  1024000  2025-01-28T02:00:00  PREV:GENESIS
def456...  wazuh-logs-2025-01-29.tar.gz  1048576  2025-01-29T02:00:00  PREV:abc123...
ghi789...  wazuh-logs-2025-01-30.tar.gz  1073152  2025-01-30T02:00:00  PREV:def456...
```

Qualsiasi modifica rompe la catena e viene rilevata dalla verifica.

## Recovery

### Recupero per Range di Date

```bash
wazuh-immutable-store recover \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --output /home/user/recovery

# Skip verifica (non consigliato)
wazuh-immutable-store recover \
    --start 2025-01-01 \
    --end 2025-01-31 \
    --output /home/user/recovery \
    --no-verify
```

### Verifica Singolo Archivio

```bash
# Verifica integrità
wazuh-immutable-store verify

# Output JSON per automation
wazuh-immutable-store list --format json | jq '.[] | select(.has_signature == true)'
```

## Sicurezza

### Immutabilità

1. **WORM QNAP**: I file non possono essere modificati/eliminati fino alla scadenza retention
2. **Firma GPG**: Garantisce autenticità e non-ripudiabilità
3. **Hash Chain**: Rileva manomissioni nella sequenza degli archivi

### Best Practices

- Genera chiave GPG dedicata per il signing
- Conserva backup della chiave GPG in luogo sicuro
- Configura retention WORM >= retention desiderata
- Monitora spazio disco QNAP
- Esegui verifiche integrità periodiche

## Troubleshooting

### NFS non si monta

```bash
# Verifica connettività
ping QNAP_IP
showmount -e QNAP_IP

# Verifica firewall
sudo iptables -L -n | grep 2049
```

### GPG signing fallisce

```bash
# Verifica chiave disponibile
gpg --list-secret-keys

# Test firma manuale
gpg --detach-sign --armor test.txt
```

### Spazio insufficiente

```bash
# Verifica spazio
df -h /mnt/qnap-wazuh

# Controlla retention policy
wazuh-immutable-store status
```

## Compliance

Il sistema è progettato per supportare requisiti di compliance:

- **GDPR**: Retention configurabile, immutabilità garantita
- **PCI-DSS**: Log audit protetti da modifiche
- **ISO 27001**: Integrità log verificabile
- **NIS2**: Archiviazione sicura eventi sicurezza

## Licenza

MIT License - vedi [LICENSE](LICENSE)

## Contributi

Contributi benvenuti! Apri una issue o pull request.

## Supporto

- Issues: https://github.com/your-repo/wazuh-immutable-store/issues
- Documentazione: [docs/](docs/)
