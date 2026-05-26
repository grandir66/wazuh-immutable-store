# Wazuh Immutable Store — Logica di gestione dell'immutabilità

> Documento descrittivo della soluzione tecnica adottata per garantire l'immutabilità dei log di sicurezza prodotti da Wazuh SIEM. Da fornire a clienti, auditor e responsabili sicurezza come materiale di accompagnamento.

---

## Indice

1. [Scopo e ambito](#1-scopo-e-ambito)
2. [Architettura a difesa in profondità](#2-architettura-a-difesa-in-profondità)
3. [Pipeline operativa end-to-end](#3-pipeline-operativa-end-to-end)
4. [Garanzie crittografiche](#4-garanzie-crittografiche)
5. [Gestione del materiale crittografico](#5-gestione-del-materiale-crittografico)
6. [Mitigazione della finestra di esposizione](#6-mitigazione-della-finestra-di-esposizione)
7. [Procedure di audit e verifica](#7-procedure-di-audit-e-verifica)
8. [Scenari di recovery](#8-scenari-di-recovery)
9. [Mappatura controlli ↔ standard di compliance](#9-mappatura-controlli--standard-di-compliance)
10. [Glossario](#10-glossario)

---

## 1. Scopo e ambito

La soluzione **Wazuh Immutable Store** implementa una catena di custodia (*chain of custody*) verificabile e a prova di manomissione per i log di sicurezza generati dalla piattaforma Wazuh SIEM.

Lo scopo è garantire che, una volta archiviato, ogni log:

- **non possa essere modificato** (integrità contenuto)
- **non possa essere cancellato** prima della scadenza della retention configurata (preservazione)
- **possa essere attribuito con certezza** al sistema che l'ha prodotto (autenticità)
- **possa essere verificato in modo indipendente** da terzi, anche dopo anni (non ripudio)

Il sistema risponde ai requisiti di conservazione delle evidenze digitali previsti dai principali standard di gestione della sicurezza delle informazioni (ISO 27001, NIS2, GDPR, PCI-DSS, TISAX) e supporta scenari di audit forensic.

---

## 2. Architettura a difesa in profondità

La protezione si articola in **quattro livelli indipendenti**. Ciascun livello garantisce una proprietà distinta. La compromissione di un singolo livello non comporta la perdita complessiva delle garanzie — gli altri continuano a fornire evidenza dell'integrità.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Livello 4 — Snapshot ZFS (recovery point-in-time)                  │
│  Filesystem copy-on-write con checksum end-to-end                   │
├─────────────────────────────────────────────────────────────────────┤
│  Livello 3 — WORM hardware (Write Once Read Many)                   │
│  Shared folder NAS con retention vincolata a livello firmware       │
├─────────────────────────────────────────────────────────────────────┤
│  Livello 2 — Hash chain SHA-256 + manifest concatenato              │
│  Manomissione retroattiva rilevabile per rottura della catena       │
├─────────────────────────────────────────────────────────────────────┤
│  Livello 1 — Firma digitale GPG (RSA 4096 o Ed25519)                │
│  Autenticità e non ripudio di ogni archivio                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Sintesi delle proprietà garantite per livello

| Livello | Tecnologia | Proprietà | Tipologia |
|---|---|---|---|
| 1 | GPG signing (RSA/Ed25519) | Autenticità, non ripudio | Rilevativa |
| 2 | SHA-256 + hash chain | Integrità retroattiva | Rilevativa |
| 3 | WORM filesystem | Immutabilità contenuto | Preventiva (hardware) |
| 4 | Snapshot ZFS | Recovery temporale | Preventiva (storico) |

---

## 3. Pipeline operativa end-to-end

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          SERVER WAZUH                                    │
│                                                                          │
│  Agent SIEM (Win/Lin/Mac)                                                │
│      │                                                                   │
│      ▼ porte 1514/1515 TCP cifrate                                       │
│  ┌─────────────────────────────────┐                                     │
│  │  Wazuh Manager                  │  <logall>yes</logall>               │
│  │  /var/ossec/logs/archives/      │  <logall_json>yes</logall_json>     │
│  │  /var/ossec/logs/alerts/        │                                     │
│  └─────────────┬───────────────────┘                                     │
│                │                                                         │
│                ├── Hash chain rolling (ogni 5 min)                       │
│                │   composite = sha256(head_1M + tail_1M + size)          │
│                │   firmato GPG → /var/log/wazuh-rolling-manifest.log     │
│                │                                                         │
│                ▼ Archive ciclo (orario o giornaliero)                    │
│  ┌─────────────────────────────────┐                                     │
│  │  wazuh-immutable-store          │                                     │
│  │  ├─ compressione gzip livello 6 │                                     │
│  │  ├─ checksum SHA-256            │                                     │
│  │  ├─ firma GPG detached          │                                     │
│  │  └─ manifest chain concatenato  │                                     │
│  └─────────────┬───────────────────┘                                     │
└────────────────┼─────────────────────────────────────────────────────────┘
                 │ NFSv4 (sys auth, host-restricted, no_root_squash)
                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          NAS / STORAGE WORM                              │
│                                                                          │
│  Shared folder "wazuh-archive" su volume ZFS                             │
│  WORM Enterprise mode · Retention 12 mesi · Auto-lock 5 min              │
│                                                                          │
│  /wazuh-archive/                                                         │
│    ├── 2026/                                                             │
│    │   └── 05/                                                           │
│    │       ├── wazuh-logs-2026-05-26-02.tar.gz                           │
│    │       ├── wazuh-logs-2026-05-26-02.tar.gz.sig                       │
│    │       └── wazuh-logs-2026-05-26-02.tar.gz.sha256                    │
│    ├── manifests/                                                        │
│    │   └── manifest.log     (chain di hash concatenati)                  │
│    └── wazuh-archive-pubkey.asc   (chiave pubblica per verifica)         │
│                                                                          │
│  Snapshot ZFS schedulati (giornalieri, settimanali, mensili)             │
└──────────────────────────────────────────────────────────────────────────┘
```

### Fase 1 — Raccolta dai Wazuh Agent

I Wazuh Agent installati sugli endpoint monitorati raccolgono eventi in tempo reale dal sistema operativo (Event Log per Windows, syslog per Unix/Linux), dai file di log applicativi e dai moduli di analisi (File Integrity Monitoring, Syscollector, Vulnerability Detector, Rootcheck, Security Configuration Assessment).

La comunicazione agent → manager utilizza il protocollo proprietario Wazuh:

| Porta | Uso |
|---|---|
| `1514/tcp` (o udp) | Eventi a regime |
| `1515/tcp` | Enrollment iniziale dell'agent (`agent-auth`) |

Il traffico è cifrato simmetricamente con la chiave assegnata univocamente a ciascun agent in fase di registrazione.

### Fase 2 — Persistenza integrale sul Manager

Il Manager è configurato con `<logall>yes</logall>` e `<logall_json>yes</logall_json>` per persistere ogni evento ricevuto, sia in formato testuale che strutturato JSON:

- `/var/ossec/logs/archives/archives.{json,log}` — eventi grezzi in tempo reale (file live, mutabili durante la giornata)
- `/var/ossec/logs/alerts/alerts.{json,log}` — alert generati dalle regole di correlazione
- `/var/ossec/logs/archives/YYYY/Mon/ossec-archive-DD.{json,log}` — file giornalieri (hard-link al live durante la giornata in corso, indipendenti dopo la rotazione di mezzanotte UTC)

A mezzanotte UTC, Wazuh esegue la rotazione interna: il file giornaliero del giorno appena terminato diventa indipendente dal file live (che riparte da zero), viene compresso in `.gz` e prosegue come "storico" del filesystem locale.

### Fase 3 — Hash chain rolling sui file live

Mentre i file live sono ancora mutabili (tra una rotazione di mezzanotte e la successiva), un timer systemd dedicato esegue ogni 5 minuti uno script che:

1. Calcola un **hash composito** di ciascun file live:
   ```
   composite = sha256( head_1MB || 0x00 || tail_1MB || 0x00 || ascii(size) )
   ```
   Questo hash rileva:
   - modifiche al passato distante (cambia `head_1MB` o `size`)
   - modifiche al passato recente (cambia `tail_1MB`)
   - iniezione di eventi (cambia `tail_1MB` e `size`)
   - troncamento (cambia `size`)
2. Concatena ciascuna entry con riferimento al hash precedente (PREV-pointer)
3. Append al manifest `/var/log/wazuh-rolling-manifest.log`
4. Firma il manifest aggiornato con GPG detached signature

Costo per ciclo: ~150 ms anche su file da decine di GB (vengono letti solo 2 MB totali per file).

### Fase 4 — Archiviazione su WORM

Il servizio `wazuh-immutable-store` esegue ciclicamente (orario o giornaliero, configurabile) il processo di archiviazione:

1. **Compressione**: i log della finestra temporale di interesse vengono raccolti in un archivio tar e compressi con gzip livello 6
2. **Checksum**: calcolo SHA-256 dell'archivio compresso, salvato in `.sha256` companion
3. **Firma GPG**: detached signature dell'archivio, salvata in `.sig` companion (RSA 4096 o Ed25519)
4. **Manifest globale**: registrazione nella catena di hash concatenati di tutti gli archivi prodotti
5. **Transfer**: trasferimento NFSv4 verso la shared folder WORM del NAS

Convenzione di nomenclatura: `wazuh-logs-{YYYY-MM-DD}[-{HH}].tar.gz` + companion file `.sig` e `.sha256`.

### Fase 5 — Lock immutable a livello firmware

La shared folder di destinazione sul NAS è configurata in modalità **WORM Enterprise** con:

- **Retention period** vincolata (es. 12 mesi, 24 mesi, 7 anni a seconda del cliente)
- **Auto-lock period** breve (consigliato ≤ 5 minuti dalla scrittura)

Dopo l'auto-lock period, qualunque tentativo di:

- cancellazione (`rm`, `DELETE` su SMB, etc.) → rigettato a livello firmware
- modifica del contenuto (`write`, `append`, …) → scrittura silenziosamente droppata, contenuto invariato
- modifica metadata → eventualmente accettata (es. `chmod`), ma non altera contenuti né firme

Nemmeno l'utente `root` del client NFS può aggirare la protezione: il lock è applicato a livello filesystem del NAS, indipendentemente dai privilegi del chiamante.

### Fase 6 — Protezione complementare via snapshot ZFS

Il volume ZFS sottostante la shared folder offre un layer di protezione complementare:

- **Snapshot atomici** (microsecondi di blocco scritture)
- **Read-only nativo** sugli snapshot
- **Checksum end-to-end** su ogni blocco letto → bit-rot detection automatica
- **Recovery point-in-time** verso qualsiasi snapshot conservato

Policy raccomandata: snapshot giornalieri (30 retention), settimanali (12 retention), mensili (12 retention).

---

## 4. Garanzie crittografiche

### 4.1 Hash chain SHA-256

Ogni archivio è registrato nel manifest globale come riga:

```
<sha256_archivio>  <nome_file>  <dimensione>  <iso_timestamp>  PREV:<hash_archivio_precedente>
```

La voce "PREV" rende impossibile alterare retroattivamente un archivio senza alterare tutti i successivi: una modifica al contenuto rompe il checksum, e la rottura si propaga per tutta la catena fino alla fine del manifest. Il primo elemento ha `PREV:GENESIS`.

La verifica della chain è eseguita dal comando di sistema in modo non distruttivo e produce esito booleano (chain integra / chain rotta) con identificazione della riga corrotta.

### 4.2 Firma digitale GPG

Ogni archivio è firmato con una chiave RSA 4096 bit (o Ed25519, a scelta) dedicata esclusivamente alla firma degli archivi Wazuh. La firma è **detached** (salvata in file `.sig` separato), permettendo verifica indipendente con la sola chiave pubblica.

Proprietà garantite dalla firma:
- **Autenticità**: dimostra che l'archivio è stato prodotto dal sistema autorizzato
- **Non ripudio**: la firma è verificabile da chiunque possieda la chiave pubblica, anche dopo anni e indipendentemente dal server di origine

La chiave pubblica viene replicata in tre posizioni per garantirne la disponibilità:
1. Sulla shared folder WORM stessa (`wazuh-archive-pubkey.asc`)
2. Nel vault aziendale del gestore
3. In cassaforte fisica del cliente

### 4.3 Composite hash rolling

Sui file live mutabili, il rolling hash usa una formula composta che bilancia velocità e copertura:

```
composite_5min = sha256( head_1MB || 0x00 || tail_1MB || 0x00 || ascii(size) )
```

| Tipo di manomissione | Rilevata da |
|---|---|
| Riscrittura intero file | Sì (head e tail cambiano) |
| Iniezione eventi falsi (append) | Sì (tail e size cambiano) |
| Cancellazione eventi (truncate) | Sì (size cambia) |
| Modifica eventi all'inizio del file | Sì (head cambia) |
| Modifica a metà file (>1MB da head e da tail) | Solo se size cambia |

L'ultimo caso è teoricamente possibile ma altamente improbabile in contesti reali, perché Wazuh scrive log in append-only sulla coda — qualunque modifica retroattiva senza variazione di size richiederebbe accesso privilegiato al filesystem e conoscenza esatta dell'offset originale del log da alterare.

---

## 5. Gestione del materiale crittografico

### 5.1 Algoritmo e posizione della chiave

- **Algoritmo**: RSA 4096 bit (consigliato) o Ed25519 (alternativa moderna, più compatta)
- **Posizione**: `/root/.gnupg/` del server Wazuh, permessi `0700` directory e `0600` file privati
- **UID identificativo**: `wazuh-archive@<hostname>`
- **Uso esclusivo**: firma degli archivi. Mai usata per cifratura, autenticazione SSH o altre operazioni

### 5.2 Passphrase

La chiave è generata **senza passphrase** per consentire l'automazione non-interattiva del timer di archiviazione. Questo trade-off è documentato e compensato dai seguenti controlli:

- Accesso SSH al server solo via chiave pubblica (no password)
- Privilegi sudo NOPASSWD ristretti a singolo utente operativo
- Server in rete privata, non esposto a Internet
- Mount NFS ristretto per IP (solo il server Wazuh può scrivere sullo storage WORM)
- Audit log filesystem raccomandato su `/root/.gnupg/`

Per ambienti con requisiti più stringenti è disponibile la roadmap di hardening verso **hardware token** (YubiKey 5 NFC con applet OpenPGP, Nitrokey HSM 2) — vedi sezione 5.7.

### 5.3 Backup della chiave privata

La chiave privata viene esportata in formato ASCII armored e cifrata con algoritmo simmetrico **AES-256** con passphrase forte (≥20 caratteri, generata casualmente). Il file cifrato risultante è custodito in tre posizioni ridondate:

| Custodia | Posizione | Responsabile |
|---|---|---|
| Primaria | Vault aziendale del gestore (1Password, Bitwarden, KeePassXC) | IT Manager gestore |
| Secondaria | USB cifrato VeraCrypt in cassaforte fisica del gestore | IT Manager gestore |
| Terziaria | Copia consegnata al cliente in cassaforte propria | IT Manager cliente |

La verifica di integrità dei backup è raccomandata con cadenza semestrale: import test su sistema isolato, registrazione esito nel registro operativo della sicurezza.

### 5.4 Certificato di revoca

Al momento del provisioning della chiave viene generato proattivamente un **certificato di revoca**. Il certificato è custodito **separatamente** dalla chiave privata (è la chiave per "uccidere" la chiave in caso di compromise), tipicamente nelle stesse tre posizioni del backup ma in entry distinte.

Il certificato viene utilizzato solo in caso di emergenza confermata. La sua importazione e distribuzione rendono pubblica la revoca: qualunque destinatario della chiave pubblica può quindi rifiutare tutte le firme successive.

### 5.5 Politica di rotazione

| Tipo | Frequenza | Trigger |
|---|---|---|
| **Ordinaria** | 24 mesi | Allineata al doppio della retention WORM |
| **Straordinaria** | Variabile (vedi sotto) | Evento specifico |

Trigger straordinari:

- Compromise sospetto o confermato del server (target < 24 ore)
- Cessazione del referente IT con accesso al server (entro 30 giorni)
- Vulnerabilità crittografica nota sull'algoritmo in uso
- Modifica strutturale del setup (migrazione hardware, sostituzione SIEM)

Procedura di rotazione ordinaria:

1. Generazione nuova chiave RSA 4096 con UID versionato
2. Periodo di sovrapposizione di 30 giorni: la chiave nuova firma gli archivi nuovi, la chiave vecchia rimane sul keyring solo per la verifica degli archivi storici
3. Distribuzione della nuova chiave pubblica su tutte le posizioni (vault, cassaforte, share WORM)
4. Dopo 30 giorni: rimozione della chiave vecchia dal keyring di firma (resta nei backup per la verifica)

### 5.6 Procedura di revoca di emergenza

In caso di compromise confermato:

1. Importare il certificato di revoca su un sistema fidato (`gpg --import revoke.asc`)
2. Distribuire la chiave pubblica revocata in tutte le posizioni dove era pubblicata
3. Sospendere immediatamente il timer di archiviazione (`systemctl stop wazuh-immutable-store.timer`)
4. Generare e deployare nuova chiave
5. Notifica formale del compromise al cliente e all'auditor, con report sull'estensione temporale del rischio
6. Re-firma facoltativa degli archivi prodotti durante la finestra di compromise sospetto

### 5.7 Roadmap di hardening — hardware token

Misure raccomandate per ambienti con requisiti audit più stringenti:

| Misura | Beneficio | Costo indicativo |
|---|---|---|
| Auditd con watch su `/root/.gnupg/` | Log immutabile di ogni accesso alla chiave | Gratuito, 30 min config |
| Migrazione su YubiKey 5 NFC (OpenPGP applet) | Chiave privata NON risiede sul filesystem; compromise server non espone chiave | ~55 EUR/token, 2 token ridondati |
| Migrazione su Nitrokey HSM 2 | Idem YubiKey, certificazione CC EAL5+ | ~130 EUR/token |
| Passaggio ad algoritmo Ed25519 | Chiavi più piccole, performance superiori, robustezza equivalente | Rotazione ordinaria |

---

## 6. Mitigazione della finestra di esposizione

L'archiviazione su WORM è per natura un'operazione batch (oraria, giornaliera): tra una scrittura su WORM e la successiva esiste una finestra in cui i log "live" sono ancora modificabili sul filesystem locale.

La soluzione adotta una strategia combinata per ridurre questa finestra:

### 6.1 Archive frequente (orario consigliato)

L'esecuzione del ciclo di archiviazione viene schedulata con frequenza oraria (anziché giornaliera): la finestra di manomissione preventiva scende da 24 ore a 1 ora.

Trade-off accettato:
- 24 archivi/giorno invece di 1 → +24× file sulla shared folder, comunque trascurabili in spazio (singolo archivio orario di pochi MB)
- Compressione meno efficiente sui singoli file orari (ratio scende da ~170:1 giornaliero a ~80:1 orario, comunque eccellente)

### 6.2 Hash chain rolling ogni 5 minuti

In aggiunta all'archive batch, viene eseguito ogni 5 minuti il rolling hash dei file live (vedi §3 Fase 3). Questa operazione **non sposta dati su WORM** ma costruisce una catena di evidenza:

- Se un attaccante manomette un file live tra due cicli di archive (es. tra le 02:00 e le 02:05), il successivo hash composito rileva la modifica
- La chain rotta è permanente e tracciabile: dimostra che si è verificato un evento di manomissione, anche se i log alterati sono già stati archiviati

| Finestra | Modello batch puro | Con archive orario + rolling 5 min |
|---|---|---|
| Manomissione preventiva | 24 ore | **1 ora** |
| Manomissione rilevativa | 7 giorni (al successivo verify) | **5 minuti** |

### 6.3 Estensione opzionale: forwarding real-time esterno

Per requisiti di compliance massimi (PCI-DSS Level 1, SOC2 Type II, settori finance/sanità), la soluzione supporta l'estensione con forwarding parallelo verso un secondo sink immutable:

- Wazuh → secondo manager esterno in colocation/cloud (via syslog)
- Wazuh → OpenSearch cluster con Index Lifecycle Management write-block
- Wazuh → S3 Object Lock (AWS / MinIO con WORM)

Questa modalità garantisce immutabilità preventiva in tempo reale, al costo di setup e manutenzione di una seconda infrastruttura.

---

## 7. Procedure di audit e verifica

Tutti i comandi sono non distruttivi: la verifica non altera in alcun modo gli archivi immutabili.

### 7.1 Verifica integrità on-demand del manifest archive

```bash
sudo wazuh-immutable-store verify
```

Esegue: verifica firma GPG di tutti gli archivi, controllo SHA-256 di ciascun archivio rispetto al companion `.sha256`, validazione della chain di hash concatenati nel manifest globale.

Esito atteso: `All integrity checks passed`.

### 7.2 Verifica del rolling hash chain

```bash
sudo wazuh-rolling-verify
```

Esegue: verifica firma GPG del manifest rolling, validazione della chain (ogni PREV deve coincidere col hash della voce precedente).

Esito atteso: `Firma GPG valida` + `Chain integra`.

### 7.3 Verifica automatica programmata

Il sistema esegue automaticamente una verifica completa ogni domenica alle 06:00 UTC. L'esito è registrato nei log di sistema:

```bash
sudo journalctl -u wazuh-immutable-store-verify.service --since "7 days ago"
```

### 7.4 Verifica indipendente da parte di terzi

Un auditor esterno, dotato della chiave pubblica esportata, può verificare in autonomia l'autenticità di qualunque archivio senza accesso al sistema in produzione:

```bash
gpg --import wazuh-archive-pubkey.asc
gpg --verify wazuh-logs-2026-05-26-14.tar.gz.sig wazuh-logs-2026-05-26-14.tar.gz
sha256sum -c wazuh-logs-2026-05-26-14.tar.gz.sha256
```

Esito atteso: `Good signature from "Wazuh Archive Signer"` + `OK` per sha256.

### 7.5 Test difensivo (audit dimostrativo)

Per dimostrare il funzionamento del WORM in fase di audit, è possibile tentare deliberatamente una manomissione su un file già lockato:

```bash
sudo rm /mnt/qnap-wazuh/2026/05/wazuh-logs-2026-05-25-12.tar.gz
# Atteso: rm: cannot remove ...: Operation not permitted
```

Il rifiuto è la prova che la protezione WORM è attiva.

---

## 8. Scenari di recovery

### 8.1 Recovery selettivo per intervallo temporale

```bash
sudo wazuh-immutable-store recover \
    --start AAAA-MM-GG \
    --end AAAA-MM-GG \
    --output /tmp/recovery
```

Estrae, decomprime e verifica gli archivi compresi nell'intervallo specificato. Gli archivi originali non vengono toccati.

### 8.2 Ricerca per pattern

```bash
sudo wazuh-immutable-store search --pattern "<regex>"
sudo wazuh-immutable-store search --pattern "rule.id:5710"
sudo wazuh-immutable-store search --pattern "srcip:192.168.1.100"
```

### 8.3 Browser interattivo

```bash
sudo wazuh-immutable-store browse
sudo wazuh-immutable-store browse --date 2026-05-26
sudo wazuh-immutable-store browse --date 2026-05-26 --agent "web-server-01"
```

### 8.4 Esportazione in formato analizzabile

```bash
sudo wazuh-immutable-store export --start AAAA-MM-GG --end AAAA-MM-GG --format json --output out.json
sudo wazuh-immutable-store export --start AAAA-MM-GG --end AAAA-MM-GG --format csv --output out.csv
```

### 8.5 Disaster recovery — perdita totale del server Wazuh

In caso di perdita del server applicativo (hardware failure, ransomware, disastro):

1. Provisioning di un nuovo server con stack Wazuh
2. Import della **chiave privata** dal backup cifrato (con la passphrase custodita separatamente)
3. Re-mount della shared folder WORM (gli archivi storici sono integri e immutabili)
4. Riconfigurazione del servizio `wazuh-immutable-store` con i parametri originali
5. Ripresa del ciclo di archiviazione

Tempo di recovery atteso: 2-4 ore (dipende dalla disponibilità di backup recenti del database Wazuh).

### 8.6 Disaster recovery — perdita totale del NAS / storage WORM

Scenario più critico. Mitigazioni in ordine di efficacia:

1. **Snapshot ZFS** locali (se NAS parzialmente recuperabile): rollback all'ultimo snapshot integro
2. **Replica off-site** (se configurata): switch al NAS replicato
3. **Recovery dal backup degli archivi locali sul server Wazuh** (max 7 giorni di history, secondo `days_keep_local`)
4. Archivi precedenti ai 7 giorni: irrecuperabili se non c'è replica off-site

Per ambienti con requisiti DR stringenti è raccomandata la configurazione di replica HBS 3 / rsync da NAS primario a NAS secondario.

---

## 9. Mappatura controlli ↔ standard di compliance

| Standard / Norma | Controllo / requisito | Implementazione |
|---|---|---|
| **ISO/IEC 27001:2022** | A.8.15 — Logging | Raccolta integrale eventi Wazuh con `logall+logall_json`. Conservazione configurabile su WORM. |
| **ISO/IEC 27001:2022** | A.8.16 — Monitoring activities | Manager Wazuh con regole di correlazione e archiviazione automatica dei dati grezzi |
| **ISO/IEC 27001:2022** | A.8.24 — Use of cryptography | Chiave GPG dedicata, custodia in tre posizioni, rotazione documentata, certificato di revoca pre-generato |
| **ISO/IEC 27001:2022** | A.5.28 — Collection of evidence | Catena di custodia preservata via WORM + firma GPG + hash chain. Verifica indipendente con sola chiave pubblica |
| **Direttiva NIS2 (UE 2022/2555)** | Art. 21 §2(g) — Politiche di sicurezza incidenti | Conservazione immutabile delle evidenze digitali di incidenti per il periodo regolamentare |
| **GDPR (Reg. UE 2016/679)** | Art. 32 — Sicurezza del trattamento | Integrità (firma+hash), disponibilità (snapshot+recovery), riservatezza (accesso ristretto al solo server autorizzato) |
| **GDPR (Reg. UE 2016/679)** | Art. 30 — Registro dei trattamenti | Tracciabilità completa degli accessi alle risorse monitorate, conservata in forma immutabile |
| **PCI-DSS v4.0** | Req. 10.5 — Protect audit logs | WORM hardware impedisce modifica e cancellazione. Auto-lock breve limita la finestra di esposizione |
| **PCI-DSS v4.0** | Req. 10.7 — Retention 12 mesi | Retention WORM configurabile e non aggirabile (solo allungabile) |
| **TISAX** | 1.2.4 — Gestione del ciclo di vita delle chiavi | Backup multi-sede, rotazione documentata, revoca pre-generata, RACI delle responsabilità |

---

## 10. Glossario

| Termine | Significato |
|---|---|
| **WORM** | Write Once Read Many. Modalità di scrittura che permette di scrivere dati una sola volta; le scritture successive (modifiche, cancellazioni) sono rigettate dal firmware fino alla scadenza della retention. |
| **Retention period** | Periodo durante il quale i dati WORM sono inalterabili. Configurabile alla creazione della share, può essere allungato in qualsiasi momento, mai ridotto. |
| **Auto-lock period** | Finestra temporale tra la chiusura di un file scritto e il suo lock immutable. Trascorso questo periodo, il file diventa WORM. |
| **Hash chain** | Sequenza di hash crittografici in cui ogni elemento contiene il riferimento all'hash dell'elemento precedente. Una modifica retroattiva a un elemento rompe tutti i successivi. |
| **Detached signature** | Firma digitale salvata in un file separato dal contenuto firmato. Permette la verifica indipendente con la sola chiave pubblica. |
| **GENESIS** | Marker convenzionale per indicare l'inizio di una hash chain (la prima entry non ha un predecessore). |
| **Composite hash** | Hash crittografico calcolato su una combinazione di porzioni di un file (es. head + tail + size) per ottimizzare le prestazioni su file molto grandi mantenendo elevata sensibilità alle modifiche. |
| **Chain of custody** | Catena di custodia. Documentazione che dimostra che le evidenze digitali sono state preservate da manomissioni tra il momento della raccolta e il momento dell'analisi. |
| **Non ripudio** | Proprietà crittografica per cui chi ha firmato un documento non può successivamente negare di averlo fatto. |
| **EPS** | Events Per Second. Metrica di throughput del SIEM. |
| **ZFS** | Filesystem transazionale con copy-on-write, checksum end-to-end, snapshot atomici e compressione nativa. |
| **NFSv4** | Network File System versione 4. Protocollo di condivisione file di rete. |

---

## Riferimenti tecnici

- Codice sorgente: <https://github.com/grandir66/wazuh-immutable-store>
- Documentazione tecnica completa: `README.md` del repository
- Setup QNAP: `docs/QNAP_SETUP.md`
- Wizard di installazione: `scripts/install-wizard.sh`
- Script di manutenzione interattivo: `scripts/maintenance.sh`

## Licenza

MIT License — vedi `LICENSE` del repository.
