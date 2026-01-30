# Configurazione QNAP per Wazuh Immutable Store

Questa guida descrive la configurazione necessaria sul NAS QNAP per abilitare l'archiviazione immutabile dei log Wazuh.

## Prerequisiti

- QNAP NAS con QTS 5.0 o superiore
- Spazio storage sufficiente per la retention desiderata
- Connettività di rete tra server Wazuh e QNAP

## 1. Creazione Storage Pool e Volume WORM

### 1.1 Accesso al pannello di controllo

1. Accedi all'interfaccia web del QNAP
2. Vai su **Storage & Snapshots** → **Storage/Snapshots**

### 1.2 Creazione Storage Pool (se necessario)

1. Click su **Create** → **New Storage Pool**
2. Seleziona i dischi da utilizzare
3. Scegli il tipo di RAID appropriato:
   - **RAID 5**: Buon compromesso prestazioni/ridondanza
   - **RAID 6**: Maggiore protezione (consigliato per dati critici)
   - **RAID 10**: Migliori prestazioni
4. Completa la procedura guidata

### 1.3 Creazione Volume WORM

⚠️ **IMPORTANTE**: Una volta abilitato WORM, i file non possono essere modificati o eliminati fino alla scadenza della retention!

1. Nel Storage Pool, click su **Create** → **New Volume**
2. Seleziona **Thick Volume** (consigliato per WORM)
3. Imposta la dimensione del volume
4. **Abilita WORM**:
   - Spunta "Enable WORM"
   - Imposta il **Retention Period minimo** (es. 2555 giorni = 7 anni)
   - Scegli la modalità:
     - **Compliance**: Nessuno può eliminare (nemmeno admin)
     - **Enterprise**: Admin può eliminare in casi estremi
5. Conferma e crea il volume

```
┌─────────────────────────────────────────────────┐
│          Configurazione WORM                     │
├─────────────────────────────────────────────────┤
│ ☑ Enable WORM                                   │
│                                                 │
│ Retention Period: [2555] days                   │
│                                                 │
│ Mode:                                           │
│   ○ Compliance (immutabile assoluto)            │
│   ● Enterprise (admin può intervenire)          │
│                                                 │
│ Auto-lock after: [0] minutes (immediato)        │
└─────────────────────────────────────────────────┘
```

## 2. Configurazione Shared Folder

### 2.1 Creazione Cartella Condivisa

1. Vai su **Control Panel** → **Shared Folders**
2. Click **Create** → **Shared Folder**
3. Configura:
   - **Nome**: `wazuh-archive`
   - **Volume**: Seleziona il volume WORM creato
   - **Path**: `/wazuh-archive`

### 2.2 Permessi Cartella

1. Nella sezione permessi, crea un utente dedicato:
   - Username: `wazuh-archive-user`
   - Password: [genera password sicura]
2. Assegna permessi **RW** (Read/Write) solo a questo utente
3. Disabilita accesso guest

## 3. Configurazione NFS

### 3.1 Abilitazione Servizio NFS

1. Vai su **Control Panel** → **Network & File Services** → **NFS Service**
2. Abilita **NFS v4** (consigliato)
3. Opzionalmente abilita anche NFS v3 per compatibilità

### 3.2 Configurazione Export NFS

1. Vai su **Shared Folders** → seleziona `wazuh-archive`
2. Click **Edit** → **NFS host access**
3. Aggiungi regola:

```
┌─────────────────────────────────────────────────┐
│           NFS Host Access Rule                   │
├─────────────────────────────────────────────────┤
│ Host/IP: 192.168.1.50                           │
│          (IP del server Wazuh)                  │
│                                                 │
│ Permission: ● Read/Write                        │
│             ○ Read Only                         │
│                                                 │
│ Squash:    ○ No mapping                         │
│            ● Map root to admin                  │
│            ○ Map all to admin                   │
│                                                 │
│ Security: ☑ sys (AUTH_SYS)                      │
│           ☐ krb5                                │
│                                                 │
│ ☑ Enable asynchronous mode                      │
│ ☑ Allow connections from non-privileged ports  │
└─────────────────────────────────────────────────┘
```

4. Applica le modifiche

### 3.3 Verifica Export

Sul QNAP, verifica che l'export sia attivo:

```bash
# Da terminale QNAP (SSH)
showmount -e localhost
```

Output atteso:
```
Export list for localhost:
/wazuh-archive 192.168.1.50
```

## 4. Configurazione Rete

### 4.1 IP Statico (consigliato)

1. **Control Panel** → **Network** → **Interfaces**
2. Configura IP statico per l'interfaccia utilizzata
3. Configura correttamente gateway e DNS

### 4.2 Firewall (se abilitato)

Se il firewall QNAP è attivo, consenti:
- **Porta 2049**: NFS
- **Porta 111**: portmapper/rpcbind
- **Porte 1024-65535**: NFS callback (per NFSv4)

## 5. Test della Configurazione

### 5.1 Test dal Server Wazuh

```bash
# Verifica raggiungibilità
ping 192.168.1.100  # IP del QNAP

# Verifica export NFS
showmount -e 192.168.1.100

# Test mount manuale
mkdir -p /mnt/test-qnap
mount -t nfs4 192.168.1.100:/wazuh-archive /mnt/test-qnap

# Verifica scrittura
echo "test" > /mnt/test-qnap/test.txt
cat /mnt/test-qnap/test.txt

# Cleanup
rm /mnt/test-qnap/test.txt
umount /mnt/test-qnap
```

### 5.2 Verifica WORM

```bash
# Crea file di test
echo "worm test" > /mnt/test-qnap/worm-test.txt

# Attendi il lock WORM (in base alla configurazione)

# Prova a eliminare (dovrebbe fallire)
rm /mnt/test-qnap/worm-test.txt
# Errore atteso: Operation not permitted
```

## 6. Configurazione Avanzata

### 6.1 Snapshot (Opzionale ma Consigliato)

1. **Storage & Snapshots** → **Snapshot**
2. Configura snapshot automatici:
   - **Frequenza**: Giornaliera
   - **Retention**: 30 giorni
   - **Smart snapshot**: Abilita

### 6.2 Replica Remota (Opzionale)

Per disaster recovery, configura replica su secondo QNAP:

1. **HBS 3** → **Sync** → **One-way Sync**
2. Configura destinazione remota
3. Schedula sincronizzazione

### 6.3 Notifiche

1. **Control Panel** → **Notification Center**
2. Configura alert per:
   - Errori disco
   - Spazio insufficiente
   - Errori WORM

## 7. Manutenzione

### 7.1 Monitoraggio Spazio

- Controlla periodicamente lo spazio disponibile
- WORM non permette eliminazione, pianifica dimensionamento adeguato

### 7.2 Verifica Integrità

- Esegui scrub RAID periodici
- Monitora health dei dischi
- Sostituisci dischi degradati tempestivamente

### 7.3 Aggiornamenti

- Mantieni QTS aggiornato
- Verifica changelog prima di aggiornare
- Testa in ambiente di staging se possibile

## 8. Troubleshooting

### Errore: "Permission denied" durante mount

```bash
# Verifica che l'IP sia autorizzato nell'export NFS
# Verifica che l'utente abbia permessi sulla shared folder
# Su QNAP: Control Panel → Shared Folders → Edit → Permissions
```

### Errore: "mount.nfs: access denied by server"

```bash
# Verifica export:
showmount -e QNAP_IP

# Verifica che l'IP del client sia nella lista
# Controlla firewall QNAP
```

### Errore: "stale file handle"

```bash
# Rimonta il filesystem
umount -f /mnt/qnap-wazuh
mount -t nfs4 QNAP_IP:/wazuh-archive /mnt/qnap-wazuh
```

### File non eliminabile (WORM attivo)

Questo è il comportamento previsto! I file rimarranno fino alla scadenza del retention period configurato.

## 9. Checklist Finale

- [ ] Storage Pool creato con RAID appropriato
- [ ] Volume WORM creato con retention corretta
- [ ] Shared folder `wazuh-archive` configurata
- [ ] Utente dedicato creato con permessi appropriati
- [ ] NFS v4 abilitato
- [ ] Export NFS configurato con IP Wazuh
- [ ] Test mount riuscito dal server Wazuh
- [ ] Test scrittura riuscito
- [ ] Verifica WORM funzionante
- [ ] Notifiche configurate
- [ ] Documentato IP QNAP, path export, credenziali

---

**Note Importanti:**

1. La configurazione WORM è **irreversibile** per i file esistenti
2. Dimensiona il volume considerando la retention completa
3. Documenta la configurazione per riferimento futuro
4. Testa sempre in ambiente non produttivo prima
