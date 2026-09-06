---
badge: Maturo
tono: ok
famiglia: 04-wazuh
ordine: 100
stato: fermo
prossimo: verificare la retention degli snapshot OpenSearch→MinIO e il POC TrueNAS WORM
---
Archiviazione immutabile dei log Wazuh su QNAP WORM: firma GPG, hash chain SHA256, retention e verifica via systemd.

nota: Clone locale v1 rimosso il. Resta `wazuh-immutable-store-v2/`.

Struttura corretta il 3 settembre: il repo stava nel sottolivello `wazuh-immutable-store-v2/`, come DA-Zabbix in `tool/`. Ora la cartella del progetto è il repo.

Il repository è **pubblico di proposito**: licenza MIT, README scritto per estranei, nessun dato cliente. Verificato il 4 settembre — codice, documentazione e history sono puliti, gli IP sono esempi e i `token=` sono nomi di parametro. Non riaprire la domanda senza un motivo nuovo.
