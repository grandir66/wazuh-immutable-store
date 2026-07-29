#!/usr/bin/env bash
# Installa l'endpoint di stato: utente dedicato, certificato, token, unit systemd.
# Idempotente: rieseguirlo non rigenera token né certificato se già presenti.
set -euo pipefail

STATE_DIR="/var/lib/wazuh-immutable-store"
CONF_DIR="/etc/wazuh-immutable-store"
CERT="$CONF_DIR/status-cert.pem"
KEY="$CONF_DIR/status-key.pem"
TOKEN_FILE="$CONF_DIR/status-token"
UTENTE="wis-status"

[[ $EUID -eq 0 ]] || { echo "Serve root"; exit 1; }

id -u "$UTENTE" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$UTENTE"

mkdir -p "$STATE_DIR" "$CONF_DIR"
chown root:"$UTENTE" "$STATE_DIR"
# Setgid: il timer di rinfresco scrive state.json come root (deve leggere
# mount e log), non come "$UTENTE". Senza setgid il file erediterebbe il
# gruppo primario di root e il servizio di sola lettura (che gira come
# "$UTENTE") non potrebbe più aprirlo nonostante la ownership root:"$UTENTE"
# della directory.
chmod 2750 "$STATE_DIR"
chown root:"$UTENTE" "$CONF_DIR"
chmod 750 "$CONF_DIR"

# Sanatoria: se state.json esiste già da un'installazione precedente (creato
# prima che questo script impostasse il setgid, o da un rerun), riallinea
# gruppo e permessi invece di aspettare la prossima scrittura del timer.
if [[ -f "$STATE_DIR/state.json" ]]; then
  chown root:"$UTENTE" "$STATE_DIR/state.json"
  chmod 640 "$STATE_DIR/state.json"
fi

if [[ ! -f "$TOKEN_FILE" ]]; then
  head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_' > "$TOKEN_FILE"
  echo "Token generato in $TOKEN_FILE"
fi
chown root:"$UTENTE" "$TOKEN_FILE"
chmod 640 "$TOKEN_FILE"

if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=$(hostname)/O=wazuh-immutable-store" \
    -addext "subjectAltName=IP:$(hostname -I | awk '{print $1}')"
  echo "Certificato generato in $CERT"
fi
chown root:"$UTENTE" "$CERT" "$KEY"
chmod 640 "$CERT" "$KEY"

install -m 644 systemd/wazuh-immutable-store-status.service /etc/systemd/system/
install -m 644 systemd/wazuh-immutable-store-refresh.service /etc/systemd/system/
install -m 644 systemd/wazuh-immutable-store-refresh.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wazuh-immutable-store-refresh.timer
systemctl enable --now wazuh-immutable-store-status.service

echo
echo "Fatto. Impronta del certificato da configurare in DA-IPAM:"
openssl x509 -in "$CERT" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
echo "Token: $(cat "$TOKEN_FILE")"
echo
echo "Ricorda di aprire la porta 9443 SOLO verso l'IP del DA-IPAM, ad esempio:"
echo "  ufw allow from <IP-DA-IPAM> to any port 9443 proto tcp"
