#!/bin/bash
#
# Wazuh Immutable Store - Installation Script
# Installa il sistema di archiviazione immutabile
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/wazuh-immutable-store"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/wazuh-immutable-store"
SYSTEMD_DIR="/etc/systemd/system"

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Wazuh Immutable Store - Installer${NC}"
echo -e "${GREEN}============================================${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Errore: Questo script deve essere eseguito come root${NC}"
   exit 1
fi

# Check Python version
echo "Verifico requisiti..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Errore: Python 3 non trovato${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "  Python: ${GREEN}$PYTHON_VERSION${NC}"

# Check required packages
echo "Verifico pacchetti richiesti..."
MISSING_PACKAGES=""

if ! command -v gpg &> /dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES gnupg"
fi

if ! command -v mount.nfs &> /dev/null; then
    MISSING_PACKAGES="$MISSING_PACKAGES nfs-common"
fi

if [ -n "$MISSING_PACKAGES" ]; then
    echo -e "${YELLOW}Pacchetti mancanti:$MISSING_PACKAGES${NC}"
    read -p "Installare i pacchetti mancanti? [S/n] " response
    if [[ "$response" =~ ^([nN][oO]|[nN])$ ]]; then
        echo -e "${RED}Installazione annullata${NC}"
        exit 1
    fi

    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y $MISSING_PACKAGES
    elif command -v yum &> /dev/null; then
        yum install -y $MISSING_PACKAGES
    elif command -v dnf &> /dev/null; then
        dnf install -y $MISSING_PACKAGES
    else
        echo -e "${RED}Package manager non riconosciuto. Installa manualmente:$MISSING_PACKAGES${NC}"
        exit 1
    fi
fi

# Install Python dependencies
echo "Installazione dipendenze Python..."
pip3 install pyyaml --quiet

# Create directories
echo "Creazione directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p /var/log/wazuh-immutable-store
mkdir -p /tmp/wazuh-archive

# Copy files
echo "Copia files..."
cp -r src/* "$INSTALL_DIR/"
cp config/config.yaml.example "$CONFIG_DIR/"

# Create main executable
echo "Creazione eseguibile..."
cat > "$BIN_DIR/wazuh-immutable-store" << 'EOF'
#!/bin/bash
PYTHONPATH=/opt/wazuh-immutable-store python3 /opt/wazuh-immutable-store/main.py "$@"
EOF
chmod +x "$BIN_DIR/wazuh-immutable-store"

# Install systemd services
echo "Installazione servizi systemd..."
cp systemd/*.service "$SYSTEMD_DIR/"
cp systemd/*.timer "$SYSTEMD_DIR/"

# Reload systemd
systemctl daemon-reload

echo
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Installazione completata!${NC}"
echo -e "${GREEN}============================================${NC}"
echo
echo "Prossimi passi:"
echo
echo "1. Esegui il wizard di configurazione:"
echo -e "   ${YELLOW}wazuh-immutable-store setup${NC}"
echo
echo "2. Configura il QNAP (vedi docs/QNAP_SETUP.md)"
echo
echo "3. Abilita i timer systemd:"
echo -e "   ${YELLOW}systemctl enable --now wazuh-immutable-store.timer${NC}"
echo -e "   ${YELLOW}systemctl enable --now wazuh-immutable-store-retention.timer${NC}"
echo -e "   ${YELLOW}systemctl enable --now wazuh-immutable-store-verify.timer${NC}"
echo
echo "4. Verifica lo stato:"
echo -e "   ${YELLOW}wazuh-immutable-store status${NC}"
echo
