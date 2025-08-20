#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# NetSentinel setup script (Debian/Ubuntu/Kali)
# Installs system dependencies, sets up Python venv,
# prepares dnsmasq configs, creates .env template,
# and grants capabilities for Scapy packet sniffing.
# ─────────────────────────────────────────────────────────────

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BLOCKLIST_PATH="/etc/dnsmasq.d/blocklist.conf"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: sudo bash $0"
    exit 1
  fi
}

check_apt() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "❌ Only apt-based distros supported (Debian/Ubuntu/Kali)."
    exit 1
  fi
}

install_system_packages() {
  echo "📦 Updating apt package index..."
  apt-get update -y

  echo "📦 Installing system packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-venv python3-pip python3-tk \
    hostapd dnsmasq iptables iproute2 \
    mdk4 \
    net-tools curl git libcap2-bin
}

create_python_venv() {
  echo "🐍 Creating Python virtual environment at $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  echo "⬆️  Upgrading pip/setuptools/wheel..."
  pip install --upgrade pip setuptools wheel

  echo "📦 Installing Python libraries..."
  pip install \
    pyrebase4 requests requests-toolbelt oauth2client pycryptodome \
    scapy==2.* \
    python-dotenv
}

grant_python_caps() {
  echo "🔐 Granting packet sniffing capabilities to venv Python..."
  PYBIN="$(readlink -f "$VENV_DIR/bin/python3")"
  setcap cap_net_raw,cap_net_admin+eip "$PYBIN" || true
  echo "ℹ Run 'getcap $PYBIN' to verify."
}

prepare_dnsmasq_blocklist() {
  echo "🧩 Preparing dnsmasq blocklist..."
  mkdir -p /etc/dnsmasq.d
  touch "$BLOCKLIST_PATH"
  chmod 644 "$BLOCKLIST_PATH"

  if ! grep -q "conf-dir=/etc/dnsmasq.d" /etc/dnsmasq.conf 2>/dev/null; then
    echo "🔧 Adding conf-dir to /etc/dnsmasq.conf ..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s)
    echo -e "\n# Load extra configs\nconf-dir=/etc/dnsmasq.d,*.conf" >> /etc/dnsmasq.conf
  fi

  systemctl enable hostapd || true
  systemctl enable dnsmasq || true
}

create_env_template() {
  ENV_FILE="$REPO_DIR/.env"
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "📝 Creating .env template ..."
    cat > "$ENV_FILE" <<'EOF'
# Firebase Configuration
FIREBASE_API_KEY=your-api-key
FIREBASE_AUTH_DOMAIN=your-project.firebaseapp.com
FIREBASE_DATABASE_URL=https://your-project-id-default-rtdb.firebaseio.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-project.appspot.com
FIREBASE_MESSAGING_SENDER_ID=0000000000
FIREBASE_APP_ID=1:0000000000:web:abcdef123456

# Gmail Alerts (replace before use!)
EMAIL_SENDER=your-email@gmail.com
EMAIL_APP_PASSWORD=your-app-password
EMAIL_RECEIVER=your-email@gmail.com
EOF
    echo "⚠️  Fill in your Firebase + Gmail details in $ENV_FILE"
  fi
}

sanity_tips() {
  echo
  echo "✅ Installation complete!"
  echo
  echo "👉 Next steps:"
  echo "  1) run this command >>>> sudo bash configure_services.sh "
}

main() {
  need_root
  check_apt
  install_system_packages
  create_python_venv
  grant_python_caps
  prepare_dnsmasq_blocklist
  create_env_template
  sanity_tips
}

main "$@"
