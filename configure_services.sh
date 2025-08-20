#!/usr/bin/env bash
set -euo pipefail

# One-time setup for hotspot services on Debian/Ubuntu/Kali
# - Unmasks/enables hostapd + dnsmasq
# - Writes sane configs for both (wlan0, 192.168.50.0/24)
# - Ensures IPv4 forwarding
# - Keeps NetworkManager from fighting over wlan0
# - Avoids dnsmasq startup race by using bind-dynamic

HOTSPOT_IFACE="wlan0"
HOTSPOT_IP="192.168.50.1"
SSID_NAME="Hola-Fiber🚀"   # change to ASCII if your adapter dislikes UTF-8
WPA_PASS="12345678"        # 8+ chars

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "❌ Run as root: sudo bash $0"; exit 1
  fi
}

apt_install() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "❌ This script supports apt-based systems only."; exit 1
  fi
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    hostapd dnsmasq iproute2 iptables network-manager
}

unmask_enable_services() {
  echo "🔧 Unmasking/enabling services..."
  systemctl unmask hostapd || true
  systemctl unmask dnsmasq || true
  systemctl enable hostapd || true
  systemctl enable dnsmasq || true
}

maybe_disable_systemd_resolved() {
  # If systemd-resolved is holding port 53, stop/disable it
  if systemctl is-active --quiet systemd-resolved; then
    echo "🛑 systemd-resolved is active; disabling to free port 53..."
    systemctl stop systemd-resolved || true
    systemctl disable systemd-resolved || true
    # Set a static resolv.conf so the host can still resolve
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
  fi
}

configure_hostapd() {
  echo "📝 Writing /etc/hostapd/hostapd.conf ..."
  cat > /etc/hostapd/hostapd.conf <<EOF
interface=${HOTSPOT_IFACE}
driver=nl80211
ssid=${SSID_NAME}
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0

wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=${WPA_PASS}
EOF

  # Point hostapd daemon to that file
  if [ -f /etc/default/hostapd ]; then
    sed -i '/^#\?DAEMON_CONF=/d' /etc/default/hostapd
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
  fi
}

configure_dnsmasq() {
  echo "📝 Writing /etc/dnsmasq.d/netsentinel.conf ..."
  mkdir -p /etc/dnsmasq.d
  cat > /etc/dnsmasq.d/netsentinel.conf <<EOF
# Serve DHCP & DNS only on the AP interface
interface=${HOTSPOT_IFACE}

# Bind dynamically so dnsmasq can start even if ${HOTSPOT_IFACE} IP not up yet
bind-dynamic

# DHCP pool on 192.168.50.0/24
dhcp-range=192.168.50.10,192.168.50.200,255.255.255.0,12h

# Default gateway and DNS handed to clients
dhcp-option=3,${HOTSPOT_IP}
dhcp-option=6,${HOTSPOT_IP}

# Use explicit upstream resolvers for the host
no-resolv
server=1.1.1.1
server=8.8.8.8
EOF

  # Ensure main dnsmasq loads drop-in dir (uncomment/add line)
  if ! grep -q '^conf-dir=/etc/dnsmasq.d,*.conf' /etc/dnsmasq.conf 2>/dev/null; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak.$(date +%s)
    echo -e "\n# Load extra configs\nconf-dir=/etc/dnsmasq.d,*.conf" >> /etc/dnsmasq.conf
  fi

  # Create (empty) blocklist file used by the realtime listener
  touch /etc/dnsmasq.d/blocklist.conf
  chmod 644 /etc/dnsmasq.d/blocklist.conf
}

enable_ip_forwarding() {
  echo "🌐 Enabling IPv4 forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
}

tame_networkmanager() {
  # Keep NetworkManager from managing the AP device (prevents conflicts)
  echo "🧭 Marking ${HOTSPOT_IFACE} unmanaged in NetworkManager..."
  mkdir -p /etc/NetworkManager/conf.d
  cat > /etc/NetworkManager/conf.d/100-unmanaged-wlan0.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${HOTSPOT_IFACE}
EOF
  systemctl restart NetworkManager || true
}

restart_services() {
  echo "🔍 Validating dnsmasq config..."
  dnsmasq --test

  echo "🔁 Restarting dnsmasq and hostapd..."
  # Restart dnsmasq first; hostapd can start even before IP assignment
  systemctl restart dnsmasq || {
    echo "⚠️ dnsmasq restart failed. Check with: journalctl -xeu dnsmasq.service"
    false
  }
  systemctl restart hostapd || {
    echo "⚠️ hostapd restart failed. Check with: journalctl -xeu hostapd.service"
    false
  }
  echo "✅ Services restarted."
}

final_tips() {
  cat <<EOF

✅ Hotspot services configured.

Next steps:
  1) run this command -->>>   sudo bash Start_Hotspot.sh
  2) after "sudo bash Start_Hotspot.sh" command run this command -->>>   sudo bash Run_Netsentinel.sh

EOF
}

main() {
  check_root
  apt_install
  unmask_enable_services
  maybe_disable_systemd_resolved
  configure_hostapd
  configure_dnsmasq
  enable_ip_forwarding
  tame_networkmanager
  restart_services
  final_tips
}
main "$@"
