#!/bin/bash

HOTSPOT_IFACE="wlan0"
UPLINK_IFACE="eth0"
HOTSPOT_IP="192.168.50.1"
SSID_NAME="Hola-Fiber🚀"
WPA_PASS="12345678"

# Determine script directory (where Kali_modified.py and mac_blocks.rules are stored)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_RULES_FILE="$SCRIPT_DIR/mac_blocks.rules"

# Run check
if [[ $EUID -ne 0 ]]; then
   echo "❌ Please run as root (use sudo)"
   exit 1
fi

echo "⚙ Configuring static IP..."
ip link set $HOTSPOT_IFACE down
ip addr flush dev $HOTSPOT_IFACE
ip addr add $HOTSPOT_IP/24 dev $HOTSPOT_IFACE
ip link set $HOTSPOT_IFACE up

echo "🌐 Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "💾 Backing up existing MAC block rules to $MAC_RULES_FILE..."
iptables-save | grep "DROP.*--mac-source" > "$MAC_RULES_FILE"

echo "🛡 Resetting iptables..."
iptables -F
iptables -t nat -F
iptables -X

echo "🛡 Setting default DROP policies..."
iptables -P FORWARD DROP

# Deny all forwarding from hotspot interface by default
iptables -A FORWARD -i "$HOTSPOT_IFACE" -j DROP

# Allow DNS and DHCP for devices to connect and get IP
iptables -A INPUT -i $HOTSPOT_IFACE -p udp --dport 67:68 -j ACCEPT
iptables -A INPUT -i $HOTSPOT_IFACE -p udp --dport 53    -j ACCEPT

# Allow internet routing for approved traffic (once allowed by Python)
iptables -A FORWARD -i $HOTSPOT_IFACE -o $UPLINK_IFACE -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i $UPLINK_IFACE -o $HOTSPOT_IFACE -j ACCEPT
iptables -t nat -A POSTROUTING -o $UPLINK_IFACE -j MASQUERADE

echo "♻ Restoring MAC block rules from $MAC_RULES_FILE..."
if [[ -s "$MAC_RULES_FILE" ]]; then
    while IFS= read -r rule; do
        iptables $rule
    done < "$MAC_RULES_FILE"
else
    echo "ℹ No saved MAC block rules found."
fi

echo "🔁 Starting dnsmasq and hostapd..."
systemctl restart dnsmasq
systemctl restart hostapd

echo "✅ Hotspot '$SSID_NAME' active on $HOTSPOT_IFACE ($HOTSPOT_IP)"
echo "⚠ All devices are blocked from internet until approved by Kali_modified.py."
