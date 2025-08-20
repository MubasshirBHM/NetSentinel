#!/bin/bash

HOTSPOT_IFACE="wlan0"

# Run check
if [[ $EUID -ne 0 ]]; then
   echo "❌ Please run as root (use sudo)"
   exit 1
fi

echo "📴 Stopping hotspot services..."
systemctl stop hostapd
systemctl stop dnsmasq

echo "📴 Bringing down interface $HOTSPOT_IFACE..."
ip link set $HOTSPOT_IFACE down

echo "🚫 IP address released from $HOTSPOT_IFACE"
ip addr flush dev $HOTSPOT_IFACE

echo "✅ Hotspot disabled. iptables rules are intact."
