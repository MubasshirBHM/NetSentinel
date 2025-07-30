#!/bin/bash

echo "────────────────────────────────────"
echo "🔧 NetSentinel Installer Script"
echo "────────────────────────────────────"
sleep 1

# ── System Requirements ───────────────────────────────
echo "[1/6] Installing system dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tcpdump aircrack-ng hostapd conntrack net-tools

# ── Python Requirements ───────────────────────────────
echo "[2/6] Installing Python packages..."

# Optional: create virtual environment
# python3 -m venv venv
# source venv/bin/activate

pip3 install --upgrade pip
pip3 install pyrebase4 scapy requests flask pandas schedule matplotlib tk colorama pyfiglet rich

# ── File Permissions ──────────────────────────────────
echo "[3/6] Setting permissions for scripts..."

if [ -f "./fakessid.sh" ]; then
    chmod +x fakessid.sh
else
    echo "#!/bin/bash
airbase-ng -e \"FreeWiFi\" -c 6 wlan0mon" > fakessid.sh
    chmod +x fakessid.sh
    echo "Created fakessid.sh ✅"
fi

if [ -f "./stopfakessid.sh" ]; then
    chmod +x stopfakessid.sh
else
    echo "#!/bin/bash
pkill airbase-ng" > stopfakessid.sh
    chmod +x stopfakessid.sh
    echo "Created stopfakessid.sh ✅"
fi

# ── Network Interface Warning ─────────────────────────
echo "[4/6] Checking for monitor mode support..."
iwconfig 2>&1 | grep -i "monitor" >/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️ Warning: Your adapter may not support monitor mode!"
else
    echo "✅ Monitor mode supported."
fi

# ── Directory Check ───────────────────────────────────
echo "[5/6] Creating required directories..."
mkdir -p visit_logs

# ── Final Message ─────────────────────────────────────
echo "[6/6] Installation complete!"
echo "🚀 Run NetSentinel using: sudo python3 kali1.py"
