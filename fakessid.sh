#!/bin/bash

INTERFACE="wlan1mon"
FULL_LIST="wifi.lst"
PID_FILE="mdk4_fake.pid"

# Check if mdk4 is installed
command -v mdk4 >/dev/null 2>&1 || { 
  echo "❌ mdk4 not found. Install mdk4."
  exit 1
}

# Check if SSID list exists
if [ ! -f "$FULL_LIST" ]; then
  echo "❌ SSID list not found: $FULL_LIST"
  exit 1
fi

echo "🚀 Broadcasting all fake SSIDs from '$FULL_LIST' on interface $INTERFACE..."

# Launch mdk4 in background and save PID
sudo mdk4 "$INTERFACE" b -f "$FULL_LIST" &
echo $! > "$PID_FILE"

echo "✅ Broadcast running in background. PID: $(cat $PID_FILE)"
