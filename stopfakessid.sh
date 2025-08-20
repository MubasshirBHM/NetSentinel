#!/bin/bash

PID_FILE="mdk4_fake.pid"

echo "🛑 Stopping fake SSID broadcast..."

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "🔪 Killing PID: $PID"
        sudo kill "$PID"
        rm -f "$PID_FILE"
        echo "✅ Broadcast stopped successfully."
    else
        echo "⚠️ No running process found with PID $PID. Cleaning up."
        rm -f "$PID_FILE"
    fi
else
    echo "⚠️ PID file not found. Attempting fallback..."
    sudo pkill -f "mdk4 .* b"
    echo "✅ Attempted to kill any remaining mdk4 processes."
fi
