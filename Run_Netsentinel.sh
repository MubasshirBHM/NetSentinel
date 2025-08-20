#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source .venv/bin/activate

echo "🚀 Starting Realtime Blocklist Listener..."
python3 realtime_blocklist_listener.py &

echo "🚀 Starting NetSentinel main app..."
exec python3 kali_modified.py
