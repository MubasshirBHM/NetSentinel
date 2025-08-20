import subprocess
from firebase_config import firebase, get_global_blocked_domains

BLOCKLIST_PATH = "/etc/dnsmasq.d/blocklist.conf"

def write_blocklist(domains: set):
    try:
        with open(BLOCKLIST_PATH, "w") as f:
            for domain in sorted(domains):
                f.write(f"address=/{domain}/0.0.0.0\n")
        print(f"[✔] Updated {BLOCKLIST_PATH} with {len(domains)} domains.")
    except Exception as e:
        print(f"[❌] Error writing blocklist: {e}")

def restart_dnsmasq():
    try:
        subprocess.run(["sudo", "systemctl", "restart", "dnsmasq"], check=True)
        print("[✔] dnsmasq restarted.")
    except subprocess.CalledProcessError as e:
        print(f"[❌] Failed to restart dnsmasq: {e}")

def update_dnsmasq_from_firebase():
    domains = get_global_blocked_domains()
    write_blocklist(domains)
    restart_dnsmasq()

def stream_handler(message):
    print(f"[⚠️] Firebase change detected → Type: {message['event']}")
    update_dnsmasq_from_firebase()

def main():
    print("[🔍] Listening for real-time updates from Firebase...")
    db = firebase.database()
    my_stream = db.child("blocked_domains").stream(stream_handler)
    return my_stream

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[✋] Listener stopped by user.")
