import pyrebase
import time
# firebase_config_template.py
firebase_config = {
    "apiKey": "YOUR_FIREBASE_API_KEY",  # Get this from Firebase console
    "authDomain": "YOUR_PROJECT.firebaseapp.com",  # Replace with your project
    "databaseURL": "https://YOUR_PROJECT.firebaseio.com",  # Replace with your database URL
    "projectId": "YOUR_PROJECT_ID",
    "storageBucket": "YOUR_PROJECT.appspot.com",
    "messagingSenderId": "YOUR_SENDER_ID",
    "appId": "YOUR_APP_ID"
}

firebase = pyrebase.initialize_app(firebase_config)
db = firebase.database()

def get_command():
    return db.child("commands").get().val()

def clear_command():
    db.child("commands").remove()

def push_device(mac, data):
    mac_key = mac.replace(":", "_")
    db.child("devices").child(mac_key).update(data)

def push_pending_device(mac, device_data):
    mac_key = mac.replace(":", "_")
    db.child("pending_devices").child(mac_key).set(device_data)

def get_pending_device_status(mac):
    mac_key = mac.replace(":", "_")
    return db.child("pending_devices").child(mac_key).child("status").get().val()

def remove_pending_device(mac):
    mac_key = mac.replace(":", "_")
    db.child("pending_devices").child(mac_key).remove()

def sanitize_string(value):
    """Replace problematic characters."""
    if value is None:
        return "unknown"
    return value.replace(".", ".").replace('"', "'").strip()

def clean_authorization_value(raw):
    import re
    if not isinstance(raw, str):
        return ""
    raw = raw.strip()
    raw = re.sub(r'^[\'"\\]+|[\'"\\]+$', '', raw)
    while raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1].strip()
    return raw.lower().strip()

def log_dns_query_firebase(mac, ip, domain, timestamp, user_agent="Unknown"):
    mac_key = mac.replace(":", "_")  # MAC still kept as key
    existing_entries = db.child("dns_queries").child(mac_key).get().val()
    count = len(existing_entries) if existing_entries else 0

    db.child("dns_queries").child(mac_key).child(str(count)).set({
        "mac": mac,
        "ip": ip,
        "domain": sanitize_string(domain),
        "timestamp": timestamp,
        "user_agent": sanitize_string(user_agent)
    })

def log_http_access_firebase(mac, ip, domain, timestamp, user_agent="Unknown"):
    mac_key = mac.replace(":", "_")  
    existing_entries = db.child("insecure_http_access").child(mac_key).get().val()
    count = len(existing_entries) if existing_entries else 0

    db.child("insecure_http_access").child(mac_key).child(str(count)).set({
        "mac": mac,
        "ip": ip,
        "domain": sanitize_string(domain),
        "timestamp": timestamp,
        "user_agent": sanitize_string(user_agent)
    })

def push_alert(alert_type, message, ip=None, mac=None):
    db.child("alerts").push({
        "type": alert_type,
        "message": message,
        "ip": ip or "unknown",
        "mac": mac or "unknown",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

def push_dashboard(active, inactive, unauthorized):
    total = active + inactive  + unauthorized
    db.child("dashboard").set({
        "active": active,
        "inactive": inactive,
        "unauthorized": unauthorized,
        "total": total,  
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

def log_mitm_attack(ip_or_mac: str, related: list, attack_type: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    db.child("mitm_attacks").push({
        "timestamp": timestamp,
        "target": ip_or_mac,
        "related": ",".join(related),
        "attack_type": attack_type
    })

def log_dos_attack_firebase(attack_type, ip, mac, packet_count):
    mac_key = mac.replace(":", "_")
    existing_entries = db.child("dos_attacks").child(mac_key).get().val()
    count = len(existing_entries) if existing_entries else 0

    db.child("dos_attacks").child(mac_key).child(str(count)).set({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "attack_type": attack_type,
        "ip": ip,
        "mac": mac,
        "packet_count": packet_count
    })

def get_global_blocked_domains():
    try:
        data = firebase.database().child("blocked_domains").get().val()
        return {domain.replace("_", ".").lower() for domain, enabled in data.items() if enabled} if data else set()
    except Exception as e:
        print(f"[ERROR] Fetching global blocked domains: {e}")
        return set()
