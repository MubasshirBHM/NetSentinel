import os
import re
import subprocess
import time
import threading
import socket
import json
from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
from functools import partial
import smtplib
from email.message import EmailMessage
from email.utils import make_msgid
from tkinter import Tk, Toplevel, Label, Button, Frame, ttk, Checkbutton, BooleanVar, Entry, StringVar, messagebox
from firebase_config import (
    push_device,
    push_pending_device,
    get_pending_device_status,
    get_command, 
    clear_command,
    log_dns_query_firebase,
    log_http_access_firebase,
    remove_pending_device,
    push_dashboard,
    log_dos_attack_firebase,
    clean_authorization_value,
    get_global_blocked_domains,
    log_mitm_attack,
    firebase
)
db = firebase.database()
# ───── CONFIG ───────────────────────────────────────────────────────────
CHECK_INTERVAL   = 1                       # seconds between scans
TEMP_BLOCK       = 5000                    # seconds to keep DROP rules
INTERFACE        = "wlan0"                 # hotspot iface (hostapd runs here)
ALLOW_LIST_FILE  = "allowed_macs.txt"
BLOCK_LIST_FILE  = "blocked_macs.txt"
VENDOR_DB_FILE   = "./vendor_db/oui.txt"            # Path to MAC vendor database file
blocked_ips = set()
EMAIL_SENDER = "your_email@example.com"             # Add the sender email address used for sending alerts
EMAIL_RECEIVER = ["receiver_email@example.com"]     # Add the list of recipient emails to receive alerts
REAL_APP_PASSWORD = "your_app_specific_password"    # Add your email app-specific password or use environment variable
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 465
# ────────────────────────────────────────────────────────────────────────
run = lambda cmd: os.popen(cmd).read()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEDULE_FILE = os.path.join(BASE_DIR, "mac_schedules.json")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSECURE_SITE_FILE = os.path.join(BASE_DIR, "insecure_sites.txt")
try:
    with open(INSECURE_SITE_FILE) as f:
        INSECURE_URLS = {line.strip().lower() for line in f if line.strip()}
except FileNotFoundError:
    INSECURE_URLS = set()
    print("[WARN] insecure_sites.txt not found. Insecure check will be skipped.")
# ─── Device Info Helpers ────────────────────────────────────────────────
def get_ip_from_mac(mac: str) -> str:
    out = run(f"arp -n | grep '{mac}'")
    match = re.search(r"\d+\.\d+\.\d+\.\d+", out)
    return match.group(0) if match else "Unknown"

popup_windows = {}

def get_hostname(mac: str) -> str:
    try:
        with open("/var/lib/misc/dnsmasq.leases") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[1].lower() == mac.lower():
                    return parts[3] if parts[3] != "*" else "Unknown"
    except Exception:
        pass
    ip = get_ip_from_mac(mac)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def get_os_guess(ip: str) -> str:
    try:
        ttl = int(run(f"ping -c 1 {ip} | grep ttl=").split("ttl=")[1].split()[0])
        if ttl >= 128:
            return "Windows"
        elif ttl >= 64:
            return "Linux/Unix"
        elif ttl >= 255:
            return "Cisco/Networking Device"
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

def load_vendor_map(path: str) -> dict:
    vendor_map = {}
    try:
        with open(path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    key = parts[0].upper()
                    vendor = " ".join(parts[1:])
                    vendor_map[key] = vendor
    except FileNotFoundError:
        print(f"[ERROR] Vendor DB file not found: {path}")
    return vendor_map

VENDOR_LOOKUP = load_vendor_map(VENDOR_DB_FILE)

def get_vendor(mac: str) -> str:
    prefix = mac.upper().replace(":", "")[:6]
    return VENDOR_LOOKUP.get(prefix, "Unknown")

def get_geo_location(ip: str) -> str:
    try:
        import requests
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = resp.json()
        return f"{data.get('city', 'Unknown')}, {data.get('region', '')}, {data.get('country', '')}"
    except Exception:
        return "Unknown"
        
def monitor_pending_device_status(ctl, root,refresh_device_log):
    processed_macs = set()
    while True:
        try:
            all_pending = db.child("pending_devices").get().val()
            if all_pending:
                for mac_key, data in all_pending.items():
                    mac = mac_key.replace("_", ":").lower()
                    if mac in processed_macs:
                        continue

                    status = clean_authorization_value(data.get("status", "")).strip('"').lower()
                    print(f"[PENDING CHECK] {mac} status={status}")

                    if status == "approved" and mac not in ctl.allowed:
                        ctl.allow(mac)
                        log_device_info(mac)
                        device_info = {
                            "mac": mac,
                            "ip": get_ip_from_mac(mac),
                            "vendor": get_vendor(mac)
                        }
                        send_email("Allowed", device_info, REAL_APP_PASSWORD)
                        remove_pending_device(mac)
                        print(f"[REMOTE APPROVED] {mac}")
                        processed_macs.add(mac)
                        if mac in popup_windows:
                            root.after(0, lambda: popup_windows.pop(mac, None).destroy())
                        root.after(0, refresh_device_log)

                    elif status == "denied" and mac not in ctl.blocked:
                        ctl.block(mac)
                        device_info = {
                            "mac": mac,
                            "ip": get_ip_from_mac(mac),
                            "vendor": get_vendor(mac)
                        }
                        send_email("Blocked", device_info, REAL_APP_PASSWORD)
                        remove_pending_device(mac)
                        print(f"[REMOTE DENIED] {mac}")
                        processed_macs.add(mac)
                        if mac in popup_windows:
                            root.after(0, lambda: popup_windows.pop(mac, None).destroy())
                        root.after(0, refresh_device_log)

        except Exception as e:
            print(f"[Error] in monitor_pending_device_status: {e}")
        time.sleep(1)

def parse_browser_from_user_agent(ua: str) -> str:
        ua = ua.lower()

        if "edg" in ua:
            return "Microsoft Edge"
        elif "opr" in ua or "opera" in ua:
            return "Opera"
        elif "vivaldi" in ua:
            return "Vivaldi"
        elif "chrome" in ua and "edg" not in ua and "brave" not in ua:
            return "Google Chrome"
        elif "brave" in ua:
            return "Brave"
        elif "firefox" in ua:
            return "Mozilla Firefox"
        elif "safari" in ua and "chrome" not in ua:
            return "Safari"
        elif "samsungbrowser" in ua:
            return "Samsung Internet"
        elif "duckduckgo" in ua:
            return "DuckDuckGo"
        elif "ucbrowser" in ua:
            return "UC Browser"
        elif "puffin" in ua:
            return "Puffin"
        elif "maxthon" in ua:
            return "Maxthon"
        elif "qqbrowser" in ua:
            return "QQBrowser"
        elif "bingpreview" in ua:
            return "Bing Preview"
        elif "yabrowser" in ua or "yandex" in ua:
            return "Yandex Browser"
        else:
            return "Other"

def log_device_info(mac: str) -> dict:
    ip = get_ip_from_mac(mac)
    hostname = get_hostname(mac)
    os_type = get_os_guess(ip)
    vendor = get_vendor(mac)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    allowed_set = load_set(ALLOW_LIST_FILE)
    blocked_set = load_set(BLOCK_LIST_FILE)
    is_active = mac in get_connected_macs()

    status = "Allowed" if mac in allowed_set else "Blocked" if mac in blocked_set else "Unknown"
    auth = "authorized" if mac in allowed_set else "blocked" if mac in blocked_set else "unauthorized"
    active_flag = "active" if is_active else "inactive"

    # Load last seen + usage + conn/disconn if exists
    log_dir = os.path.join(BASE_DIR, "visit_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "device_logs.txt")

    usage = 0
    conn_count = 0
    disconn_count = 0
    connected_time = timestamp

    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            for line in f:
                if mac in line:
                    try:
                        parts = line.split(" | ")
                        usage = int(re.search(r"usage=(\d+)", line).group(1)) if "usage=" in line else 0
                        conn_count = int(re.search(r"conn=(\d+)", line).group(1)) if "conn=" in line else 0
                        disconn_count = int(re.search(r"disc=(\d+)", line).group(1)) if "disc=" in line else 0
                        connected_time = re.search(r"Connected: ([\d\-: ]+)", line).group(1)
                    except:
                        pass
                    break

    # Update counters
    if is_active:
        conn_count += 1
    else:
        disconn_count += 1
    usage += 1

    # Final structure
    device_data = {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "authorization": auth,
        "status": active_flag,
        "connected_time": connected_time,
        "last_seen": timestamp,
        "usage": usage,
        "connection_count": conn_count,
        "disconnection_count": disconn_count,
        "connection_type": "Wireless",
        "os_fingerprint": os_type
    }

    # Push to cloud
    push_device(mac, device_data)

    # Save to disk
    with open(log_path, "a") as f:
        f.write(
            f"Connected: {connected_time} | MAC: {mac} | IP: {ip} | Hostname: {hostname} | "
            f"OS: {os_type} | Vendor: {vendor} | usage={usage} | conn={conn_count} | disc={disconn_count} | status={active_flag} | last_seen={timestamp}\n"
        )

    return {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "os": os_type,
        "vendor": vendor,
        "timestamp": timestamp,
        "status": status,
        "active": "Yes" if is_active else "No"
    }

def refresh_device_status():
    connected = get_connected_macs()
    last_seen_dict = load_last_seen()
    allowed = load_set(ALLOW_LIST_FILE)
    blocked = load_set(BLOCK_LIST_FILE)
    known = allowed | blocked

    for mac in known:
        is_active = mac in connected
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = get_ip_from_mac(mac)
        hostname = get_hostname(mac)
        os_type = get_os_guess(ip)
        vendor = get_vendor(mac)

        auth = "authorized" if mac in allowed else "unauthorized"
        status = "active" if is_active else "inactive"

        # Load previous log details to retain usage counters
        usage = 0
        conn_count = 0
        disconn_count = 0
        connected_time = timestamp
        log_path = os.path.join(BASE_DIR, "visit_logs", "device_logs.txt")

        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                for line in f:
                    if mac in line:
                        try:
                            usage = int(re.search(r"usage=(\d+)", line).group(1)) if "usage=" in line else 0
                            conn_count = int(re.search(r"conn=(\d+)", line).group(1)) if "conn=" in line else 0
                            disconn_count = int(re.search(r"disc=(\d+)", line).group(1)) if "disc=" in line else 0
                            connected_time = re.search(r"Connected: ([\d\-: ]+)", line).group(1)
                        except:
                            pass
                        break

        # Update counters
        if is_active:
            conn_count += 1
        else:
            disconn_count += 1
            update_last_seen(mac, timestamp)  # Set last seen on disconnect

        usage += 1

        # Prepare data
        device_data = {
            "mac": mac,
            "ip": ip,
            "hostname": hostname,
            "vendor": vendor,
            "authorization": auth,
            "status": status,
            "connected_time": connected_time,
            "last_seen": timestamp,
            "usage": usage,
            "connection_count": conn_count,
            "disconnection_count": disconn_count,
            "connection_type": "Wireless",
            "os_fingerprint": os_type
        }

        push_device(mac, device_data)

        # Save to disk
        os.makedirs(os.path.join(BASE_DIR, "visit_logs"), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(
                f"Connected: {connected_time} | MAC: {mac} | IP: {ip} | Hostname: {hostname} | "
                f"OS: {os_type} | Vendor: {vendor} | usage={usage} | conn={conn_count} | disc={disconn_count} | "
                f"status={status} | last_seen={timestamp}\n"
            )

def log_domain_visit(mac: str, ip: str, domain: str, user_agent: str = "Unknown"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = os.path.join(BASE_DIR, "visit_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_dns_query_firebase(mac, ip, domain, timestamp, user_agent)
    with open(os.path.join(log_dir, "domain_visits.log"), "a") as f:
        f.write(f"Timestamp: {timestamp} | MAC: {mac} | IP: {ip} | Domain: {domain} | UA: {user_agent}\n")
    print(f"[VISIT] {mac} accessed {domain} at {timestamp}")

def send_email(subject, mac_info, password):
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content("A new device has been detected on your network.")

        logo_cid = make_msgid(domain="example.com")[1:-1]
        html_body = f"""
        <html>
            <body style="font-family: sans-serif; line-height: 1.6;">
                <p style="font-size: 20px;">🚨🚨🚨 <strong>WARNING ALERT</strong> 🚨🚨🚨</p>
                <p style="font-size: 18px;">⚠️ <strong>A NEW DEVICE has been {subject}!</strong> ⚠️</p>
                <ul>
                    <li><strong>📅 Time:</strong> {timestamp}</li>
                    <li><strong>🔌 MAC Address:</strong> {mac_info['mac']}</li>
                    <li><strong>🌐 IP Address:</strong> {mac_info['ip']}</li>
                    <li><strong>🏢 Vendor:</strong> {mac_info['vendor']}</li>
                </ul>
                <hr />
                <p>🔐 --- NetSentinel --- 🔐</p>
            </body>
        </html>
        """
        msg.add_alternative(html_body, subtype="html")

        with smtplib.SMTP_SSL(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, password)
            smtp.send_message(msg)
    except Exception as e:
        print(f"Email error: {e}")

def log_unsecured_http(mac: str, ip: str, domain: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = os.path.join(BASE_DIR, "visit_logs")
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "http_unsecured.log"), "a") as f:
        f.write(f"[HTTP] {timestamp} | MAC: {mac} | IP: {ip} | Domain: {domain} (unsecured)\n")
    print(f"[UNSECURED HTTP] {mac} visited http://{domain}")


# ─── Networking helpers ────────────────────────────────────────────────
def get_connected_macs() -> set[str]:
    out  = run(f"ip neigh show dev {INTERFACE}")
    macs = re.findall(r"lladdr\s+([0-9a-f:]{17})", out, re.I)
    return {m.lower() for m in macs}

def ip_to_mac(ip: str) -> str:
    out = run(f"arp -n | grep '{ip}'")
    match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", out, re.I)
    return match.group(1).lower() if match else None

def monitor_dns_queries(controller):
    cmd = f"tcpdump -l -i {INTERFACE} port 53 -nn -v"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    for line in iter(process.stdout.readline, b''):
        decoded = line.decode("utf-8", errors="ignore")
        match = re.search(r"([\d\.]+)\.\d+ > .*:.* A\? ([\w.-]+)\.?", decoded)
        if match:
            src_ip, domain = match.groups()
            mac = ip_to_mac(src_ip)
            if mac and mac in controller.allowed:
                log_domain_visit(mac, src_ip, domain)

def monitor_global_dns_filtering():
    print("[DNS FILTER] Global domain filtering thread started.")
    import subprocess
    cmd = f"tcpdump -l -i {INTERFACE} port 53 -nn -v"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    blocked_domains = set()
    last_update = 0

    while True:
        line = process.stdout.readline()
        if not line:
            continue

        decoded = line.decode("utf-8", errors="ignore")
        match = re.search(r"([\d\.]+)\.\d+ > .*:.* A\? ([\w\.-]+)\.?", decoded)
        if not match:
            continue

        src_ip, domain = match.groups()
        domain = domain.lower()
        mac = ip_to_mac(src_ip)

        # Refresh blocked domain list every 10 seconds
        if time.time() - last_update > 10:
            blocked_domains = get_global_blocked_domains()
            last_update = time.time()

        if any(domain.endswith(b) for b in blocked_domains):
            print(f"[DNS BLOCKED] {mac or src_ip} → {domain}")
            if mac:
                add_drop_rules(mac)
                time.sleep(10)
                remove_drop_rules(mac)


def monitor_http_requests(controller):
    # Monitor HTTP (unsecured) requests on port 80
    cmd = f"tcpdump -l -i {INTERFACE} port 80 -nn -A"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    current_mac = None
    current_ip = None
    dest_ip = None
    domain_or_ip = None
    user_agent = None
    requested_path = None
    buffer = []

    for line in iter(process.stdout.readline, b''):
        decoded = line.decode("utf-8", errors="ignore").strip()

        # Track source IP and destination IP
        if "IP" in decoded and ">" in decoded and "HTTP" not in decoded:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.\d+", decoded)
            if match:
                current_ip, dest_ip = match.groups()
                current_mac = ip_to_mac(current_ip)
                domain_or_ip = None
                user_agent = None
                requested_path = None
                buffer = []

        # Capture HTTP GET requests
        if decoded.startswith("GET "):
            parts = decoded.split()
            if len(parts) > 1:
                requested_path = parts[1]  # e.g., "/index.html" or "/"

        # Accumulate HTTP header lines
        if current_mac:
            buffer.append(decoded)

            if decoded == "":
                for entry in buffer:
                    if entry.lower().startswith("host:"):
                        domain_or_ip = entry.split(":", 1)[1].strip()
                    elif entry.lower().startswith("user-agent:"):
                        user_agent = entry.split(":", 1)[1].strip()

                # Fallback to destination IP if no Host header
                if not domain_or_ip and dest_ip:
                    domain_or_ip = dest_ip

                if domain_or_ip and requested_path:
                    full_url = f"http://{domain_or_ip}{requested_path}"
                    if current_mac in controller.allowed:
                        browser = parse_browser_from_user_agent(user_agent or "")
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        print(f"[HTTP ALERT] Logging to Firebase: {full_url} from {current_ip} ({current_mac})")

                        # 1. Local log
                        log_unsecured_http(current_mac, current_ip, full_url)

                        # 2. Firebase logs
                        log_http_access_firebase(current_mac, current_ip, full_url, timestamp, f"{browser} | {user_agent or 'Unknown'}")
                        log_domain_visit(current_mac, current_ip, full_url, f"{browser} | {user_agent or 'Unknown'}")

                # Reset after processing
                domain_or_ip = None
                user_agent = None
                requested_path = None
                buffer = []

dos_active = False  # Global tracker

def inspect_http_requests_with_scapy(controller):
    print("[INFO] Scapy HTTP monitor started...")

    def process_packet(packet):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            data = packet[Raw].load
            try:
                http_payload = data.decode(errors='ignore')
                if http_payload.startswith(("GET", "POST", "HEAD", "OPTIONS")):
                    lines = http_payload.split("\r\n")
                    request_line = lines[0]  # e.g. "GET /index.html HTTP/1.1"
                    path = request_line.split()[1] if len(request_line.split()) > 1 else "/"
                    host = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("host:")), None)
                    ua = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("user-agent:")), "Unknown")

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    mac = ip_to_mac(src_ip) or "UNKNOWN"
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                    # Construct full URL
                    url = f"http://{host}{path}" if host else f"http://{dst_ip}{path}"
                    browser = parse_browser_from_user_agent(ua)

                    if mac in controller.allowed:
                        print(f"[HTTP DETECT] {mac} → {url}")
                        log_domain_visit(mac, src_ip, url, f"{browser} | {ua}")

                        # ✅ Only send to Firebase if the URL is in the insecure_sites.txt list
                        if url.lower().startswith("http://") and any(site in url.lower() for site in INSECURE_URLS):
                            log_http_access_firebase(mac, src_ip, url, timestamp, f"{browser} | {ua}")
                            log_unsecured_http(mac, src_ip, url)

            except Exception as e:
                print(f"[ERROR] Packet parse failed: {e}")
    sniff(filter="tcp port 80", prn=process_packet, store=0)

def detect_dos_attack():
    global dos_active
    print("[INFO] Starting DoS detection (ICMP + TCP SYN + UDP)...")

    # Capture ICMP, TCP SYN, and UDP in one tcpdump
    cmd = f"tcpdump -l -i {INTERFACE} icmp or tcp[tcpflags] & tcp-syn != 0 or udp"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    icmp_count = 0
    syn_count = 0
    udp_count = 0

    ip_sources = {}  # ip -> count per second
    start_time = time.time()

    while True:
        line = process.stdout.readline()
        if not line:
            continue

        decoded = line.decode("utf-8", errors="ignore")

        # Extract IP
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*>", decoded)
        src_ip = match.group(1) if match else "Unknown"

        # ICMP detection
        if "ICMP" in decoded:
            icmp_count += 1
            ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1

        # TCP SYN detection
        elif "Flags [S]" in decoded:
            syn_count += 1
            ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1

        # UDP flood detection
        elif "UDP" in decoded:
            udp_count += 1
            ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1

        # Check every second
        if time.time() - start_time >= 1:
            alerts = []
            if icmp_count > 300:
                alerts.append(f"ICMP Flood: {icmp_count} pps")
            if syn_count > 300:
                alerts.append(f"TCP SYN Flood: {syn_count} pps")
            if udp_count > 400:
                alerts.append(f"UDP Flood: {udp_count} pps")

            if alerts and not dos_active:
                dos_active = True
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n🛑 DoS Attack Detected at {now}")
                for a in alerts:
                    print(f" - {a}")
                for ip, count in ip_sources.items():
                    mac = ip_to_mac(ip) or "N/A"
                    print(f"Source IP: {ip}, Packets: {count}, MAC: {mac}")
                log_dos_attack(ip_sources)

            elif not alerts and dos_active:
                print("[INFO] DoS activity has subsided.")
                dos_active = False

            # Reset counts
            icmp_count = syn_count = udp_count = 0
            ip_sources = {}
            start_time = time.time()

def detect_mitm_attack():
    print("[INFO] Starting MITM detection (MAC and ARP spoofing)...")

    seen_mac_to_ip = {}
    seen_ip_to_mac = {}

    while True:
        output = subprocess.getoutput("arp -n | grep -v incomplete")
        mac_to_ips = {}
        ip_to_macs = {}

        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[2].lower()
                # MAC to multiple IPs (MAC spoofing)
                mac_to_ips.setdefault(mac, set()).add(ip)
                # IP to multiple MACs (ARP spoofing)
                ip_to_macs.setdefault(ip, set()).add(mac)

        # Check for MAC spoofing (same MAC, multiple IPs)
        # MAC Spoofing: same MAC used by multiple IPs
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1 and mac not in seen_mac_to_ip:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n🛑 [MITM WARNING] MAC Spoofing Detected at {timestamp}")
                print(f"[VICTIM] MAC: {mac}")

                legit_ip = None
                allowed_macs = load_set(ALLOW_LIST_FILE)

                if mac in allowed_macs:
                    legit_ip = next(iter(ips))
                    legit_hostname = get_hostname(mac)
                    print(f"   → Legitimate IP: {legit_ip}")
                    print(f"   → Hostname: {legit_hostname}")
                else:
                    print("   → Legitimate MAC not in allow list.")

                for ip in ips:
                    if ip != legit_ip:
                        attacker_host = get_hostname(mac)
                        print(f"[ATTACKER] MAC: {mac} | IP: {ip} | Hostname: {attacker_host}")

                # Log to Firebase and local
                log_mitm_attack(mac, list(ips), "MAC Spoofing")
                with open("visit_logs/mitm_alerts.log", "a") as f:
                    f.write(f"{timestamp} | MAC Spoofing detected: {mac} → {', '.join(ips)}\n")

                seen_mac_to_ip[mac] = ips
                # Check for ARP spoofing (same IP, multiple MACs)
        for ip, macs in ip_to_macs.items():
            if len(macs) > 1 and ip not in seen_ip_to_mac:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n🛑 [MITM WARNING] ARP Spoofing Detected at {timestamp}")
                print(f"[VICTIM] IP: {ip}")

                legit_mac = None
                for mac in macs:
                    if mac in load_set(ALLOW_LIST_FILE):
                        legit_mac = mac
                        break

                if legit_mac:
                    legit_hostname = get_hostname(legit_mac)
                    print(f"   → Legitimate MAC: {legit_mac}")
                    print(f"   → Hostname: {legit_hostname}")
                else:
                    print("   → Legitimate device not found in allow list.")

                for mac in macs:
                    if mac != legit_mac:
                        attacker_ip = get_ip_from_mac(mac)
                        attacker_host = get_hostname(mac)
                        print(f"[ATTACKER] MAC: {mac} | IP: {attacker_ip} | Hostname: {attacker_host}")

                # Log to Firebase and disk
                log_mitm_attack(ip, list(macs), "ARP Spoofing")
                with open("visit_logs/mitm_alerts.log", "a") as f:
                    f.write(f"{timestamp} | ARP Spoofing detected: {ip} → {', '.join(macs)}\n")

                seen_ip_to_mac[ip] = macs
        time.sleep(1)

def activate_fake_ssid():
    script = "./scripts/fakessid.sh"  # Path to fake SSID script used for deauth attacks
    if os.path.exists(script):
        print("[ACTION] Starting fake SSID...")
        subprocess.Popen(["bash", script])
    else:
        print(f"[ERROR] Script not found at: {script}")

def deactivate_fake_ssid():
    script = "/home/cicada/Desktop/Net Sentinel/stopfakessid.sh"
    if os.path.exists(script):
        print("[ACTION] Stopping fake SSID...")
        subprocess.call(["bash", script])
    else:
        print(f"[ERROR] Script not found at: {script}")

def block_ip(ip):
    try:
        subprocess.call(f"iptables -A INPUT -s {ip} -j DROP", shell=True)
        print(f"[BLOCKED] IP {ip} has been blocked via iptables.")
    except Exception as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")

def log_dos_attack(ip_counts: dict):
    # 🔧 Build IP → MAC mapping from ARP table
    ip_mac_mapping = {}
    arp_output = subprocess.getoutput("arp -n | grep -v incomplete")
    for line in arp_output.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            ip = parts[0]
            mac = parts[2].lower()
            ip_mac_mapping[ip] = mac

    # 🚨 Log each detected DoS attack
    for ip, count in ip_counts.items():
        mac = ip_mac_mapping.get(ip, "00:00:00:00:00:00")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        attack_type = "UDP Flood"  # You can adjust this dynamically if needed

        # ✅ Local log file
        with open("visit_logs/dos_attacks.log", "a") as f:
            f.write(f"{timestamp} | {attack_type} detected from {ip} ({mac}) | Packets: {count}\n")

        # ✅ Firebase structured logging
        log_dos_attack_firebase(attack_type, ip, mac, count)


def ipt_rule(mac: str) -> str:
    return f"-m mac --mac-source {mac} -j DROP"

def rule_exists(chain: str, mac: str) -> bool:
    sig = f"-A {chain} {ipt_rule(mac)}"
    return sig in subprocess.getoutput("iptables-save")

def add_drop_rules(mac: str):
    for chain in ("INPUT", "FORWARD"):
        if not rule_exists(chain, mac):
            subprocess.call(f"iptables -I {chain} {ipt_rule(mac)}", shell=True)
    subprocess.call(f"iptables -I INPUT -p udp --dport 67:68 {ipt_rule(mac)}", shell=True)
    subprocess.call(f"iptables -I INPUT -p udp --dport 53    {ipt_rule(mac)}", shell=True)

def remove_drop_rules(mac: str):
    for chain in ("INPUT", "FORWARD"):
        while rule_exists(chain, mac):
            subprocess.call(f"iptables -D {chain} {ipt_rule(mac)}", shell=True)

    # Remove DNS and DHCP specific blocks
    subprocess.call(f"iptables -D INPUT -p udp --dport 67:68 {ipt_rule(mac)}", shell=True)
    subprocess.call(f"iptables -D INPUT -p udp --dport 53 {ipt_rule(mac)}", shell=True)

    # Flush active connections from conntrack
    ip = get_ip_from_mac(mac)
    if ip != "Unknown":
        subprocess.call(f"conntrack -D -s {ip}", shell=True)
    # Flush active connections from conntrack after allowing

def disconnect_wifi(mac: str):
    subprocess.call(f"hostapd_cli -i {INTERFACE} deauthenticate {mac}", shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def accept_rule_exists(mac: str) -> bool:
    sig = f"-A FORWARD -m mac --mac-source {mac} -j ACCEPT"
    return sig in subprocess.getoutput("iptables-save")

# ─── Persistence helpers ───────────────────────────────────────────────
def load_set(path: str) -> set[str]:
    try:
        with open(os.path.join(BASE_DIR, path)) as f:
            return {l.strip().lower() for l in f if l.strip()}
    except FileNotFoundError:
        return set()

def get_device_status(mac):
    allowed = load_set(ALLOW_LIST_FILE)
    blocked = load_set(BLOCK_LIST_FILE)
    if mac in allowed:
        return "authorized"
    elif mac in blocked:
        return "unauthorized"
    else:
        return "unknown"


def save_set(data: set[str], path: str):
    with open(os.path.join(BASE_DIR, path), "w") as f:
        f.write("\n".join(sorted(data)) + "\n")

def load_schedules():
    if os.path.exists(SCHEDULE_FILE):
        with open(SCHEDULE_FILE, "r") as f:
            return json.load(f)
    return {}

NAME_FILE = os.path.join(BASE_DIR, "mac_names.json")

def load_names() -> dict:
    if os.path.exists(NAME_FILE):
        import json
        with open(NAME_FILE, "r") as f:
            return json.load(f)
    return {}

def save_name(mac: str, name: str):
    import json
    names = load_names()
    names[mac.lower()] = name
    with open(NAME_FILE, "w") as f:
        json.dump(names, f)

LAST_SEEN_FILE = os.path.join(BASE_DIR, "last_seen.json")

def load_last_seen() -> dict:
    if os.path.exists(LAST_SEEN_FILE):
        import json
        with open(LAST_SEEN_FILE, "r") as f:
            return json.load(f)
    return {}

def update_last_seen(mac: str, timestamp: str):
    import json
    last_seen = load_last_seen()
    last_seen[mac.lower()] = timestamp
    with open(LAST_SEEN_FILE, "w") as f:
        json.dump(last_seen, f)


def save_mac_iptables_rules():
    """Save current DROP MAC rules to mac_blocks.rules so the Bash script can restore them."""
    rules = subprocess.getoutput("iptables-save")
    lines = [line for line in rules.splitlines() if "--mac-source" in line and "-j DROP" in line]
    with open(os.path.join(BASE_DIR, "mac_blocks.rules"), "w") as f:
        f.write("\n".join(lines) + "\n")

def force_remove_mac(mac: str, ctl):
    """Immediately disconnect and clean up MAC-related rules and schedules (custom standalone logic)."""
    print(f"[FORCE REMOVE] Removing {mac} from network...")

    # Step 1: Deauth
    subprocess.call(f"hostapd_cli -i {INTERFACE} deauthenticate {mac}", shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Step 2: Remove iptables DROP rules
    for chain in ("INPUT", "FORWARD"):
        rule = f"-m mac --mac-source {mac} -j DROP"
        while rule in subprocess.getoutput("iptables-save"):
            subprocess.call(f"iptables -D {chain} {rule}", shell=True)

    # Remove DNS/DHCP rules
    for port in ["67:68", "53"]:
        rule = f"-p udp --dport {port} -m mac --mac-source {mac} -j DROP"
        while rule in subprocess.getoutput("iptables-save"):
            subprocess.call(f"iptables -D INPUT {rule}", shell=True)

    # Step 3: Remove ACCEPT rule
    accept_rule = f"-m mac --mac-source {mac} -j ACCEPT"
    while accept_rule in subprocess.getoutput("iptables-save"):
        subprocess.call(f"iptables -D FORWARD {accept_rule}", shell=True)

    # Step 4: Clear conntrack state
    ip = get_ip_from_mac(mac)
    if ip != "Unknown":
        subprocess.call(f"conntrack -D -s {ip}", shell=True)

    # Step 5: Remove from allowed/blocked sets
    ctl.allowed.discard(mac)
    ctl.blocked.discard(mac)
    save_set(ctl.allowed, ALLOW_LIST_FILE)
    save_set(ctl.blocked, BLOCK_LIST_FILE)

    # Step 6: Remove schedule
    schedules = load_schedules()
    if mac.lower() in schedules:
        del schedules[mac.lower()]
        with open(SCHEDULE_FILE, "w") as f:
            json.dump(schedules, f, indent=2)

    # Step 7: Save iptables snapshots
    save_mac_iptables_rules()
    save_mac_accept_rules()

    print(f"[FORCE REMOVE] Cleanup complete for {mac}")

def save_mac_accept_rules():
    """Save current ACCEPT MAC rules to mac_accept.rules for later restoration."""
    rules = subprocess.getoutput("iptables-save")
    lines = [line for line in rules.splitlines() if "--mac-source" in line and "-j ACCEPT" in line]
    with open(os.path.join(BASE_DIR, "mac_accept.rules"), "w") as f:
        f.write("\n".join(lines) + "\n")

# ─── GUI prompt ────────────────────────────────────────────────────────
class Prompt(Toplevel):
    def __init__(self, root, info, allow_cb, block_cb):
        super().__init__(root)
        self.mac = info['mac'].lower()  # Normalize MAC
        popup_windows[self.mac] = self  # Register popup
        self.allow_cb, self.block_cb = allow_cb, block_cb
        self.title("New Device Detected")

        Label(self, text=f"MAC: {info['mac']}", font=("Arial", 12)).pack(pady=4)
        Label(self, text=f"IP: {info['ip']}").pack()
        Label(self, text=f"Hostname: {info['hostname']}").pack()
        Label(self, text=f"OS: {info['os']}").pack()
        Label(self, text=f"Vendor: {info['vendor']}").pack()
        Label(self, text=f"Timestamp: {info['timestamp']}").pack()

        btns = Frame(self); btns.pack(pady=10)
        Button(btns, text="Allow", width=12, command=self.allow).pack(side="left", padx=10)
        Button(btns, text="Block", width=12, command=self.block).pack(side="right", padx=10)

    def allow(self):
        self.allow_cb(self.mac)
        popup_windows.pop(self.mac, None)
        self.destroy()

    def block(self):
        self.block_cb(self.mac)
        popup_windows.pop(self.mac, None)
        self.destroy()


# ─── Controller ────────────────────────────────────────────────────────
class Controller:
    def __init__(self):
        self.allowed = load_set(ALLOW_LIST_FILE)
        self.blocked = load_set(BLOCK_LIST_FILE)
        self.known = self.allowed | self.blocked
        self.internet_disabled = set()       # ⬅️ Track disabled internet state
        self.deauth_threads = {}             # ⬅️ Track ongoing deauth threads
        self.restore_accept_rules()

    def restore_accept_rules(self):
        """Ensure ACCEPT rules for allowed MACs are re-added after reboot."""
        for mac in self.allowed:
            if not accept_rule_exists(mac):
                subprocess.call(f"iptables -I FORWARD -m mac --mac-source {mac} -j ACCEPT", shell=True)
                ip = get_ip_from_mac(mac)
                if ip != "Unknown":
                    subprocess.call(f"conntrack -D -s {ip}", shell=True)

    def allow(self, mac):
        print(f"[ALLOW] {mac}") 

        # 1. Remove all DROP rules first
        remove_drop_rules(mac)

        # 2. Ensure FORWARD ACCEPT rule exists
        if not accept_rule_exists(mac):
            subprocess.call(f"iptables -I FORWARD -m mac --mac-source {mac} -j ACCEPT", shell=True)

        # 3. Remove DNS/DHCP DROP rules again (forcefully)
        for port in ["67:68", "53"]:
            subprocess.call(f"iptables -D INPUT -p udp --dport {port} -m mac --mac-source {mac} -j DROP", shell=True)

        # 4. Clear conntrack sessions
        ip = get_ip_from_mac(mac)
        if ip != "Unknown":
            subprocess.call(f"conntrack -D -s {ip}", shell=True)

        # 5. Update status and persist
        self.allowed.add(mac)
        self.blocked.discard(mac)
        save_set(self.allowed, ALLOW_LIST_FILE)
        save_set(self.blocked, BLOCK_LIST_FILE)

        log_device_info(mac)
        save_mac_iptables_rules()
        save_mac_accept_rules()
        remove_pending_device(mac)

    def block(self, mac):
        print(f"[BLOCK] {mac}")
        disconnect_wifi(mac)
        add_drop_rules(mac)

        # Remove ACCEPT rule if it exists
        subprocess.call(f"iptables -D FORWARD -m mac --mac-source {mac} -j ACCEPT", shell=True)

        # FIX: Remove from allowed list if previously allowed
        self.allowed.discard(mac)
        self.blocked.add(mac)

        save_set(self.allowed, ALLOW_LIST_FILE)
        save_set(self.blocked, BLOCK_LIST_FILE)

        log_device_info(mac)
        save_mac_iptables_rules()
        remove_pending_device(mac)

    def block_many(self, mac_list):
        for mac in mac_list:
            if mac not in self.blocked:
                self.block(mac)

    def popup(self, root, mac):
        mac = mac.lower()
        if mac in popup_windows:
            return  # Already open, skip
        self.known.add(mac)
        info = log_device_info(mac)
        Prompt(root, info, self.allow, self.block)

    def toggle_internet(self, mac):
        """Toggle deauth and internet block/restore state for a MAC."""
        # Cancel ongoing deauth if active
        if mac in self.deauth_threads:
            thread, stop_flag = self.deauth_threads[mac]
            stop_flag.set()
            thread.join(timeout=1)
            del self.deauth_threads[mac]
            print(f"[DEAUTH CANCELLED] for {mac}")

        if mac in self.internet_disabled:
            print(f"[INTERNET RESTORE] {mac}")
            if not accept_rule_exists(mac):
                subprocess.call(f"iptables -I FORWARD -m mac --mac-source {mac} -j ACCEPT", shell=True)
            remove_drop_rules(mac)
            ip = get_ip_from_mac(mac)
            if ip != "Unknown":
                subprocess.call(f"conntrack -D -s {ip}", shell=True)
            self.internet_disabled.discard(mac)
            save_set(self.allowed | {mac}, ALLOW_LIST_FILE)
        else:
            print(f"[INTERNET DISABLE] {mac}")
            disconnect_wifi(mac)
            add_drop_rules(mac)
            subprocess.call(f"iptables -D FORWARD -m mac --mac-source {mac} -j ACCEPT", shell=True)
            self.internet_disabled.add(mac)
            save_set(self.blocked | {mac}, BLOCK_LIST_FILE)

def evaluate_schedules(controller):
    schedules = load_schedules()
    now = datetime.now()
    current_time = now.strftime("%H:%M")
    weekday = now.weekday()  # 0 = Monday, 6 = Sunday

    for mac, config in schedules.items():
        allow_start, allow_end = config.get("allow_time", ["00:00", "23:59"])
        block_weekends = config.get("block_weekends", False)
        is_weekend = weekday >= 5

        in_range = allow_start <= current_time <= allow_end

        if block_weekends and is_weekend:
            controller.block(mac)
        elif in_range and not is_weekend:
            controller.allow(mac)
        else:
            controller.block(mac)

def get_device_counts() -> dict:
    connected = get_connected_macs()
    allowed = load_set(ALLOW_LIST_FILE)
    blocked = load_set(BLOCK_LIST_FILE)
    known = allowed | blocked

    active = set()
    inactive = set()
    unauthorized = set()

    for mac in connected:
        if mac in known:
            active.add(mac)
        else:
            unauthorized.add(mac)

    for mac in known:
        if mac not in connected:
            inactive.add(mac)

    return {
        "active": len(active),
        "inactive": len(inactive),
        "unauthorized": len(unauthorized)
    }

def view_dos_alerts():
    win = Toplevel()
    win.title("DoS Attack Alerts")
    win.geometry("800x400")
    tree = ttk.Treeview(win, columns=["Timestamp", "IP", "MAC", "Packets", "Location"], show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=150)
    tree.pack(expand=True, fill="both")

    try:
        with open(os.path.join(BASE_DIR, "visit_logs", "dos_attacks.log")) as f:
            for line in f:
                parts = re.findall(r"\[(.*?)\].*IP=(.*?), MAC=(.*?), Packets=(\d+)", line)
                if parts:
                    for p in parts:
                        timestamp, ip, mac, count = p
                        location = get_geo_location(ip)
                        tree.insert("", "end", values=(timestamp, ip, mac, count, location))
    except FileNotFoundError:
        messagebox.showinfo("Info", "No DoS logs found.")

def view_mitm_alerts():
    win = Toplevel()
    win.title("MITM Attack Alerts")
    win.geometry("800x400")
    tree = ttk.Treeview(win, columns=["Timestamp", "Type", "Target", "Conflicts"], show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=180)
    tree.pack(expand=True, fill="both")

    try:
        with open(os.path.join(BASE_DIR, "visit_logs", "mitm_alerts.log")) as f:
            for line in f:
                match = re.match(r"\[(.*?)\] \[(.*?)\] (.*?): (.*)", line.strip())
                if match:
                    timestamp, attack_type, target, conflicts = match.groups()
                    tree.insert("", "end", values=(timestamp, attack_type, target, conflicts))
    except FileNotFoundError:
        messagebox.showinfo("Info", "No MITM logs found.")

def view_http_alerts():
    win = Toplevel()
    win.title("Unsecured HTTP Visits")
    win.geometry("900x400")
    tree = ttk.Treeview(win, columns=["Timestamp", "MAC", "IP", "Domain"], show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=200)
    tree.pack(expand=True, fill="both")

    try:
        with open(os.path.join(BASE_DIR, "visit_logs", "http_unsecured.log")) as f:
            for line in f:
                match = re.match(r"\[HTTP\] (.*?) \| MAC: (.*?) \| IP: (.*?) \| Domain: (.*)", line.strip())
                if match:
                    timestamp, mac, ip, domain = match.groups()
                    tree.insert("", "end", values=(timestamp, mac, ip, domain))
    except FileNotFoundError:
        messagebox.showinfo("Info", "No HTTP alert logs found.")

def load_alert_table(mode):
    global alert_tree
    if "alert_tree" not in globals():
        print("[WARN] alert_tree not yet initialized")
        return
    alert_tree.delete(*alert_tree.get_children())

    if mode == "dos":
        try:
            with open(os.path.join(BASE_DIR, "visit_logs", "dos_attacks.log")) as f:
                for line in f:
                    parts = line.split("|")
                    if len(parts) == 3:
                        timestamp = parts[0].strip()
                        attack_type = " ".join(parts[1].strip().split()[:2])  # e.g. "UDP Flood"
                        ip_mac_match = re.search(r"from (.*?) \((.*?)\)", parts[1])
                        if ip_mac_match:
                            ip, mac = ip_mac_match.groups()
                        else:
                            ip, mac = "Unknown", "Unknown"
                        packet_info = parts[2].strip()
                        alert_tree.insert("", "end", values=(timestamp, attack_type, ip, mac, packet_info))
        except FileNotFoundError:
            alert_tree.insert("", "end", values=("N/A", "DoS", "No logs found", "", ""))

    elif mode == "mitm":
        try:
            with open(os.path.join(BASE_DIR, "visit_logs", "mitm_alerts.log")) as f:
                for line in f:
                    match = re.match(r"\[(.*?)\] \[(.*?)\] (.*?): (.*)", line.strip())
                    if match:
                        timestamp, attack_type, target, conflict = match.groups()
                        alert_tree.insert("", "end", values=(timestamp, f"MITM-{attack_type}", target, conflict, ""))
        except FileNotFoundError:
            alert_tree.insert("", "end", values=("N/A", "MITM", "No logs found", "", ""))

    elif mode == "http":
        try:
            with open(os.path.join(BASE_DIR, "visit_logs", "http_unsecured.log")) as f:
                for line in f:
                    match = re.match(r"\[HTTP\] (.*?) \| MAC: (.*?) \| IP: (.*?) \| Domain: (.*)", line.strip())
                    if match:
                        timestamp, mac, ip, domain = match.groups()
                        alert_tree.insert("", "end", values=(timestamp, "HTTP", mac, domain, ip))
        except FileNotFoundError:
            alert_tree.insert("", "end", values=("N/A", "HTTP", "No logs found", "", ""))

# ─── Main loop ─────────────────────────────────────────────────────────
def main():
    root = Tk()
    root.title("NetSentinel Dashboard")
    root.geometry("1400x500")
    ctl = Controller()
    def poll_commands():
        cmd = get_command()
        if cmd:
            print("[REMOTE COMMAND RECEIVED]:", cmd)

            if cmd.strip().lower() == '"start-fake"':
                activate_fake_ssid()
                print("[+] Fake SSID script started.")
            elif cmd.strip().lower() == '"stop-fake"':
                deactivate_fake_ssid()
                print("[-] Fake SSID script stopped.")
            else:
                print("[!] Unknown command received.")

            clear_command()  # Clear after processing
        # Schedule next poll
        root.after(1000, poll_commands)
    poll_commands()

    def schedule_checker():
        evaluate_schedules(ctl)
        root.after(1000, schedule_checker)  # check every second
    schedule_checker()
    previous_connected_macs = set()
    threading.Thread(target=monitor_dns_queries, args=(ctl,), daemon=True).start()
    #threading.Thread(target=monitor_http_requests, args=(ctl,), daemon=True).start()
    threading.Thread(target=inspect_http_requests_with_scapy, args=(ctl,), daemon=True).start()
    threading.Thread(target=detect_dos_attack, daemon=True).start()
    threading.Thread(target=detect_mitm_attack, daemon=True).start()
    threading.Thread(target=monitor_global_dns_filtering, daemon=True).start()

    # Top Buttons
    nav_frame = Frame(root)
    nav_frame.pack(side="top", fill="x", pady=5)
    content_frame = Frame(root)
    content_frame.pack(fill="both", expand=True)

    # Tabs
    tab_control = ttk.Notebook(content_frame)
    alerts_tab = Frame(tab_control)
    device_tab = Frame(tab_control)
    Label(alerts_tab, text="View Detected Alerts", font=("Arial", 14)).pack(pady=5)
    button_frame = Frame(alerts_tab)
    button_frame.pack(pady=5)
    Button(button_frame, text="DoS Alerts", width=20, command=lambda: load_alert_table("dos")).pack(side="left", padx=10)
    Button(button_frame, text="MITM Alerts", width=20, command=lambda: load_alert_table("mitm")).pack(side="left", padx=10)
    Button(button_frame, text="HTTP Alerts", width=20, command=lambda: load_alert_table("http")).pack(side="left", padx=10)
    # Create Treeview (shared for all 3 views)
    alert_cols = ["Timestamp", "Type", "MAC/IP", "Target/Domain", "Info"]
    global alert_tree
    alert_tree = ttk.Treeview(alerts_tab, columns=alert_cols, show="headings")
    for col in alert_cols:
        alert_tree.heading(col, text=col)
        alert_tree.column(col, width=180)
    alert_tree.pack(expand=True, fill="both")

    dns_tab = Frame(tab_control)
    dos_tab = Frame(tab_control)
    tab_control.add(device_tab, text="Device Details")
    tab_control.add(dns_tab, text="DNS Queries")
    tab_control.add(dos_tab, text="DoS Attack")
    tab_control.add(alerts_tab, text="Alerts & Attacks")
    tab_control.pack(expand=True, fill="both")
    # Status Summary Panel
    summary_frame = Frame(content_frame)
    summary_frame.pack(fill="x", pady=5)

    active_label = Label(summary_frame, text="Active Devices: 0", font=("Arial", 11))
    inactive_label = Label(summary_frame, text="Inactive Devices: 0", font=("Arial", 11))
    unauth_label = Label(summary_frame, text="Unauthorized Devices: 0", font=("Arial", 11))

    active_label.pack(side="left", padx=20)
    inactive_label.pack(side="left", padx=20)
    unauth_label.pack(side="left", padx=20)

    # DoS Attack Tab Content
    Label(dos_tab, text="Manual DoS Defense Control", font=("Arial", 14)).pack(pady=20)
    Button(dos_tab, text="Activate DoS Attack Defender", width=30, command=activate_fake_ssid).pack(pady=10)
    Button(dos_tab, text="Deactivate DoS Attack Defender", width=30, command=deactivate_fake_ssid).pack(pady=10)

    def update_device_counts():
        counts = get_device_counts()
        active_label.config(text=f"Active Devices: {counts['active']}")
        inactive_label.config(text=f"Inactive Devices: {counts['inactive']}")
        unauth_label.config(text=f"Unauthorized Devices: {counts['unauthorized']}")
        root.after(1000, update_device_counts)  # refresh every 2 seconds

    def switch_to_devices():
        tab_control.select(device_tab)

    def switch_to_dns():
        tab_control.select(dns_tab)

    Button(nav_frame, text="Device Details", command=switch_to_devices, width=20).pack(side="left", padx=5)
    Button(nav_frame, text="DNS Details", command=switch_to_dns, width=20).pack(side="left", padx=5)
    Button(nav_frame, text="DoS Attack", command=lambda: tab_control.select(dos_tab), width=20).pack(side="left", padx=5)
    Button(nav_frame, text="Alerts/Attacks", command=lambda: tab_control.select(alerts_tab), width=20).pack(side="left", padx=5)

    # ── Device Tab ──
    dev_cols = ["Name", "Timestamp", "MAC", "IP", "Hostname", "OS", "Vendor", "Status", "Active", "Last Seen"]
    dev_xscroll = ttk.Scrollbar(device_tab, orient="horizontal")
    dev_tree = ttk.Treeview(
        device_tab, columns=dev_cols, show="headings", xscrollcommand=dev_xscroll.set
    )
    dev_xscroll.config(command=dev_tree.xview)

    column_widths = {
        "Name": 150,
        "Timestamp": 140,
        "MAC": 160,
        "IP": 130,
        "Hostname": 140,
        "OS": 120,
        "Vendor": 120,
        "Status": 100,
        "Active": 80,
        "Last Seen": 150
    }

    for col in dev_cols:
        dev_tree.heading(col, text=col)
        dev_tree.column(col, width=column_widths.get(col, 120), anchor="w")

    dev_tree.pack(expand=True, fill="both")
    dev_xscroll.pack(side="bottom", fill="x")

    def on_device_click(event):
        selected_item = dev_tree.selection()
        if selected_item:
            values = dev_tree.item(selected_item, "values")
            if not values or len(values) < 2:
                return
            mac = values[2]  # MAC is in the 2nd column

            popup = Toplevel(root)
            popup.title("Action on Device")
            popup.geometry("800x120")

            Label(popup, text=f"Selected MAC:\n{mac}", font=("Arial", 11), pady=10).pack()

            btn_frame = Frame(popup)
            btn_frame.pack(pady=10)

            def do_keep():
                print("[KEEP] Disabling fake SSID broadcast if active.")
                popup.destroy()
                messagebox.showinfo("Deauth Disabled", "Fake SSID broadcast stopped. Device kept.")

            def do_remove():
                timeout_win = Toplevel(popup)
                timeout_win.title("Temporary Deauth")
                timeout_win.geometry("300x130")

                Label(timeout_win, text="Enter deauth duration (minutes):").pack(pady=10)
                entry = Entry(timeout_win, width=10)
                entry.pack(pady=5)

                def confirm_duration():
                    try:
                        minutes = int(entry.get())
                        if minutes <= 0:
                            raise ValueError
                    except ValueError:
                        messagebox.showerror("Invalid Input", "Enter a valid number of minutes.")
                        return

                    duration = minutes * 60
                    stop_time = time.time() + duration
                    stop_flag = threading.Event() 

                    def deauth_loop():
                        print(f"[DEAUTH] Sending deauth packets to {mac} for {minutes} minutes...")
                        while time.time() < stop_time and not stop_flag.is_set():
                            subprocess.call(f"hostapd_cli -i {INTERFACE} deauthenticate {mac}", shell=True,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            time.sleep(1)
                        print(f"[DEAUTH] Ended for {mac}")

                    thread = threading.Thread(target=deauth_loop, daemon=True)
                    ctl.deauth_threads[mac] = (thread, stop_flag)
                    thread.start()
                Button(timeout_win, text="Start", command=confirm_duration).pack(pady=10)

            def do_schedule():
                schedule_win = Toplevel(popup)
                schedule_win.title("Schedule Access")
                schedule_win.geometry("400x250")

                Label(schedule_win, text="Allow From (HH:MM):").pack(pady=5)
                start_var = StringVar()
                Entry(schedule_win, textvariable=start_var).pack()

                Label(schedule_win, text="Allow Until (HH:MM):").pack(pady=5)
                end_var = StringVar()
                Entry(schedule_win, textvariable=end_var).pack()

                weekend_var = BooleanVar()
                Checkbutton(schedule_win, text="Block on Weekends", variable=weekend_var).pack(pady=10)

                # Load existing values if present
                schedules = load_schedules()
                mac_data = schedules.get(mac.lower(), {})
                start_var.set(mac_data.get("allow_time", ["09:00", "18:00"])[0])
                end_var.set(mac_data.get("allow_time", ["09:00", "18:00"])[1])
                weekend_var.set(mac_data.get("block_weekends", False))

                def save_schedule():
                    new_data = {
                        "allow_time": [start_var.get(), end_var.get()],
                        "block_weekends": weekend_var.get()
                    }
                    schedules[mac.lower()] = new_data
                    with open(SCHEDULE_FILE, "w") as f:
                        json.dump(schedules, f, indent=2)
                    schedule_win.destroy()
                    popup.destroy()

                Button(schedule_win, text="Save Schedule", command=save_schedule).pack(pady=15)

            def do_add_name():
                name_win = Toplevel(popup)
                name_win.title("Enter Name/ID")
                name_win.geometry("400x120")

                Label(name_win, text="Enter custom name or ID:").pack(pady=10)
                entry = ttk.Entry(name_win, width=30)
                entry.pack(pady=5)

                def save_input():
                    name = entry.get().strip()
                    if name:
                        save_name(mac, name)
                    name_win.destroy()
                    popup.destroy()
                    refresh_device_log()
                Button(name_win, text="Save", command=save_input).pack(pady=10)

            Button(btn_frame, text="Add Name/ID", width=12, command=do_add_name).pack(side="left", padx=10)
            Button(btn_frame, text="Keep", width=10, command=do_keep).pack(side="left", padx=10)
            Button(btn_frame, text="Remove", width=10, command=do_remove).pack(side="right", padx=10)
            Button(btn_frame, text="Schedule", width=10, command=do_schedule).pack(side="right", padx=10)
            Button(btn_frame, text="Fix Internet", width=12,command=lambda: ctl.toggle_internet(mac)).pack(side="left", padx=10)

    # Bind the double-click event to the device list
    dev_tree.bind("<Double-1>", on_device_click)

    # ── DNS Tab ──
    dns_cols = ["Timestamp", "MAC", "IP", "Domain", "UA"]
    dns_tree = ttk.Treeview(dns_tab, columns=dns_cols, show="headings")
    for col in dns_cols:
        dns_tree.heading(col, text=col)
        dns_tree.column(col, width=120)
    dns_tree.pack(expand=True, fill="both")

    seen_devices = set()
    seen_dns = set()

    def refresh_device_log():
        try:
            dev_tree.delete(*dev_tree.get_children())
            connected = get_connected_macs()
            last_seen_dict = load_last_seen()
            log_path = os.path.join(BASE_DIR, "visit_logs", "device_logs.txt")
            if not os.path.exists(log_path):
                return

            with open(log_path, "r") as f:
                lines = f.readlines()

            displayed_macs = set()

            for line in reversed(lines):
                match = re.search(r"MAC: ([\w:]+)", line)
                if not match:
                    continue
                mac = match.group(1)
                mac_lc = mac.lower()

                if mac_lc in displayed_macs:
                    continue  # Skip duplicate entries in log
                displayed_macs.add(mac_lc)

                ts_match = re.search(r"Connected: ([\d\-: ]+)", line)
                timestamp = ts_match.group(1) if ts_match else "Unknown"

                ip_match = re.search(r"IP: ([\d.]+)", line)
                ip = ip_match.group(1) if ip_match else "Unknown"

                hn_match = re.search(r"Hostname: ([\w\-.]+)", line)
                hostname = hn_match.group(1) if hn_match else "Unknown"

                os_match = re.search(r"OS: ([\w\s\-_/]+)", line)
                os_type = os_match.group(1) if os_match else "Unknown"

                vendor = get_vendor(mac)
                status = get_device_status(mac)
                active = "Yes" if mac_lc in connected else "No"

                # Handle last seen display
                if active == "No":
                    last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    update_last_seen(mac_lc, last_seen)
                    last_seen_display = last_seen
                else:
                    last_seen_display = ""

                dev_tree.insert("", "end", values=[
                    hostname, timestamp, mac, ip,
                    hostname, os_type, vendor, status, active, last_seen_display
                ])
        except Exception as e:
            print(f"[ERROR] refresh_device_log: {e}")


    def refresh_dns_log():
        try:
            with open(os.path.join(BASE_DIR, "visit_logs", "domain_visits.log")) as f:
                for line in f:
                    line = line.strip()
                    if not line or "| " not in line or line in seen_dns:
                        continue
                    seen_dns.add(line)
                    parts = line.split(" | ")
                    values = [p.split(": ", 1)[1] if ": " in p else "" for p in parts]
                    dns_tree.insert('', 'end', values=values)
        except FileNotFoundError:
            pass
        root.after(1000, refresh_dns_log)

    # ── Scanning Logic ──
    def scan():
        for mac in get_connected_macs() - ctl.known:
            if mac not in ctl.allowed and mac not in ctl.blocked:
                add_drop_rules(mac)
                ctl.known.add(mac)
                info = log_device_info(mac)
                push_pending_device(mac, info)

                status = clean_authorization_value(get_pending_device_status(mac))

                if status in ["approved", "denied"]:
                    continue  # Already handled by remote thread
                else:
                    root.after(0, ctl.popup, root, mac)

        root.after(CHECK_INTERVAL * 1000, scan)
        db.child("scan_info").child("last_scan").set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    root.after(1000, scan)
    refresh_device_log()
    refresh_dns_log()
    update_device_counts()

    def push_counts():
        counts = get_device_counts()
        push_dashboard(counts["active"], counts["inactive"], counts["unauthorized"])
        root.after(1000, push_counts)  
    push_counts()

    def loop_device_status_update():
        refresh_device_status()
        root.after(1000, loop_device_status_update)  
    loop_device_status_update()
    threading.Thread(target=monitor_pending_device_status, args=(ctl, root, refresh_device_log), daemon=True).start()
    root.mainloop()
# ─── Entrypoint ────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting.")
