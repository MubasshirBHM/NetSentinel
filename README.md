# NetSentinel  

<img width="389" height="400" alt="net" src="https://github.com/user-attachments/assets/6e934768-6f49-4929-ade0-3bcffcb9e0b8" />

NetSentinel is a **real-time Wi-Fi monitoring and control system** for Debian/Ubuntu/Kali.  
It allows non-technical users to set up a secure hotspot, monitor connected devices, approve/block them, and sync DNS blocklists from Firebase.  

---

## ✨ Features
- 🔐 Hostapd/dnsmasq based hotspot creation  
- 📊 Real-time traffic monitoring (Tkinter GUI)  
- ✅ Device approval/blocking with firewall rules  
- ☁️ Firebase integration for logging + remote control  
- 🛑 Realtime blocklist sync with dnsmasq  
- 📧 Email alerts (via Gmail App Password)  
- 🧪 Optional fake SSID broadcaster for lab testing  

---

## 🖥️ System Requirements
- Linux distro: Debian / Ubuntu / Kali (**Kali recommended**)  
- Wi-Fi adapter supporting **AP mode** (e.g., Atheros AR9271)  
- Internet uplink via Ethernet (default: `eth0`) or another interface  
- Root access (`sudo`)  
- Python **3.8+**  

---

## 🌐 Network Assumptions
- **AP interface**: `wlan0`  
- **Uplink interface**: `eth0`  
- **AP IP**: `192.168.50.1/24`  
- **DHCP range**: `192.168.50.10 – 192.168.50.200`  
- **Default SSID**: `Hola-Fiber🚀` *(changeable)*  
- **Default WPA2 passphrase**: `12345678` *(change this!)*  

---

## 📂 Project Structure
```bash
├── firebase_config.py             # Firebase integration & logging
├── kali_modified.py               # Main GUI + monitoring
├── realtime_blocklist_listener.py # Syncs blocked domains to dnsmasq
├── oui.txt                        # MAC prefix → vendor database
├── wifi.lst                       # SSID list for fake AP (optional)
├── Packages_Installer.sh          # Installer (system deps + Python venv)
├── configure_services.sh          # Configures hostapd/dnsmasq
├── Start_Hotspot.sh               # Starts AP, iptables, NAT
├── Run_Netsentinel.sh             # Runs realtime listener + GUI
├── switchoff.sh                   # Stops AP services
├── fakessid.sh / stopfakessid.sh  # Fake SSID broadcast (optional)
└── README.md
```
## ⚡ Quick Start 
Run following command in as order
```
sudo bash Packages_Installer.sh
sudo bash configure_services.sh
sudo bash Start_Hotspot.sh
nano firebase_config.py   # add Firebase keys
nano kali_modified.py     # (optional) set email alerts
sudo bash Run_Netsentinel.sh

## ⚙️ Installation
```
Run the one-time installer to set up dependencies, Python venv, and configs:
sudo bash Packages_Installer.sh
sudo bash configure_services.sh
This installs:
•	hostapd, dnsmasq, iptables, mdk4
•	Python venv with pyrebase4, scapy, requests
•	Prepares blocklist configs
```
## 📡 Starting the Hotspot
sudo bash Start_Hotspot.sh
This sets the AP IP, NAT, firewall rules, and blocks all clients by default until approved.
Stop hotspot:
sudo bash switchoff.sh

## 🖥️ Running NetSentinel
sudo bash Run_Netsentinel.sh
This will:
•	Start realtime_blocklist_listener.py in background
•	Launch kali_modified.py (Tkinter GUI)

🔑 Firebase Setup
1.	Create a Firebase Realtime Database project
2.	Obtain the following values:
o	apiKey
o	authDomain
o	databaseURL
o	projectId
o	storageBucket
o	messagingSenderId
o	appId
3.	Add them into firebase_config.py
By default, NetSentinel reads values directly from firebase_config.py.

## 📧 Email Alerts (Optional)
Edit kali_modified.py with:
•	EMAIL_SENDER → your Gmail
•	EMAIL_RECEIVER → list of recipients
•	REAL_APP_PASSWORD → Gmail App Password (not your login password)
•	EMAIL_SMTP_SERVER → default: smtp.gmail.com
•	EMAIL_SMTP_PORT → default: 465

## 🔒 Device Approval/Blocking
•	By default, all clients are blocked until approved
•	Devices appear as pending in the GUI
•	Approve/deny via GUI or Firebase UI
•	Rules are applied via iptables and logged in Firebase
•	Email alerts can notify on approval/denial

## 🛑 Blocklist Sync (DNSMASQ)
•	realtime_blocklist_listener.py listens for changes under blocked_domains in Firebase
•	Updates /etc/dnsmasq.d/blocklist.conf
•	Restarts dnsmasq automatically

## 🧪 Optional: Fake SSID Broadcasting
⚠️ For lab testing only!
Start fake SSID broadcast:
sudo bash fakessid.sh
Stop broadcast:
sudo bash stopfakessid.sh

## 📂 Logs & Useful Locations
•	DHCP leases → /var/lib/misc/dnsmasq.leases
•	Blocklist → /etc/dnsmasq.d/blocklist.conf
•	Hostapd config → /etc/hostapd/hostapd.conf
•	GUI + listener logs → console output
•	Vendor DB → oui.txt

## 🛠️ Troubleshooting
•	dnsmasq fails → journalctl -xeu dnsmasq.service
•	hostapd fails → ensure adapter supports AP mode (nl80211)
•	No internet → verify NAT rules & uplink interface
•	No pending devices → check Firebase keys & Python venv
•	Email alerts fail → verify Gmail App Password & SMTP settings


