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
```
sudo bash Packages_Installer.sh
sudo bash configure_services.sh
sudo bash Start_Hotspot.sh
nano firebase_config.py   # add Firebase keys
nano kali_modified.py     # (optional) set email alerts
sudo bash Run_Netsentinel.sh
