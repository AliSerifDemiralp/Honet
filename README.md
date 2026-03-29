# 🛡 Honet

🛰 Honet: Homelab Network Monitor is a scheduled network scanner for complete visibility across your home network.

---

## 🧰 Current Tech Stack

- 🐍 Python 3.12.13
- 🎛 Streamlit 1.55.0  
- 🗄 SQLite 3.45.1  
- 📡 Nmap 7.94SVN  

---

## 🖥 Development Platform

- 🐧 Ubuntu 24.04.3 LTS (Noble Numbat)

---

## 🚀 How To Run

Execute the commands below:

1. `git clone https://github.com/AliSerifDemiralp/Honet.git`
2. `cd Honet`
3. `python3 -m venv .venv`
4. `source .venv/bin/activate`
5. `pip install -r requirements.txt`
6. `streamlit run app.py`

## 🐳 For Docker

`docker compose -f deploy/docker/docker-compose.yml up -d`

---

## 🔐 Features

- 📡 Network discovery based on custom CIDR (ARP based)
- 🚪 Open port detection (Builtin limited)
- 🧠 Auto device classification
- 🗂 SQLite forensic logging to portal
- 🔒 Login protection + brute-force guard (Session based)
- 🛑 Session timeout
- ⏱ Scheduled scans
- 🔐 SSL / HTTPS support
    - Supported by Streamlit but not recommended due to security/performance reasons
- 📤 PDF report & RAW DB export
- 🐳 Docker support (Currently optimized for RPi Zero W – 1 CPU / ~500MB RAM)
---

## 🧪 Improvements (Not Scheduled)
- Telegram Notification
- Rule Management
