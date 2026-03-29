# 🛡 Honet

🛰 Honet: Home Network Monitor is a scheduled network scanner for complete visibility across your home network.

---

## 🧰 Tech Stack

- 🐍 Python 3.12.3  
- 🎛 Streamlit 1.55.0  
- 🗄 SQLite 3.45.1  
- 📡 Nmap 7.94SVN  

---

## 🖥 Development Platform

- 🐧 Ubuntu 24.04.3 LTS (Noble Numbat)

---

## 🚀 How To Run

Execute the commands below:

1. 🧪 `python3 -m venv .venv`
2. 🔓 `source .venv/bin/activate`
3. 📂 `cd Honet`
4. 📦 `pip install -r requirements.txt`
5. ▶ `streamlit run app.py`
6. 🌐 Open your browser and navigate to port **8501**

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
