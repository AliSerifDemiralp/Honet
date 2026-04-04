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


<details><summary>Recommended Steps</summary>
🚩 Nginx Setup (Recommended)

1. `sudo apt update`
2. `sudo apt install nginx -y`

Configure Reverse Proxy

3. `sudo nano /etc/nginx/sites-available/honet`
```
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8501;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Enable Configuration

4. `sudo rm -f /etc/nginx/sites-enabled/default`
5. `sudo ln -s /etc/nginx/sites-available/honet /etc/nginx/sites-enabled/`
6. `sudo nginx -t`
7. `sudo systemctl restart nginx`

Firewall (Recommended)

Allow only HTTP/HTTPS:

8. `sudo ufw allow 80`
9. `sudo ufw allow 443`
10. `sudo ufw deny 8501`
11. `sudo ufw enable`

Client IP Detection

- Honet uses reverse proxy headers to detect client IP addresses.
- Without Nginx (or another proxy), the application may only see "localhost"

Notes:
- Streamlit runs on 127.0.0.1:8501
- Nginx exposes the app on port 80
- HTTPS (port 443) can be added later with a valid certificate
- Self-signed SSL is not included by default
</details>

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
