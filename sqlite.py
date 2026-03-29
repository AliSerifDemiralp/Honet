import sqlite3
from datetime import datetime, UTC
import os

DB_FILE = "honet.db"

def init_db():
    if os.path.exists(DB_FILE):
        return
    print("Initializing database...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT UNIQUE,
        first_seen TEXT,
        last_seen TEXT,
        last_ip TEXT,
        last_vendor TEXT,
        last_device_type TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS device_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        port INTEGER,
        first_seen TEXT,
        last_seen TEXT,
        is_open INTEGER,
        UNIQUE(device_id, port)
    )
    """)
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY,
    username TEXT,
    hashed_pass TEXT,
    first_login TEXT,
    last_login TEXT,
    cidr TEXT,
    scan_interval INTEGER,
    last_run TEXT
    )
    """)
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    attempt_time TEXT,
    success INTEGER
    )
    """)
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS login_lock (
    ip TEXT PRIMARY KEY,
    lock_until TEXT
    )
    """)

    conn.commit()
    conn.close()
    
def get_config():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT username, hashed_pass, first_login, last_login, scan_interval, cidr FROM config LIMIT 1")
    row = c.fetchone()

    conn.close()
    return row if row else None

def register_user(username, hashed_pass):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        INSERT INTO config (id, username, hashed_pass)
        VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            username = excluded.username,
            hashed_pass = excluded.hashed_pass
    """, (username, hashed_pass))

    conn.commit()
    conn.close()

def reset_credentials():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE config SET username = NULL, hashed_pass = NULL, first_login = NULL, last_login = NULL")
    conn.commit()
    conn.close()

def update_config(field, value):
    allowed_fields = [
        "username",
        "hashed_pass",
        "first_login",
        "last_login",
        "scan_interval",
        "last_run",
        "cidr"
    ]

    if field not in allowed_fields:
        raise ValueError("Invalid field name")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    query = f"UPDATE config SET {field} = ?"

    c.execute(query, (value,))
    conn.commit()
    conn.close()

def get_scan_interval():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT scan_interval FROM config LIMIT 1")
    row = c.fetchone()

    conn.close()
    return row[0] if row else None

def is_locked(ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT lock_until FROM login_lock WHERE ip=?", (ip,))
    row = c.fetchone()
    conn.close()

    if not row:
        return False

    lock_until = datetime.fromisoformat(row[0])

    now = datetime.now(UTC)

    if now < lock_until:
        return True

    return False

def record_failed_attempt(ip):
    now = datetime.now(UTC)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        INSERT INTO login_attempts (ip, attempt_time, success)
        VALUES (?, ?, 0)
    """, (ip, now.isoformat()))

    # Son 10 dakika içinde fail say
    ten_min_ago = now - timedelta(minutes=10)

    c.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE ip=? AND success=0 AND attempt_time >= ?
    """, (ip, ten_min_ago.isoformat()))

    fail_count = c.fetchone()[0]

    if fail_count >= 5:
        lock_until = now + timedelta(minutes=10)
        c.execute("""
            INSERT OR REPLACE INTO login_lock (ip, lock_until)
            VALUES (?, ?)
        """, (ip, lock_until.isoformat()))

    conn.commit()
    conn.close()

def get_devices_with_ports():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        SELECT 
            d.mac,
            d.last_ip,
            d.last_vendor,
            d.last_device_type,
            d.last_seen,
            GROUP_CONCAT(dp.port) AS open_ports
        FROM devices d
        LEFT JOIN device_ports dp 
            ON dp.device_id = d.id AND dp.is_open = 1
        GROUP BY d.id;
    """)

    rows = c.fetchall()
    conn.close()
    return rows

def export_db_to_pdf():
    # Do not add these import to global, it crashes somehow, I don't have time to investigate it.
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        SELECT d.mac, d.last_ip, d.last_vendor, d.last_device_type, d.last_seen,
               GROUP_CONCAT(dp.port)
        FROM devices d
        LEFT JOIN device_ports dp 
            ON dp.device_id = d.id AND dp.is_open = 1
        GROUP BY d.id
    """)
    rows = c.fetchall()
    conn.close()

    file_path = os.path.join(os.getcwd(), "honet_export.pdf")

    if os.path.exists(file_path):
        os.remove(file_path)

    styles = getSampleStyleSheet()
    content = []

    if not rows:
        content.append(Paragraph("No data found in database.", styles["Normal"]))
    else:
        for d in rows:
            mac = d[0] or "N/A"
            ip = d[1] or "N/A"
            vendor = d[2] or "N/A"
            dtype = d[3] or "N/A"
            last_seen = d[4] or "N/A"
            ports = d[5] or "None"

            content.append(Paragraph(f"<b>IP:</b> {ip}", styles["Normal"]))
            content.append(Paragraph(f"MAC: {mac}", styles["Normal"]))
            content.append(Paragraph(f"Vendor: {vendor}", styles["Normal"]))
            content.append(Paragraph(f"Type: {dtype}", styles["Normal"]))
            content.append(Paragraph(f"Ports: {ports}", styles["Normal"]))
            content.append(Paragraph(f"Last Seen: {last_seen}", styles["Normal"]))
            content.append(Spacer(1, 10))

    doc = SimpleDocTemplate(file_path)
    doc.build(content)

    return file_path

def save_scan(devices):
    now = datetime.now(UTC).isoformat()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    for device in devices:
        mac = device.get("mac")
        ip = device.get("ip")
        vendor = device.get("vendor")
        device_type = device.get("device_type")
        open_ports = device.get("open_ports", [])

        # If MAC not exists IP fallback
        key = mac if mac else f"IP:{ip}"

        c.execute("SELECT id FROM devices WHERE mac IS ?", (mac,))
        row = c.fetchone()

        if row:
            device_id = row[0]
            c.execute("""
                UPDATE devices
                SET last_seen=?, last_ip=?, last_vendor=?, last_device_type=?
                WHERE id=?
            """, (now, ip, vendor, device_type, device_id))
        else:
            c.execute("""
                INSERT INTO devices
                (mac, first_seen, last_seen, last_ip, last_vendor, last_device_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (mac, now, now, ip, vendor, device_type))
            device_id = c.lastrowid

        # Port handling
        # Check open ports first
        c.execute("SELECT port FROM device_ports WHERE device_id=? AND is_open=1", (device_id,))
        existing_open = {row[0] for row in c.fetchall()}

        current_open = set(open_ports)

        # New open ports
        for port in current_open - existing_open:
            c.execute("""
                INSERT OR IGNORE INTO device_ports
                (device_id, port, first_seen, last_seen, is_open)
                VALUES (?, ?, ?, ?, 1)
            """, (device_id, port, now, now))

        # Ports that still open
        for port in current_open & existing_open:
            c.execute("""
                UPDATE device_ports
                SET last_seen=?, is_open=1
                WHERE device_id=? AND port=?
            """, (now, device_id, port))

        # Closed ports
        for port in existing_open - current_open:
            c.execute("""
                UPDATE device_ports
                SET is_open=0, last_seen=?
                WHERE device_id=? AND port=?
            """, (now, device_id, port))

    conn.commit()
    conn.close()