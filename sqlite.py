import sqlite3
from datetime import datetime, UTC


DB_FILE = "honet.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

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