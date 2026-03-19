# streamlit_app.py

import streamlit as st
import sqlite3
import subprocess
import hashlib
from datetime import datetime, UTC, timedelta
from sqlite import init_db

DB_FILE = "honet.db"
SCAN_SCRIPT = "net_scan.py"

# ---- CONFIG ----
USERNAME = "admin"
PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()

SESSION_TIMEOUT_MINUTES = 5
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

init_db()

# ---- SESSION STATE INIT ----
if "auth" not in st.session_state:
    st.session_state.auth = False

if "last_activity" not in st.session_state:
    st.session_state.last_activity = None

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

if "lockout_until" not in st.session_state:
    st.session_state.lockout_until = None


# ---- SESSION TIMEOUT CHECK ----
def check_session_timeout():
    if not st.session_state.auth:
        return

    now = datetime.now(UTC)

    if st.session_state.last_activity:
        if now - st.session_state.last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            st.session_state.auth = False
            st.session_state.last_activity = None
            st.warning(" ⏱ Session expired")
            st.rerun()

    st.session_state.last_activity = now


# ---- LOGIN ----
def login():
    st.title("🔐 Honet Login")

    ip = get_client_ip()

    if is_locked(ip):
        st.error(" 🚨 Too many failed attempts. Try again later.")
        return

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        hashed = hashlib.sha256(password.encode()).hexdigest()

        if username == USERNAME and hashed == PASSWORD_HASH:
            st.session_state.auth = True
            st.session_state.last_activity = datetime.now(UTC)
            st.rerun()
        else:
            record_failed_attempt(ip)
            st.error(" 🚨 Invalid credentials")


def get_client_ip():
    try:
        return st.context.headers.get("x-forwarded-for", "local")
    except:
        return "local"
    
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

# ---- DB READ ----
def get_devices():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        SELECT mac, last_ip, last_vendor, last_device_type, last_seen
        FROM devices
    """)
    rows = c.fetchall()
    conn.close()
    return rows


# ---- MANUAL SCAN ----
def run_manual_scan():
    subprocess.run(["sudo", "python3", SCAN_SCRIPT])
    st.success(" 🟢 Scan completed")


# ---- Time Prettier ----
def format_last_seen(ts_string):
    dt = datetime.fromisoformat(ts_string)
    return dt.strftime("%d.%m.%Y %H:%M:%S %Z")

# ---- DASHBOARD ----
def dashboard():
    check_session_timeout()
    st.title(" 📟 Honet Network Visibility")
    st.divider()
    col_top1, col_top2 = st.columns([6, 1])

    with col_top2:
        if st.button("Logout"):
            st.session_state.auth = False
            st.session_state.last_activity = None
            st.rerun()

    with col_top1:
        if st.button(" 📡 Run Manual Scan"):
            run_manual_scan()

    
    st.divider()
    devices = get_devices()

    st.subheader("Discovered Devices")
    st.divider()

    for d in devices:
        with st.container():
            st.markdown(f"### IP: {d[1]}")
            col1, col2 = st.columns(2)
            col1.write(f"MAC: {d[0]}")
            col1.write(f"Vendor: {d[2]}")
            col2.write(f"Type: {d[3]}")
            st.markdown(f"Last Seen: {format_last_seen(d[4])}")
            st.divider()


# ---- MAIN ----
if not st.session_state.auth:
    login()
    st.stop()
else:
    dashboard()