# streamlit_app.py

import streamlit as st
import sqlite3
import subprocess
import hashlib
from datetime import datetime, UTC, timedelta
from sqlite import init_db, get_scan_interval, get_config, update_config, register_user, reset_credentials, get_devices_with_ports, record_failed_attempt, is_locked, export_db_to_pdf
import threading
import time, os, sys
import ipaddress

DB_FILE = "honet.db"
SCAN_SCRIPT = "net_scan.py"

# ---- DB INITIALIZATION ----
init_db()

# ---- CONFIG ----
SESSION_TIMEOUT_MINUTES = 5
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

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


# ---- REGISTER ----
def register():
    config = get_config()

    needs_register = (
        config is None or
        config[0] is None or
        config[1] is None
    )

    if not needs_register:
        login()
        return

    st.title("Honet", text_alignment="center")
    st.subheader("Homelab Network Visibility", text_alignment="center", divider="green")
    st.success("No admin user found. Please register.")

    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register", use_container_width=True)

    if submitted:
        if password != confirm_password:
            st.error(" ⚠︎ Passwords do not match")
            return

        hashed_pass = hashlib.sha256(password.encode()).hexdigest()

        try:
            register_user(username, hashed_pass)
            st.success(" ✔ Registration successful. Please login.")

            st.session_state.auth = False
            st.session_state.last_activity = None

            st.rerun()
        except Exception as e:
            st.error(f" ⚠︎ Error occurred: {e}")

# ---- LOGIN ----
def login():
    config = get_config()
    st.title("Honet", text_alignment="center")
    st.subheader("Homelab Network Visibility", text_alignment="center", divider="green")

    ip = get_client_ip()

    if is_locked(ip):
        st.error(" ⓘ Too many failed attempts. Try again later.")
        return

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        submitted = st.form_submit_button("Login", use_container_width=True)

    if submitted:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        
        if username == config[0] and hashed == config[1]:
            st.session_state.auth = True
            st.session_state.last_activity = datetime.now(UTC)
            if config[2] is None:
                update_config("first_login", datetime.now(UTC).isoformat())
            else:
                update_config("last_login", datetime.now(UTC).isoformat())
            st.rerun()
        else:
            record_failed_attempt(ip)
            st.error(" ⚠︎ Invalid credentials")

def get_client_ip():
    try:
        return st.context.headers.get("x-forwarded-for", "local")
    except:
        return "local"

# ---- Time Prettier ----
def format_last_seen(ts_string):
    dt = datetime.fromisoformat(ts_string)
    return dt.strftime("%d.%m.%Y %H:%M:%S %Z")

# ---- Network Validation ----
def validate_network(net):
    try:
        ipaddress.ip_network(net)
        return True
    except:
        return False

# ---- DASHBOARD ----
def render_devices():
    devices = get_devices_with_ports()

    st.subheader("Discovered Devices")

    for i, d in enumerate(devices):
        with st.expander(f"IP: {d[1]}", expanded=False):
            col1, col2 = st.columns(2)
            col1.write(f"MAC: {d[0]}")
            col1.write(f"Vendor: {d[2]}")
            col2.write(f"Type: {d[3]}")
            col2.write(f"Open Ports: {d[5]}")
            st.markdown(f"Last Seen: {format_last_seen(d[4])}")

@st.fragment(run_every=10)
def devices_fragment():
    render_devices()

def dashboard():
    config = get_config()
    check_session_timeout()
    st.subheader("모 Honet Network Visibility", divider="green")

    
    network = st.text_input("Network (CIDR)", value="192.168.1.0/24")
    if st.button("Save CIDR", use_container_width=True, key="btn_update_cidr"):
            update_cidr(network)
        
    if st.button("▶ Run Manual Scan", use_container_width=True, key="btn_manual_scan"):
        if not validate_network(network):
            st.error("Invalid network")
        else:
            run_manual_scan(network)

    if config[4] == None:
        st.warning("Please set the scanning interval")
    interval = st.number_input(
        label="Scan Interval (minutes)",
        min_value=1,
        value=config[4] if config and config[4] else 5,
        max_value=1440,
        step=1,
        key="scan_interval_input",
    )

    if st.button("⏱ Schedule Scan", use_container_width=True, key="btn_schedule_scan"):
        schedule_scan(interval)
        
    if st.button("Export DB (raw)", use_container_width=True):
        with open(DB_FILE, "rb") as f:
            st.download_button(
                label="Download DB",
                data=f,
                file_name="honet.db",
                mime="application/octet-stream",
                use_container_width=True
            )
    
    if st.button("📄 Export DB to PDF", use_container_width=True):
        file_path = export_db_to_pdf()
        with open(file_path, "rb") as f:
            st.download_button(
                label="Download Now",
                data=f.read(),
                file_name="honet_export.pdf",
                mime="application/pdf",
                use_container_width=True
            )

    if st.button("➜ Logout", use_container_width=True, key="btn_logout"):
        st.session_state.auth = False
        st.session_state.last_activity = None
        st.rerun()
        
    if st.button("Reset Credentials", use_container_width=True, key="btn_reset_creds"):
        reset_credentials()
        st.session_state.auth = False
        st.session_state.last_activity = None
        st.rerun()
        
    if st.button("Hard Reset", use_container_width=True, key="btn_hard_reset"):
        hard_reset()
    
    st.divider()

    devices_fragment()


# ---- MANUAL SCAN ----
def run_manual_scan(network):
    try:
        subprocess.run([sys.executable, SCAN_SCRIPT, network])
        update_config("last_run", datetime.now(UTC).isoformat())
    except:
        st.fail(' ✘ Scan couldn\'t executed')
    else:
        st.success(" ✔ Scan completed")
        

# ---- SCHEDULE SCAN ----
def schedule_scan(interval):
    try:
        update_config("scan_interval", interval)
        st.success(f"✔ Scan scheduled every {interval} minutes")
    except:
        st.error("✘ Failed to schedule scan")
        
# ---- EDIT CIDR ----
def update_cidr(cidr):
    try:
        update_config("cidr", cidr)
        st.success(f"✔ CIDR updated to {cidr}")
    except:
        st.error("✘ Failed to update CIDR")

# ---- EDIT SCAN INTERVAL ----
def schedule_scan(interval):
    try:
        update_config("scan_interval", interval)
        st.success(f"✔ Scan scheduled every {interval} minutes")
    except:
        st.error("✘ Failed to schedule scan")

def scheduler_worker(network):
    while True:
        interval = get_scan_interval()

        if interval:
            try:
                subprocess.run([sys.executable, SCAN_SCRIPT, network])
                update_config("last_run", datetime.now(UTC).isoformat())
            except:
                pass

            time.sleep(interval * 60)
        else:
            time.sleep(10)

def start_scheduler():
    if "scheduler_started" not in st.session_state:
        config = get_config()
        t = threading.Thread(target=scheduler_worker, args=(config[5] if config and config[5] else "192.168.1.0/24",), daemon=True)
        t.start()
        st.session_state.scheduler_started = True

# ---- HARD RESET ----
def hard_reset():
    try:
        import os

        for f in [DB_FILE, DB_FILE + "-wal", DB_FILE + "-shm"]:
            if os.path.exists(f):
                os.remove(f)

        st.cache_resource.clear()   # 🔥 cache temizle
        st.session_state.clear()    # 🔥 session reset

        st.rerun()  # 🔥 düzgün restart

    except Exception as e:
        st.error(f"Hard reset failed: {e}")



# ---- MAIN ----
start_scheduler()

if not st.session_state.auth:
    register()
    st.stop()
else:
    dashboard()