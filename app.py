import streamlit as st
import sqlite3
import subprocess
import hashlib
from datetime import datetime, UTC, timedelta
from sqlite import init_db, get_scan_interval, get_config, update_config, register_user, reset_credentials, get_devices_with_ports, record_failed_attempt, is_locked, export_db_to_pdf, record_successful_attempt, get_login_history
import threading
import time, os, sys
import ipaddress
import threading

# ---- DB EXPORTS & SCAN SCRIPT ----
DB_FILE = os.environ.get("HONET_DB_PATH", "honet.db")
SCAN_SCRIPT = "net_scan.py"

# ---- THREADING ----
SCAN_LOCK = threading.Lock()
SCHEDULER_STARTED = False
LOCK_FILE = "honet_scan.lock"

# ---- DB INITIALIZATION ----
@st.cache_resource
def initialize_db():
    init_db()
initialize_db()

# ---- CONFIG ----
SESSION_TIMEOUT_MINUTES = 5
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

@st.cache_data(ttl=30)
def cached_config():
    return get_config()

# ---- LOGGING ----
def log(msg):
    print(f"[{datetime.now().isoformat()}] {msg}", flush=True)

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
    config = cached_config()

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

            cached_config.clear()
            st.rerun()
        except Exception as e:
            st.error(f" ⚠︎ Error occurred: {e}")

# ---- LOGIN ----
def login():
    config = cached_config()
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
            record_successful_attempt(ip)
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

    st.subheader("Discovered Devices", divider="green")
    st.caption("Refreshes every 30 seconds")

    for i, d in enumerate(devices):
        with st.expander(f"IP: {d[1]}", expanded=False):
            col1, col2 = st.columns(2)
            col1.write(f"MAC: {d[0]}")
            col1.write(f"Vendor: {d[2]}")
            col2.write(f"Type: {d[3]}")
            col2.write(f"Open Ports: {d[5]}")
            st.markdown(f"Last Seen: {format_last_seen(d[4])}")

@st.fragment(run_every=30)
def devices_fragment():
    render_devices()

def dashboard():
    config = cached_config()
    check_session_timeout()
    st.subheader("모 Honet Network Visibility", divider="green")

    with st.sidebar:
        network = st.text_input("Network (CIDR)", value=config[5])
        if st.button("Save CIDR", use_container_width=True, key="btn_update_cidr"):
                update_cidr(network)

        if st.button("▶ Run Manual Scan", use_container_width=True, key="btn_manual_scan"):
            if not validate_network(network):
                st.error("Invalid network")
            else:
                run_manual_scan(network)
        st.divider()
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
        st.divider()
        if st.button("Export DB (raw)", use_container_width=True):
            with open(DB_FILE, "rb") as f:
                st.download_button(
                    label="Download DB",
                    data=f,
                    file_name="honet.db",
                    mime="application/octet-stream",
                    use_container_width=True
                )

        if st.button("Export DB to PDF", use_container_width=True):
            file_path = export_db_to_pdf()
            with open(file_path, "rb") as f:
                st.download_button(
                    label="Download Now",
                    data=f.read(),
                    file_name="honet_export.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
        st.divider()
        if st.button("⏱ Login History", use_container_width=True):
            st.session_state.show_login_history = not st.session_state.get("show_login_history", False)

        if st.session_state.get("show_login_history", False):
            with st.container(border=True):
                col1, col2 = st.columns([6, 2])
                col1.subheader("Login History")
                if col2.button("✕", key="close_login_history"):
                    st.session_state.show_login_history = False
                    st.rerun()

                records = get_login_history()

                if not records:
                    st.info("No login records found.")
                else:
                    for r in records:
                        st.divider()
                        color=f"{'green' if r[2] else 'red'}"
                        st.badge(f"**IP:** {r[0]}", color=color)
                        st.badge(f"**Time:** {format_last_seen(r[1])}", color=color)
                        st.badge(f"**Status:** {'✔ Success' if r[2] else '✘ Failed'}", color=color)

        st.divider()
        
        if st.button("➜ Logout", use_container_width=True, key="btn_logout"):
            st.session_state.auth = False
            st.session_state.last_activity = None
            st.rerun()

        if st.button("Reset Credentials", use_container_width=True, key="btn_reset_creds"):
            reset_credentials()
            st.session_state.auth = False
            st.session_state.last_activity = None
            cached_config.clear()
            st.rerun()

        if st.button("Hard Reset", use_container_width=True, key="btn_hard_reset"):
            hard_reset()

        
    devices_fragment()


# ---- MANUAL SCAN ----
def run_manual_scan(network):
    if os.path.exists(LOCK_FILE):
        st.warning("⚠ Scan already running")
        return
    subprocess.Popen([sys.executable, SCAN_SCRIPT, network])
    st.success("✔ Scan started in background")

# ---- EDIT CIDR ----
def update_cidr(cidr):
    try:
        update_config("cidr", cidr)
        st.success(f"✔ CIDR updated to {cidr}")
    except:
        st.error("✘ Failed to update CIDR")

# ---- SCAN INTERVAL ----
def schedule_scan(interval):
    current = get_scan_interval()

    if current == interval:
        st.info("Scan already scheduled with same interval")
        return

    update_config("scan_interval", interval)
    st.success(f"✔ Scan scheduled every {interval} minutes")
    start_scheduler()

def scheduler_worker():
    while True:
        interval = get_scan_interval()

        if interval:
            config = cached_config()
            cidr = config[5] if config and config[5] else "192.168.1.0/24"

            log("⚠ Scheduler scan START")
            subprocess.run([sys.executable, SCAN_SCRIPT, cidr])
            log("⚠ Scheduler scan DONE")

            time.sleep(interval * 60)
        else:
            time.sleep(60)


def start_scheduler():
    global SCHEDULER_STARTED

    if not SCHEDULER_STARTED:
        interval = get_scan_interval()
        
        if interval is None:
            log("⚠ Scheduler not started, no interval set")
            SCHEDULER_STARTED = False 
            return

        log("⚠ Scheduler will start in " + str(interval) + " sec")

        def delayed_start():
            time.sleep(interval * 60)
            scheduler_worker()

        t = threading.Thread(target=delayed_start, daemon=True)
        t.start()

        SCHEDULER_STARTED = True

# ---- HARD RESET ----
def hard_reset():
    try:
        import os

        for f in [DB_FILE, DB_FILE + "-wal", DB_FILE + "-shm"]:
            if os.path.exists(f):
                os.remove(f)

        st.cache_resource.clear()
        st.session_state.clear()
        cached_config.clear()
        st.rerun()

    except Exception as e:
        st.error(f"Hard reset failed: {e}")



# ---- MAIN ----
if __name__ == "__main__":
    if "scheduler_started" not in st.session_state:
        st.session_state.scheduler_started = True
        start_scheduler()

    if not st.session_state.auth:
        register()
        st.stop()
    else:
        dashboard()