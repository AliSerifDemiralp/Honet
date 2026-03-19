import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from functools import lru_cache

COMMON_PORTS = [
    # File Transfer
    20, 21, 69,

    # Remote Access / Management
    22, 23, 3389, 5900, 5985, 5986,

    # Email Services
    25, 110, 143, 465, 587,

    # Network Infrastructure
    53, 67, 68, 123, 139, 161, 162, 389, 445,

    # Web Services
    80, 443, 8000, 8008, 8080, 8443, 5000, 3000,

    # Databases
    5432, 3306, 1433, 1521, 27017, 6379,
    9042, 9200, 11211,

    # Containers / Orchestration / Streaming
    6443, 10250, 9092, 2181,

    # Monitoring / Logging
    9090, 5601
]

OUTPUT_FILE = "scan_result.json"
STATE_FILE = ".scan_state.json"


def run_nmap_xml(cmd: list[str]) -> ET.Element:
    fd, tmp_path = tempfile.mkstemp(prefix="nmap_", suffix=".xml")
    os.close(fd)

    try:
        full_cmd = cmd + ["-oX", tmp_path]
        result = subprocess.run(
            full_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise RuntimeError(f"nmap failed: {stderr}")

        if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
            raise RuntimeError("nmap produced empty XML output")

        tree = ET.parse(tmp_path)
        return tree.getroot()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@lru_cache(maxsize=1)
def load_oui_database() -> dict[str, str]:
    oui_db: dict[str, str] = {}
    candidate_paths = [
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
    ]

    oui_path = next((p for p in candidate_paths if os.path.exists(p)), None)
    if not oui_path:
        return oui_db

    with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" not in line:
                continue

            left, right = line.split("(hex)", 1)
            prefix = left.strip().replace("-", ":").upper()
            vendor = right.strip()

            if len(prefix) == 8 and vendor:
                oui_db[prefix] = vendor

    return oui_db


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    return mac.upper().replace("-", ":")


def get_vendor_from_mac(mac: str | None) -> str | None:
    mac = normalize_mac(mac)
    if not mac or len(mac) < 8:
        return None

    prefix = mac[:8]
    return load_oui_database().get(prefix)


def is_locally_administered_mac(mac: str | None) -> bool:
    mac = normalize_mac(mac)
    if not mac:
        return False

    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except Exception:
        return False


def extract_hostnames(host_elem: ET.Element) -> list[str]:
    names = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is None:
        return names

    for hostn in hostnames_elem.findall("hostname"):
        name = hostn.get("name")
        if name:
            names.append(name)
    return names


def discover_hosts(network: str) -> list[dict]:
    root = run_nmap_xml([
        "nmap",
        "-sn",
        "-PR",
        "-n",
        network
    ])

    hosts: list[dict] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None

        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.get("addr")
            elif addrtype == "mac":
                mac = normalize_mac(addr.get("addr"))
                vendor = addr.get("vendor")

        if not vendor:
            vendor = get_vendor_from_mac(mac)

        hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostnames": extract_hostnames(host),
            "mac_randomized": is_locally_administered_mac(mac)
        })

    return hosts


def bulk_scan_ports(hosts: list[dict], ports: list[int]) -> dict[str, list[int]]:
    ip_list = [h["ip"] for h in hosts if h.get("ip")]
    if not ip_list:
        return {}

    port_str = ",".join(map(str, ports))

    root = run_nmap_xml([
        "nmap",
        "-sS",
        "-T3",
        "-n",
        "-Pn",
        "--max-rate", "50",
        "--open",
        "-p", port_str,
        *ip_list
    ])

    results: dict[str, list[int]] = {ip: [] for ip in ip_list}

    for host in root.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break

        if not ip:
            continue

        open_ports: list[int] = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    try:
                        open_ports.append(int(port.get("portid")))
                    except (TypeError, ValueError):
                        pass

        results[ip] = sorted(open_ports)

    return results


def classify_device(vendor: str | None, open_ports: list[int], hostnames: list[str], mac_randomized: bool) -> str:
    vendor_l = (vendor or "").lower()
    hostname_l = " ".join(hostnames).lower()

    phone_vendors = [
        "apple", "samsung", "xiaomi", "huawei", "honor", "oppo",
        "oneplus", "google", "motorola", "realme", "vivo"
    ]
    tv_vendors = [
        "lg", "sony", "philips", "tcl", "hisense", "vestel",
        "arcelik", "beko", "samsung", "panasonic"
    ]
    router_vendors = [
        "zte", "tp-link", "tplink", "ubiquiti", "mikrotik",
        "keenetic", "asus", "huawei", "netgear", "cisco", "zyxel"
    ]
    vm_vendors = [
        "vmware", "virtualbox", "oracle", "qemu", "xen"
    ]
    pc_vendors = [
        "intel", "realtek", "dell", "hp", "lenovo", "asus", "acer", "msi"
    ]

    if any(v in vendor_l for v in vm_vendors):
        return "vm"

    if 53 in open_ports and any(p in open_ports for p in [67, 68, 80, 443]):
        return "router"

    if any(v in vendor_l for v in router_vendors) and 53 in open_ports:
        return "router"

    if any(v in vendor_l for v in tv_vendors):
        if not open_ports or any(p in open_ports for p in [8008, 8080, 8443, 80, 443]):
            return "smart_tv"

    if "apple" in vendor_l:
        if not open_ports:
            return "phone_or_tablet"
        if any(p in open_ports for p in [80, 443, 7000, 7100]):
            return "apple_device"
        return "phone_or_tablet"

    if any(v in vendor_l for v in phone_vendors):
        if not open_ports:
            return "phone_or_tablet"
        return "phone_or_tablet"

    if mac_randomized and not open_ports:
        return "phone_or_tablet"

    if 3389 in open_ports or 445 in open_ports or 5985 in open_ports or 5986 in open_ports:
        return "windows_pc"

    if 22 in open_ports and any(p in open_ports for p in [5432, 3306, 6443, 9200, 9090, 5601, 27017, 6379]):
        return "server"

    if 22 in open_ports and any(p in open_ports for p in [80, 443, 8000, 8080, 8443, 5000, 3000]):
        return "server"

    if any(p in open_ports for p in [5432, 3306, 1433, 1521, 27017, 6379, 9042, 9200, 11211]):
        return "server"

    if any(p in open_ports for p in [6443, 10250, 9092, 2181, 9090, 5601]):
        return "server"

    if any(v in vendor_l for v in pc_vendors):
        if 22 in open_ports or 80 in open_ports:
            return "pc"
        if not open_ports:
            return "pc_or_laptop"

    if "android" in hostname_l or "iphone" in hostname_l or "ipad" in hostname_l:
        return "phone_or_tablet"

    if "tv" in hostname_l or "bravia" in hostname_l:
        return "smart_tv"

    if not open_ports:
        return "unknown_passive_device"

    if any(p in open_ports for p in [80, 443, 8000, 8080, 8443]) and len(open_ports) <= 3:
        return "iot_or_embedded"

    return "unknown"


def stable_device_key(device: dict) -> str:
    mac = device.get("mac")
    ip = device.get("ip")
    return mac or f"ip:{ip}"


def normalize_device_for_state(device: dict) -> dict:
    return {
        "ip": device.get("ip"),
        "mac": device.get("mac"),
        "vendor": device.get("vendor"),
        "hostnames": sorted(device.get("hostnames", [])),
        "open_ports": sorted(device.get("open_ports", [])),
        "device_type": device.get("device_type"),
        "mac_randomized": bool(device.get("mac_randomized", False))
    }


def load_previous_state(path: str) -> dict[str, dict]:
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    devices = data.get("devices", [])
    state = {}
    for device in devices:
        state[stable_device_key(device)] = normalize_device_for_state(device)
    return state


def build_changes(previous: dict[str, dict], current_devices: list[dict]) -> dict:
    current = {
        stable_device_key(d): normalize_device_for_state(d)
        for d in current_devices
    }

    added = []
    removed = []
    changed = []

    prev_keys = set(previous.keys())
    curr_keys = set(current.keys())

    for key in sorted(curr_keys - prev_keys):
        added.append(current[key])

    for key in sorted(prev_keys - curr_keys):
        removed.append(previous[key])

    for key in sorted(prev_keys & curr_keys):
        old = previous[key]
        new = current[key]

        delta = {}
        for field in ["ip", "vendor", "hostnames", "open_ports", "device_type", "mac_randomized"]:
            if old.get(field) != new.get(field):
                delta[field] = {
                    "old": old.get(field),
                    "new": new.get(field)
                }

        if delta:
            changed.append({
                "key": key,
                "mac": new.get("mac"),
                "changes": delta
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "has_changes": bool(added or removed or changed)
    }


def run_scan(network: str) -> dict:
    hosts = discover_hosts(network)
    port_results = bulk_scan_ports(hosts, COMMON_PORTS)

    devices = []
    for host in hosts:
        ip = host["ip"]
        open_ports = sorted(port_results.get(ip, []))

        device = {
            "ip": ip,
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "hostnames": host.get("hostnames", []),
            "mac_randomized": host.get("mac_randomized", False),
            "open_ports": open_ports,
        }
        device["device_type"] = classify_device(
            device["vendor"],
            device["open_ports"],
            device["hostnames"],
            device["mac_randomized"]
        )
        devices.append(device)

    devices.sort(key=lambda x: tuple(int(part) for part in x["ip"].split(".")))

    previous_state = load_previous_state(STATE_FILE)
    changes = build_changes(previous_state, devices)

    result = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "network": network,
        "device_count": len(devices),
        "devices": devices,
        "changes": changes
    }

    return result


if __name__ == "__main__":
    network = "192.168.1.0/24"
    output = run_scan(network)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"devices": output["devices"]}, f, indent=4, ensure_ascii=False)

    print(f"Scan saved to {OUTPUT_FILE}")
    print(
        f"Devices: {output['device_count']} | "
        f"Added: {len(output['changes']['added'])} | "
        f"Removed: {len(output['changes']['removed'])} | "
        f"Changed: {len(output['changes']['changed'])}"
    )