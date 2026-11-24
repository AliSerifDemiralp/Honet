# Honet v2 — Go rewrite (design)

Date: 2026-11-23 · Status: approved

## 1. Purpose and motivation

Honet is a personal hobby project that scans the home network and answers the question "are all of these devices mine?". The previous version (Python + Streamlit + nmap) cannot run on a first-generation Raspberry Pi Zero W (ARMv6, 512 MB RAM, single core): Streamlit's dependencies (pyarrow, numpy, pandas) cannot be installed on ARMv6. The code also had serious security flaws (see §6).

Goal: a single-binary Go application that runs **as efficiently as possible** on the Zero W. It shows the devices on the network, nearby Bluetooth devices and the WiFi networks around. The user names their devices and marks them as "known"; anything unknown stands out on the dashboard.

## 2. Goals, non-goals, things to avoid

**Goals**
- One static file built on Windows, copied to the Zero W and run (`CGO_ENABLED=0`, `linux/arm/v6`; also `arm/v7`, `arm64`, `amd64`).
- No runtime dependencies on the Pi: no nmap, Python or Node.
- **Network (LAN):** device discovery with ARP, TCP connect probes of 45 common ports, vendor (OUI) lookup, hostname, device type guess.
- **Bluetooth:** list nearby classic and BLE devices. Devices with a fixed address can be added to the inventory.
- **WiFi networks (separate menu):** list nearby access points and detect fakes (evil twins) of networks the user marked as "my networks".
- **Inventory:** give devices a name, a note and a "known" mark. Unknown devices appear as warnings at the top of the list and the dashboard.
- **Internet measurement (separate menu):** latency, jitter, packet loss and DNS time continuously; download/upload speed every 3 hours. Weekly graphs.
- **Event history:** new device, IP change, port opened/closed, suspected fake access point.
- Scheduled and manual scans.
- Mobile-friendly, server-rendered HTML + Bootstrap 5 UI.

**Non-goals (not in v2)**
- Phone notifications (Telegram, ntfy, e-mail). Alerts are shown in the UI only.
- Multiple users or roles. There is one administrator.
- Exposure to the internet. The target is a home network.
- nmap-style service/version detection and OS fingerprinting.
- Passive WiFi monitoring in monitor mode (the Zero W chip does not support it).
- IPv6 device discovery.
- Migrating the old `honet.db` data (the project was not in active use).

**Things to avoid (a failure even if it works)**
- A process running as root.
- Any step that requires compiling on the Zero W.
- A UI that depends on a CDN or the internet. The Pi must work fully on an offline network.
- Frequent writes that wear out the SD card (for example writing to the database every 30 seconds).
- More than 30 MB of RAM while idle.

## 3. Constraints

- **Hardware:** ARMv6 (BCM2835), 1 GHz single core, 512 MB RAM, SD card.
- **Shared radio:** WiFi and Bluetooth use the same chip (CYW43438) and antenna. LAN, Bluetooth and WiFi scans **never run at the same time**; they run one after another.
- **Operating system:** Raspberry Pi OS (Bookworm/Trixie, 32-bit). NetworkManager and BlueZ are installed by default. On older Raspbian without NetworkManager the WiFi menu shows "not supported"; the rest of the application works.
- **Privileges:** LAN scanning needs only `CAP_NET_RAW`. Bluetooth and WiFi scans go through D-Bus without root.

## 4. Approaches considered

| | Python + Flask | **Go (chosen)** | Rust |
|---|---|---|---|
| Web process RAM | ~35–50 MB | ~15–25 MB | ~3–8 MB |
| Building for ARMv6 on Windows | not needed (interpreted) | one command, no extra tools | `cross`/`cargo-zigbuild` + C libraries |
| Dependencies on the Pi | Python, apt packages | none | none |

**Chosen: Go.** Rust's few-MB RAM advantage does not matter on the Zero W (the scans are the real load), while its cross-compilation effort is significant. Python's runtime and RAM cost work against the efficiency goal. The code is written from scratch by Claude Code, so the language learning curve is not a factor.

**Also chosen: drop nmap.** ARP discovery and TCP connect probing are written in Go. Installation becomes copying one file, scans start no extra processes and root is not needed. Lost: service/version and OS detection (the old Honet did not use them either).

**UI:** HTML + Bootstrap 5 (the user's preference), rendered on the server with Go's `html/template`.

## 5. Architecture

One program with subcommands:

- `honet serve` — web server and scheduler (runs as a systemd service).
- `honet reset-password` — resets the administrator password on the Pi.
- `honet version`

**Packages (proposal)**
- `internal/config` — flags and environment variables (database path, listen address, TLS).
- `internal/store` — SQLite (`modernc.org/sqlite`, pure Go), schema migrations.
- `internal/scan/lan` — ARP discovery (`AF_PACKET`, pure Go), TCP connect probes, hostname resolution.
- `internal/scan/bt` — BlueZ over D-Bus (`github.com/godbus/dbus/v5`).
- `internal/scan/wifi` — NetworkManager over D-Bus.
- `internal/scheduler` — sequential scan queue.
- `internal/classify` — device type guess (the existing `classify_device` rules, ported).
- `internal/oui` — embedded vendor table.
- `internal/web` — `net/http`, `html/template`, authentication, sessions, embedded static files (`embed`).

**Scheduler:** one goroutine and one job queue. Only one scan runs at a time (shared radio). A manual scan is queued; if a scan of the same kind is already queued or running, no new one is added. Scan state (waiting / running / done, progress) is kept in memory and shown in the UI.

**Default intervals (configurable, at least 1 min, 0 = off):**

| Scan | Interval |
|---|---|
| LAN discovery (ARP) | 5 min |
| LAN port probe | 60 min; also immediately for a device that is new or changed IP |
| Bluetooth | 5 min |
| WiFi networks | 15 min |
| Internet latency (ping) | 1 min (not in the radio queue, light) |
| Internet speed test | 3 hours + manual |

Rationale: discovery is cheap and quiet, so it runs often and also catches devices that connect briefly. Port probes can trigger "port scan" alarms and IP blocks on devices such as NAS boxes and modems, so they run rarely. A WiFi scan interrupts the Pi's own connection for 2–3 s, hence 15 min.

### 5.1 LAN scanning
- The target CIDR comes from the settings. If no interface is chosen, the subnet of the default interface is used.
- **Discovery:** an ARP request to every address at about 50 packets per second. Replies are collected for 2 seconds. The kernel ARP table (`/proc/net/arp`) is read as well.
- **Port probe (a separate job with its own interval):** 45 ports for every known device (the existing `COMMON_PORTS` list), TCP connect, at most 32 concurrent connections, 800 ms timeout. No root needed.
- **Hostname:** reverse DNS (PTR) through the system resolver with a short timeout. Home routers usually publish DHCP names there. An mDNS query is an optional improvement (left to the implementer).
- **Random MAC detection:** the locally administered bit (existing logic).
- **Limits:** the CIDR must be a private range (RFC 1918) and at most /22 (1024 addresses).

### 5.2 Bluetooth scanning
- BlueZ `Adapter1.SetDiscoveryFilter(Transport="auto")` + `StartDiscovery` for about 12 seconds, then `StopDiscovery`.
- From `Device1` objects: address, address type, name/alias, RSSI, Class, Appearance, manufacturer data (company ID).
- **Random addresses:** devices with `AddressType=random` that behave like resolvable private addresses are shown only in the **"Nearby now"** view. Only a summary is stored (they cannot be added to the inventory), because their address changes about every 15 minutes.
- **Devices with fixed addresses** (public or static random) can be added to the inventory and get a name and the "known" mark.
- If there is no Bluetooth adapter or it is off, the menu says so and the application does not crash.

### 5.3 WiFi networks
- NetworkManager over D-Bus: `Device.Wireless.RequestScan` + `GetAllAccessPoints`. Reads SSID, BSSID, frequency/channel, signal strength and security flags.
- The user marks one or more networks as **"my network"** (SSID + known BSSIDs, security type).
- **Suspected fake access point:** if an unknown BSSID broadcasts the SSID of one of my networks, or the same SSID appears with weaker security (for example an open network), an event and a dashboard warning are created. The user can confirm a new BSSID as "also mine" (for example in mesh networks).
- A polkit rule installed by the setup script grants the scan permission (`org.freedesktop.NetworkManager.wifi.scan` → the `honet` user).

### 5.4 Device classification
- The existing Python rules are ported to Go and protected by table tests.
- For Bluetooth the type is guessed from the Class and Appearance fields (headphones, watch, phone, …).
- The user can change the type by hand. A manual type overrides the automatic guess.

### 5.5 Extra features (chosen by the user)

1. **Router impersonation (ARP spoofing) and IP conflict alerts.** The MAC address of the gateway (default route) is stored when first seen. If a later discovery sees a different MAC, a `gateway_mac_changed` event and a red dashboard alert are created. The user can confirm "the router changed, the new MAC is correct". When two different MACs answer for the same IP, an `ip_conflict` event is created.
2. **Risky port marking.** A fixed list: 21 (FTP), 23 (Telnet), 3389 (RDP), 5900 (VNC), 445/139 (SMB), 1433/3306/5432/27017/6379/9200/11211 (exposed databases), 161 (SNMP; shown only if it looks open, since probes are TCP). A ⚠ badge in the device list and a short "why it is risky" note on the detail page. The user can silence each one as "intentional".
3. **Watchlist (offline alerts).** The user can watch any LAN device or fixed-address Bluetooth device. If it is not seen for the configured time (default 15 min, per device), a `device_offline` event is created, and `device_online` when it returns. Offline watched devices are listed at the top of the dashboard.
4. **Who is home (presence).** The user creates "people" and links one or more devices (phone, watch) to each. A person is "home" if one of their devices was seen on the LAN or over Bluetooth in the last 10 minutes. State changes (`arrived`/`left`) are recorded. A separate **People** menu shows everyone's current state and a daily timeline of the last 7 days (simple horizontal bars, no chart library). History is kept for 30 days.
5. **Pi health card.** A small card on the settings page and at the bottom of the dashboard: CPU temperature (`/sys/class/thermal/thermal_zone0/temp`), RAM (`/proc/meminfo`), disk (`statfs` of the database partition), uptime (`/proc/uptime`), Honet's own RSS, under-voltage/throttling (`/sys/devices/platform/soc/soc:firmware/get_throttled`; hidden if missing). Read when the page opens, never written to the database. Fields that do not exist on non-Raspberry Pi systems are not shown.

6. **Internet speed and latency.**
   - **Latency (every minute):** 5 ICMP pings each to the gateway and two internet targets (default `1.1.1.1` and `8.8.8.8`, configurable) (`CAP_NET_RAW` is already granted), plus the DNS resolution time of a domain. Collected in memory and written as **5-minute summaries** (min/avg/max latency, jitter, loss %). This separates "home network" from "provider" problems.
   - **Speed test (every 3 hours + manual):** Cloudflare's open endpoints (`speed.cloudflare.com/__down?bytes=…`, `/__up`). At most 10 s per direction, requests of increasing size, result in Mbps. Latency under load is measured too, and the amount of data used is recorded. Ookla (terms of use) and M-Lab (adds the IP to a public data set) are deliberately not used.
   - **Scheduling:** the speed test goes through the radio queue and never runs together with LAN/BT/WiFi scans. Ping measurements run outside the queue and are skipped while a speed test runs (so they do not distort it).
   - **Pi limit note:** if the measured speed is close to the Pi's practical limit (~25 Mbps, configurable threshold), the result shows "may be limited by the Pi". On the user's line this limit is not reached in practice, so the measurements are taken as realistic.
   - **Internet menu:** current values, the last speed test, a "Test now" button and **graphs of the last 7 days** (download/upload; latency and packet loss). Graphs are inline SVG rendered on the server; no JavaScript chart library. Outage periods (high loss) are marked on the graph and create an `internet_outage` event.
   - **Retention:** ping summaries 30 days, speed tests 90 days.

### 5.6 OUI (vendor) table
- The IEEE OUI list is converted at build time into a compressed, sorted table embedded in the program. It is updated with `go generate`.
- It is searched with binary search instead of a map, so it takes no RAM.

## 6. Security

Flaws in the old code and how v2 addresses them:

| Old problem | v2 solution |
|---|---|
| A "Reset Credentials" button deleted the account and let the next visitor register as admin | No credential reset over the web. Only `honet reset-password` on the Pi. |
| On first setup, whoever opened the page first became the admin | On first start a one-time **setup code** is generated and written to the systemd journal. The registration form asks for it. |
| Unsalted SHA-256 passwords | bcrypt (cost 10), constant-time comparison. |
| Lockout bypass through `X-Forwarded-For` | The client IP comes from `RemoteAddr`. Headers are trusted only from a proxy listed in the settings (default: none). |
| Lockout only per IP | Per-IP lockout (5 failures in 10 minutes → 10 minutes) **plus** global slowdown: when failures from all IPs grow, every attempt gets an increasing delay. |
| The login attempts table grew without limit | Records older than 30 days and beyond 1000 rows are deleted. |
| "Hard Reset" deleted all data without confirmation | Removed from the web. Deleting the file on the Pi is enough. |
| The raw database export leaked the password hash and login IPs | No raw export. Devices are exported as CSV/JSON without sensitive fields. |
| The CIDR went to nmap as an argument without validation | No nmap. The CIDR is parsed; a private range and at most /22 are required. |
| Streamlit listened on `0.0.0.0` and nginx could be bypassed | The application serves TLS itself; nginx is unnecessary. |
| The scanner ran as root | A separate `honet` user with only `CAP_NET_RAW`. |

**Other measures**
- **HTTPS by default:** on first start a self-signed ECDSA P-256 certificate is generated. The `--http` flag switches to plain HTTP. Users can supply their own certificate.
- **Sessions:** 32-byte random key kept in server memory. The cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` over HTTPS. Idle timeout 15 min (configurable). Sessions end when the application restarts.
- **CSRF:** a session-bound token in every POST form.
- **Security headers:** `Content-Security-Policy: default-src 'self'` (no inline script), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **Output escaping:** every value that comes from the network (hostname, Bluetooth name, SSID) is escaped automatically by `html/template`. SSIDs and Bluetooth names are also length-limited and stripped of control characters.
- **Password policy:** at least 10 characters.
- **Login history:** the settings page shows the last 50 login attempts (IP, time, result).

## 7. Data model (proposal)

- `users` — one row: username, bcrypt hash, creation and last login time.
- `settings` — key/value: CIDR, interface, scan intervals, session timeout, trusted proxy.
- `devices` — LAN devices: id, mac (unique; an `ip:` key when there is no MAC), name, note, known, manual type, automatic type, vendor, last IP, hostname, random MAC, first/last seen.
- `device_ports` — device, port, open, first/last seen.
- `bt_devices` — address, address type, name, alias, known, type, vendor/company, last RSSI, first/last seen. For random addresses only a summary of the last 24 hours.
- `wifi_aps` — BSSID, SSID, channel, security, last signal, first/last seen.
- `my_networks` — SSID, expected security, list of confirmed BSSIDs.
- `events` — time, kind (`new_device`, `ip_changed`, `port_opened`, `port_closed`, `bt_new`, `wifi_twin_suspect` …), related record, read.
- `login_attempts` — IP, time, success.
- `watchlist` — watched device (LAN or BT), offline threshold, last state.
- `people` / `person_devices` — person name and linked devices.
- `presence` — person, state (`home`/`away`), start time (written only on changes).
- `port_ack` — risky ports the user silenced as "intentional".
- `gateway` — gateway IP and confirmed MAC.
- `latency_5m` — time, target, min/avg/max latency, jitter, loss %, DNS time.
- `speedtests` — time, download/upload Mbps, latency under load, data used, error.
- `scans` — kind, start, end, result count, error.

**SD card protection:** SQLite WAL + `synchronous=NORMAL`. Every scan result is written in **one transaction**. Only changed fields are updated; `last_seen` is updated on every scan, but within that one transaction. Events are kept 90 days, scan records 30 days. Database path: `/var/lib/honet/honet.db`.

## 8. User interface

Server-rendered pages, Bootstrap 5 (embedded locally, no CDN), dark theme with the existing green accent. The UI language is English (as are the README and the repository).

**Menu:** Network · Bluetooth · WiFi · People · Internet · Events · Settings · Logout

- **Network (home page):** at the top, the number of unknown devices, the last scan time and a "Scan now" button. Unknown devices first. Each row shows name, IP, MAC, vendor, type, open ports and an "Identify" button (name, type, note, known mark).
- **Device detail:** port history (risky ports explained), IP history, events, add to the watchlist.
- **Dashboard banner:** router impersonation / IP conflict alert (red), number of unknown devices, offline watched devices. The Pi health card at the bottom.
- **Bluetooth:** "Nearby now" (seen in the last scan, with RSSI) and "Inventory" (saved fixed-address devices).
- **WiFi:** table of nearby networks, "My networks" management, fake access point alerts.
- **People:** everyone's current state (home/away), a daily timeline of the last 7 days, linking people and devices.
- **Internet:** current latency/loss, the last speed test, "Test now", SVG graphs of the last 7 days.
- **Events:** timeline with unread events highlighted, "mark all as read".
- **Settings:** CIDR, interface, scan intervals, session timeout, password change, CSV/JSON export, login history, a printable report page (saved as PDF from the browser; replaces reportlab).
- **Login / Setup:** setup code + username + password.

**Automatic refresh:** a small vanilla JS file (no external library) refreshes only the list fragment every 30 seconds (an HTML fragment fetched with `fetch`). Refreshing stops while the tab is not visible. Progress is shown while a scan runs.

```
┌ Honet ──────── [Network] [Bluetooth] [WiFi] [Events] [Settings] ┐
│ ⚠ 2 unknown devices            Last scan 14:32 · [▶ Scan now]   │
├──────────────────────────────────────────────────────────────────┤
│ ⚠ ?            192.168.1.57  random MAC     —          [Identify]│
│ ⚠ ?            192.168.1.63  Espressif      80         [Identify]│
│ ✔ Living TV    192.168.1.20  LG             8008, 8443           │
│ ✔ Modem        192.168.1.1   ZTE            53, 80, 443          │
└──────────────────────────────────────────────────────────────────┘
```

## 9. Deployment

- **Build:** a `Makefile`/PowerShell script for all targets. `-trimpath -ldflags "-s -w"` for a small file.
- **Installation (Pi):** `install.sh` — copies the file to `/usr/local/bin/honet`, creates the `honet` system user (adds it to the `bluetooth` group), installs the systemd unit and the polkit rule, starts the service and shows the setup code.
- **systemd unit:** `User=honet`, `StateDirectory=honet`, `AmbientCapabilities=CAP_NET_RAW`, `CapabilityBoundingSet=CAP_NET_RAW`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `MemoryMax=96M`, `Restart=on-failure`.
- **Port:** default `:8443` (HTTPS). Not 443 by default, since binding it needs an extra privilege.
- **Password reset:** `sudo -u honet honet reset-password` (the `honet` user owns the database).
- **Time zone:** Go's embedded `time/tzdata` package. Times are shown in the Pi's local time zone and stored as UTC.
- **Docker (secondary path):** `FROM scratch` + the binary. `network_mode: host`, `cap_drop: ALL` + `cap_add: NET_RAW`, `/run/dbus/system_bus_socket` mounted for Bluetooth/WiFi, data written to a `/data` volume (fixing the data loss bug of the old version). The setup code is shown with `docker logs`. The nginx service is removed.
- **CI (GitHub Actions):** when a tag is pushed, tests run, binaries for four architectures are attached to a GitHub Release, and a multi-architecture Docker image (`linux/arm/v6`, `arm/v7`, `arm64`, `amd64`) is published.
- **Removed:** the Python code (`app.py`, `net_scan.py`, `sqlite.py`, `requirements.txt`, `.streamlit/`), `deploy/docker/nginx.conf`, `deploy/k8s/honet.yaml` (broken placeholder image name; unnecessary `hostPID`). The old code stays in the git history.
- **README** is rewritten with the new installation, build and security information. Screenshots are updated with the new UI.

## 10. Testing

- **Unit tests:** classification rules (table tests), OUI lookup, CIDR validation, change/event generation, password and session logic, CSRF, lockout and slowdown, Bluetooth address type handling, the fake access point rule.
- **Scanners behind interfaces:** with fake LAN, Bluetooth and WiFi scanners, the scheduler and event generation can be tested on Windows.
- **HTTP tests:** login, pages that need authentication and security headers, with `httptest`.
- **Extra feature tests:** gateway MAC change and IP conflict events, risky port rules and silencing, watchlist threshold timing, home/away transitions (with a fake clock), health card readers skipping silently when files are missing.
- **Manual test (Zero W, Raspberry Pi OS):** the installation script, real LAN/BT/WiFi scans, resource measurements.

## 11. Success criteria

- On the Zero W: idle RSS < 30 MB; < 50 MB while scanning; binary < 20 MB.
- LAN scan of a /24 network (discovery + 45 ports) < 90 seconds.
- Runs on the Pi without `apt install` (apart from BlueZ and NetworkManager, which Raspberry Pi OS ships by default).
- Every flaw in §6 is closed.
- Comfortable to use from a phone browser.

## 12. Delivery phases

- **Phase 1:** Go skeleton, security (setup code, login, sessions, CSRF, TLS), SQLite, LAN discovery + port probes, classification, OUI, inventory, events, router impersonation/IP conflict, risky ports, watchlist, Pi health card, Network/Events/Settings pages, systemd installation, build scripts. Delivered working on the Zero W; the user tries it on the Pi.
- **Phase 2:** Bluetooth, WiFi networks and fake AP detection, who is home (People), internet measurement and graphs, Docker, CI, README.

## 13. Left to the implementer

- Hostname lookup over mDNS (as an extra, if done).
- Exact package split and file names.
- Bootstrap version (5.3.x) and custom CSS details.
- Fine-tuning ARP rate, port timeout and concurrency by measuring on the Pi (the values above are starting points).
- Details of the Bluetooth device type mapping table.
