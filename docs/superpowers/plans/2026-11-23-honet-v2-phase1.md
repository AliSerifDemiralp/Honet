# Honet v2 — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python/Streamlit Honet with a single-file Go program that runs on a first-generation Raspberry Pi Zero W. Phase 1: secure login, LAN discovery + port probing, inventory, events, router impersonation/IP conflict, risky ports, watchlist, Pi health card, systemd installation.

**Architecture:** One `honet` program (`serve`, `reset-password`, `version`). A single scheduler goroutine runs scans one after another; results are written through the `inventory` package in one SQLite transaction. The web layer renders HTML on the server with `net/http` + `html/template`; Bootstrap 5 and all templates are embedded in the program with `embed`.

**Tech Stack:** Go (latest stable, at least 1.24), `modernc.org/sqlite`, `github.com/mdlayher/arp`, `golang.org/x/crypto/bcrypt`, `golang.org/x/term`, Bootstrap 5.3 (latest patch release, local file).

**Spec:** `docs/superpowers/specs/2026-11-23-honet-go-rewrite-design.md` (§12 "Phase 1" scope). Anyone implementing this plan reads the spec too.

## Global Constraints

- Module path: `github.com/AliSerifDemiralp/honet`.
- `CGO_ENABLED=0`; at the end of every task both `go test ./...` (Windows) and `GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build ./...` must pass.
- Linux-specific code (`AF_PACKET`, `statfs`) lives in `_linux.go` files; other operating systems get an `_other.go` counterpart that fakes it or returns an error, so the tests run on Windows.
- Nothing requires root. The only privilege is `CAP_NET_RAW`.
- No outbound connections: no CDN, telemetry or internet requests (except the speed test in Phase 2).
- UI text in English.
- No inline `<script>` or `style="..."` in templates (CSP: `default-src 'self'`).
- Times are stored in the database as UTC RFC3339Nano text and shown in `time.Local`. `import _ "time/tzdata"` in `cmd/honet/main.go`.
- Defaults: data directory `/var/lib/honet`, database `<data dir>/honet.db`, listen `:8443`, HTTPS on.
- Intervals: discovery 5 min, port probe 60 min; configurable, at least 1 min, 0 = off.
- Discovery: ARP at ~50 packets/s, replies collected for 2 s after the last request. Port probe: TCP connect, 32 concurrent, 800 ms timeout.
- CIDR: RFC 1918 only (`10/8`, `172.16/12`, `192.168/16`), prefix ≥ /22.
- Auth: bcrypt cost 10, password ≥ 10 characters, 5 failures per IP in 10 min → 10 min lockout, session idle timeout 15 min by default.
- Retention: events 90 days, scan records 30 days, login attempts 30 days and at most 1000 rows.
- Commit messages end with: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **The Pi has no clock (no RTC).** At boot, until NTP syncs, the clock may say 1970 or an old date. Expected: while the year is below 2025 the scheduler starts no scans and the watchlist is not evaluated. → tests in Task 10 and Task 9.
2. **Discovery while the network is down.** If WiFi dropped, discovery fails or finds no devices. Expected: the scan counts as failed and no events are created (no "all watched devices offline", no "router disappeared" alarm). → test in Task 9.
3. **Malicious text from the network.** A PTR name may contain `<script>`, control characters or 500 characters. Expected: cut to 64 characters, control characters removed, shown escaped on the page. → tests in Task 6 and Task 15.
4. **The Pi itself in the list.** ARP does not answer for the Pi's own address. Expected: the Pi appears in the list with its own interface MAC as "this device" and does not count as "unknown". → tests in Task 6 and Task 9.
5. **Reuse of the setup code.** If `/setup` is posted again with the same code after the administrator was created. Expected: rejected, the existing account does not change. → tests in Task 12 and Task 15.

---

## File Structure

```
cmd/honet/main.go            subcommands, serve wiring, reset-password
internal/config/             flag + environment variable parsing
internal/store/              opening SQLite, schema migrations, settings
internal/netutil/            CIDR validation, MAC helpers, /proc/net parsing, text cleaning
internal/oui/                embedded vendor table + generator (gen/)
internal/classify/           device type rules
internal/risk/               risky port table
internal/scan/lan/           ARP discovery, TCP prober, reverse DNS
internal/inventory/          devices, ports, events, gateway, watchlist
internal/scheduler/          job queue
internal/app/                Runner that executes scan jobs
internal/auth/               user, setup code, login attempts, client IP
internal/session/            session manager
internal/tlsutil/            self-signed certificate
internal/health/             Pi health readings
internal/web/                server, middleware, handlers, templates/, static/
deploy/systemd/honet.service
deploy/install.sh
build.ps1
```

---

### Task 1: Remove the old code, set up the Go skeleton

**Files:**
- Delete: `app.py`, `net_scan.py`, `sqlite.py`, `requirements.txt`, `.streamlit/`, `deploy/docker/`, `deploy/k8s/`, `.github/workflows/docker.yaml`, `.dockerignore`
- Create: `go.mod`, `cmd/honet/main.go`, `cmd/honet/main_test.go`, `build.ps1`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `var version = "dev"` (set with `-ldflags "-X main.version=..."`); `func run(args []string, stdout, stderr io.Writer) int` — subcommand dispatcher, returns the exit code.

- [ ] **Step 1: Prerequisite.** If Go is not installed, run `winget install GoLang.Go` with the user's approval; in a new terminal `go version` must show at least `go1.24`.
- [ ] **Step 2: Delete the old files** (list above; Docker and CI come back in Phase 2). Add `/honet`, `/dist/`, `*.db`, `*.db-wal`, `*.db-shm` to `.gitignore`.
- [ ] **Step 3: `go mod init github.com/AliSerifDemiralp/honet`.**
- [ ] **Step 4: Failing test** `cmd/honet/main_test.go`:

```go
func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 { t.Fatalf("code %d", code) }
	if !strings.Contains(out.String(), "honet dev") { t.Fatalf("got %q", out.String()) }
}
func TestRunUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"nope"}, &out, &errb); code != 2 { t.Fatalf("code %d", code) }
	if !strings.Contains(errb.String(), "usage") { t.Fatal("no usage") }
}
```

- [ ] **Step 5:** `go test ./cmd/honet/` → FAIL (`run` undefined).
- [ ] **Step 6: Write `run` and `main`.** `version` → `honet <version>`; no arguments or unknown → usage text on stderr, code 2. `serve` and `reset-password` are `not implemented` + code 1 for now. `main` → `os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))`. `import _ "time/tzdata"`.
- [ ] **Step 7: `build.ps1`.** Produces `dist/honet-linux-armv6`, `-armv7`, `-arm64`, `-amd64`; `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always --dirty)"`. Restores the environment variables after each target.
- [ ] **Step 8:** `go test ./...` PASS; `./build.ps1` produces four files.
- [ ] **Step 9: Commit** — `chore: replace Python app with Go skeleton`.

---

### Task 2: Configuration

**Files:** Create `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces:

```go
type Config struct {
	DataDir   string // default /var/lib/honet; env HONET_DATA_DIR; --data-dir
	DBPath    string // <DataDir>/honet.db; --db
	Listen    string // ":8443"; env HONET_LISTEN; --listen
	PlainHTTP bool   // --http
	CertFile  string // --cert (self-signed if empty)
	KeyFile   string // --key
	DevAssets string // --dev-assets: read templates/static files from disk (development)
}
func Parse(args []string, getenv func(string) string) (Config, error)
```

- [ ] **Step 1: Failing test** — table test: no arguments → `DataDir=/var/lib/honet`, `DBPath=/var/lib/honet/honet.db`, `Listen=":8443"`; `HONET_DATA_DIR=/x` → `DBPath=/x/honet.db`; `--db /y.db` overrides the env; `--cert a` without `--key` is an error. DBPath is joined with `path.Join` (Linux path, `/` on Windows too).
- [ ] **Step 2:** `go test ./internal/config/` → FAIL.
- [ ] **Step 3:** Implement with `flag.NewFlagSet("serve", flag.ContinueOnError)`; flag > env > default.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(config): flags and env parsing`.

---

### Task 3: SQLite store, schema and settings

**Files:** Create `internal/store/store.go`, `internal/store/schema.go`, `internal/store/settings.go`, `internal/store/store_test.go`

**Interfaces:**
- Produces:

```go
type Store struct{ DB *sql.DB }
func Open(path string) (*Store, error)
func (s *Store) Close() error
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error

type Settings struct {
	CIDR              string        // "" = the interface's own subnet
	Interface         string        // "" = default route interface
	DiscoveryInterval time.Duration // 5m
	PortInterval      time.Duration // 60m
	SessionIdle       time.Duration // 15m
	WatchAfter        time.Duration // 15m (default watchlist threshold)
	TrustedProxies    []netip.Prefix
}
func DefaultSettings() Settings
func (s *Store) LoadSettings(ctx context.Context) (Settings, error)
func (s *Store) SaveSettings(ctx context.Context, v Settings) error
func (s *Store) GetKV(ctx context.Context, key string) (string, bool, error)
func (s *Store) SetKV(ctx context.Context, key, val string) error
func FormatTime(t time.Time) string     // UTC RFC3339Nano
func ParseTime(s string) (time.Time, error)
```

`Open`: `_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)`, `SetMaxOpenConns(1)`, then runs the migrations. File permissions 0600 (create the directory with 0700 if missing).

Schema (ordered migrations tracked in a `schema_version` table; v1 is all of the below). Phase 2 tables are **not** here; they come with their own migrations.

```sql
users(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login TEXT)
kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)
devices(id INTEGER PRIMARY KEY, mac TEXT UNIQUE, name TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  known INTEGER NOT NULL DEFAULT 0, manual_type TEXT NOT NULL DEFAULT '', auto_type TEXT NOT NULL DEFAULT 'unknown',
  vendor TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '', last_ip TEXT NOT NULL, randomized INTEGER NOT NULL DEFAULT 0,
  is_self INTEGER NOT NULL DEFAULT 0, watched INTEGER NOT NULL DEFAULT 0, watch_after_s INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)
device_ports(device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, port INTEGER NOT NULL, open INTEGER NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(device_id, port))
ip_history(device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ip TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, PRIMARY KEY(device_id, ip))
events(id INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL, device_id INTEGER, detail TEXT NOT NULL DEFAULT '', read INTEGER NOT NULL DEFAULT 0)
gateway(id INTEGER PRIMARY KEY CHECK(id=1), ip TEXT NOT NULL, mac TEXT NOT NULL, pending_mac TEXT NOT NULL DEFAULT '')
login_attempts(id INTEGER PRIMARY KEY, ip TEXT NOT NULL, at TEXT NOT NULL, success INTEGER NOT NULL)
scans(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, found INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '')
CREATE INDEX events_at ON events(at); CREATE INDEX login_attempts_ip_at ON login_attempts(ip, at);
```

Settings are stored in `kv` (`settings.cidr`, `settings.discovery_interval_s` …); a missing key → the default.

- [ ] **Step 1: Failing tests:** `TestOpenCreatesSchema` (open in a temp dir, `schema_version`=1, the `devices` table exists, after close-and-reopen the version is still 1 and the migration does not run again); `TestSettingsRoundTrip` (empty DB → equal to `DefaultSettings()`; save-and-load of `DiscoveryInterval=2m`, `TrustedProxies=[192.168.1.2/32]` is equal); `TestTimeRoundTrip`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(store): sqlite schema and settings`.

---

### Task 4: Network helpers

**Files:** Create `internal/netutil/cidr.go`, `mac.go`, `procnet.go`, `text.go` and their `_test.go` counterparts

**Interfaces:**
- Produces:

```go
var ErrNotPrivate, ErrTooLarge error
func ValidateScanCIDR(s string) (netip.Prefix, error) // returns Masked()
func Hosts(p netip.Prefix) []netip.Addr               // excludes network and broadcast (does not exclude for /31 and /32)
func NormalizeMAC(s string) (string, error)           // "aa-bb-cc-dd-ee-ff" → "AA:BB:CC:DD:EE:FF"
func IsLocallyAdministered(mac string) bool
type ARPEntry struct{ IP netip.Addr; MAC, Iface string }
func ParseProcARP(r io.Reader) ([]ARPEntry, error)    // flags 0x0 and 00:00:00:00:00:00 are skipped
func ParseProcRoute(r io.Reader) (iface string, gw netip.Addr, err error) // first line with destination 00000000; little-endian hex
func CleanText(s string, max int) string              // removes control characters, truncates, UTF-8 safe
```

- [ ] **Step 1: Failing tests:**
  - `ValidateScanCIDR`: `"192.168.1.0/24"` ok; `"192.168.1.77/24"` → `192.168.1.0/24`; `"10.0.0.0/22"` ok; `"10.0.0.0/21"` → `ErrTooLarge`; `"8.8.8.0/24"` → `ErrNotPrivate`; `"172.32.0.0/24"` → `ErrNotPrivate`; `"--script=x"` → error; IPv6 → error.
  - `len(Hosts(192.168.1.0/24)) == 254`, first `.1`, last `.254`.
  - `IsLocallyAdministered("DA:A1:19:00:00:01") == true`, `("B8:27:EB:00:00:01") == false`.
  - Fixtures from real file samples for `ParseProcARP` and `ParseProcRoute` (route: `wlan0	00000000	0101A8C0	0003 …` → `wlan0`, `192.168.1.1`).
  - `CleanText("<b>\x00tv\n</b>", 64) == "<b>tv</b>"`; a 500-character input is cut to 64 runes.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(netutil): cidr, mac, procnet, text helpers`.

---

### Task 5: OUI table

**Files:** Create `internal/oui/oui.go`, `internal/oui/oui_test.go`, `internal/oui/gen/main.go`, `internal/oui/oui.bin.gz` (generated, committed)

**Interfaces:**
- Produces: `func Lookup(mac string) string` (`""` if not found); `func load(r io.Reader) (*table, error)` (for tests).

Binary format (inside gzip): `uint32 n`; `n` records of `[3]byte prefix | uint32 offset | uint16 len`, sorted by prefix; then one contiguous UTF-8 block of all vendor names. `Lookup` opens it on first use with `sync.Once` and searches with `sort.Search`. No map.

Generator: `go run ./internal/oui/gen -in oui.csv -out internal/oui/oui.bin.gz`; `oui.csv` = `https://standards-oui.ieee.org/oui/oui.csv` (MA-L). Names go through `CleanText(..., 48)`. A `//go:generate` line in `oui.go` documents it; the CSV is not committed.

- [ ] **Step 1: Failing test:** `load` of a small three-record table (made with the gen package's `encode` function) → `"B8:27:EB:12:34:56"` → `"Raspberry Pi Foundation"`, unknown → `""`, short/broken MAC → `""`. Also `Lookup("B8:27:EB:00:00:00") != ""` for the real embedded table.
- [ ] **Step 2:** FAIL. **Step 3:** Write `gen` + `oui.go`, download the CSV, generate the table (expected size < 1 MB). **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(oui): embedded vendor table`.

---

### Task 6: LAN scanners (ARP discovery, TCP probe, reverse DNS)

**Files:** Create `internal/scan/lan/types.go`, `arp_linux.go`, `arp_other.go`, `probe.go`, `resolve.go`, `probe_test.go`, `resolve_test.go`, `arp_test.go`

**Interfaces:**
- Produces:

```go
type Host struct {
	IP         netip.Addr
	MAC        string // in NormalizeMAC form
	Vendor     string
	Hostname   string
	Randomized bool
	Self       bool   // the Pi itself
}
type Discoverer interface {
	Discover(ctx context.Context, iface string, p netip.Prefix) ([]Host, error) // only IP+MAC(+Self); if two MACs answer for one IP, both are returned
}
func NewARPDiscoverer(pps int, collect time.Duration) Discoverer // linux; on other OSes Discover returns ErrUnsupported
var ErrUnsupported error

var CommonPorts = []int{20, 21, 69, 22, 23, 3389, 5900, 5985, 5986, 25, 110, 143, 465, 587,
	53, 67, 68, 123, 139, 161, 162, 389, 445, 80, 443, 8000, 8008, 8080, 8443, 5000, 3000,
	5432, 3306, 1433, 1521, 27017, 6379, 9042, 9200, 11211, 6443, 10250, 9092, 2181, 9090, 5601}
type Prober interface{ Probe(ctx context.Context, ip netip.Addr, ports []int) ([]int, error) }
type TCPProber struct{ Concurrency int; Timeout time.Duration } // 32, 800ms; sorted result
type Resolver interface{ LookupAddr(ctx context.Context, addr string) ([]string, error) }
func ReverseName(ctx context.Context, r Resolver, ip netip.Addr, timeout time.Duration) string // first name, trailing "." removed, CleanText(…, 64), error → ""
func Enrich(hosts []Host, ouiLookup func(string) string, names func(netip.Addr) string) // fills Vendor, Randomized, Hostname
```

`arp_linux.go`: `net.InterfaceByName` → `arp.Dial`; `Request` over `Hosts(p)` paced by `time.Ticker(1s/pps)`; a separate goroutine collects replies with `Read`; close `collect` after the last request; add `/proc/net/arp` entries in the same subnet (IP+MAC pairs deduplicated); the interface's own IP+MAC is added as `Self: true`. Note: the ARP side is verified on the Pi in Task 19, not by a unit test; `arp_test.go` only tests the dedup helper.

- [ ] **Step 1: Failing tests:**
  - `TestTCPProber`: open two `net.Listen("tcp","127.0.0.1:0")`, close one port; `Probe(127.0.0.1, [open1, closed, open2])` → `[open1, open2]` sorted; cancelling with a 1 ms context returns no error, just the results so far.
  - `TestCommonPortsCount`: `len(CommonPorts) == 46`, no duplicates.
  - `TestReverseName`: a fake Resolver returns `"<script>tv.lan.\x07"` → `"<script>tv.lan"`; error → `""`; 600 characters → 64 runes.
  - `TestMergeDedup`: ARP replies + `/proc/net/arp` with the same IP/MAC → one; same IP with different MACs → both records kept.
  - `TestEnrich`: `DA:..` → `Randomized=true`; vendor lookup is called.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS + ARMv6 cross build.
- [ ] **Step 5: Commit** — `feat(lan): arp discovery, tcp prober, reverse dns`.

---

### Task 7: Classification and risky ports

**Files:** Create `internal/classify/classify.go`, `classify_test.go`, `internal/risk/risk.go`, `risk_test.go`

**Interfaces:**
- Produces:

```go
// classify
func Classify(vendor string, ports []int, hostname string, randomized bool) string
// Returned types (identical to Python): "vm","router","smart_tv","apple_device","phone_or_tablet","windows_pc",
// "server","pc","pc_or_laptop","unknown_passive_device","iot_or_embedded","unknown"

// risk
type Risk struct{ Port int; Name, Reason string }
func Lookup(port int) (Risk, bool)
```

The rules are exactly the old `net_scan.py` `classify_device` function, in the same order (in git history: `git show 169fda5:net_scan.py`). Risky ports: 21 FTP, 23 Telnet, 3389 RDP, 5900 VNC, 445 SMB, 139 NetBIOS, 1433 MSSQL, 3306 MySQL, 5432 PostgreSQL, 27017 MongoDB, 6379 Redis, 9200 Elasticsearch, 11211 Memcached, 161 SNMP. `Reason` is one English sentence (e.g. Telnet: `"Sends passwords in plain text; use SSH instead."`).

- [ ] **Step 1: Failing tests** (table): `("VMware",nil)`→`vm`; `("",[53,80])`→`router`; `("LG Electronics",[8008])`→`smart_tv`; `("Apple",nil)`→`phone_or_tablet`; `("Apple",[7000])`→`apple_device`; `("",nil,"",randomized=true)`→`phone_or_tablet`; `("",[3389])`→`windows_pc`; `("",[22,5432])`→`server`; `("Intel",[22])`→`pc`; `("Dell",nil)`→`pc_or_laptop`; `("",nil,"my-iphone",false)`→`phone_or_tablet`; `("",nil)`→`unknown_passive_device`; `("",[80])`→`iot_or_embedded`; `("",[25,110,143,465])`→`unknown`. Risk: `Lookup(23)` exists, `Lookup(443)` does not, every record's `Reason` is non-empty.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat: device classification and risky port table`.

---

### Task 8: Inventory — writing discovery and port results

**Files:** Create `internal/inventory/inventory.go`, `apply.go`, `query.go`, `events.go`, `apply_test.go`, `query_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.FormatTime`, `lan.Host`, `classify.Classify`, `risk.Lookup`.
- Produces:

```go
const (
	EvNewDevice = "new_device"; EvIPChanged = "ip_changed"; EvIPConflict = "ip_conflict"
	EvGatewayMACChanged = "gateway_mac_changed"; EvPortOpened = "port_opened"; EvPortClosed = "port_closed"
	EvDeviceOffline = "device_offline"; EvDeviceOnline = "device_online"
)
var ErrEmptyDiscovery error
type Port struct{ Port int; Open, Acked bool; Risk *risk.Risk; FirstSeen, LastSeen time.Time }
type Device struct {
	ID int64; MAC, Name, Notes, Vendor, Hostname, AutoType, ManualType string
	Known, Randomized, Self, Watched, Online bool; WatchAfter time.Duration
	LastIP netip.Addr; FirstSeen, LastSeen time.Time; Ports []Port
}
func (d Device) Type() string        // ManualType if set, otherwise AutoType
func (d Device) Unknown() bool       // !Known && !Self
func (d Device) RiskyOpen() []Port   // Open && Risk != nil && !Acked
type Event struct{ ID int64; At time.Time; Kind string; DeviceID int64; Detail string; Read bool }
type GatewayAlert struct{ IP netip.Addr; OldMAC, NewMAC string }

type Inventory struct{ /* st *store.Store; now func() time.Time */ }
func New(st *store.Store, now func() time.Time) *Inventory
func (inv *Inventory) ApplyDiscovery(ctx context.Context, hosts []lan.Host, gw netip.Addr) (needPorts []int64, err error)
func (inv *Inventory) ApplyPorts(ctx context.Context, deviceID int64, open []int) error
func (inv *Inventory) OnlineIDs(ctx context.Context) ([]int64, error)
func (inv *Inventory) IPOf(ctx context.Context, id int64) (netip.Addr, error)
func (inv *Inventory) List(ctx context.Context) ([]Device, error)      // Unknown first, then by IP
func (inv *Inventory) Get(ctx context.Context, id int64) (Device, []IPRecord, []Event, error)
func (inv *Inventory) Events(ctx context.Context, limit int) ([]Event, error)
func (inv *Inventory) UnreadCount(ctx context.Context) (int, error)
func (inv *Inventory) MarkAllRead(ctx context.Context) error
func (inv *Inventory) GatewayAlert(ctx context.Context) (*GatewayAlert, error) // when pending_mac is not empty
type IPRecord struct{ IP netip.Addr; FirstSeen, LastSeen time.Time }
```

`ApplyDiscovery` rules (all in one `store.Tx`):
- `len(hosts)==0` or no hosts other than `Self` → `ErrEmptyDiscovery`, nothing is written.
- Key: MAC; `"ip:<ip>"` when there is no MAC.
- New device → insert, `EvNewDevice` (no event for Self), add to `needPorts`.
- IP changed → update `last_ip`, `ip_history`, `EvIPChanged` (detail `"old → new"`), add to `needPorts`.
- Hosts reporting the same IP with different MACs → `EvIPConflict` (detail: both MACs). No repeat event for the same conflict within 1 hour.
- If `gw` is valid: if there is no `gateway` row, create it with gw's MAC. If there is one and the MAC at the gw IP differs: if `pending_mac` is empty or different, set it and create `EvGatewayMACChanged`; no repeat event for the same pending_mac.
- Every device seen: `last_seen=now`, `online=1`; vendor/hostname are updated only when not empty; `auto_type = Classify(vendor, open ports, hostname, randomized)`.

`ApplyPorts`: newly open → insert, `EvPortOpened` (with `Risk.Name` in the detail if risky); open → closed → `open=0`, `EvPortClosed`; `auto_type` is recalculated. On a device's first port probe (`device_ports` empty) **no** `port_opened` events are created (10 ports of a new device should not become 10 events).

- [ ] **Step 1: Failing tests** (temp DB, fixed `now`):
  - `TestNewDeviceEvent`: two hosts → 2 devices, 2 `new_device`, `needPorts` has both IDs; the same discovery again → no new events, `needPorts` empty.
  - `TestSelfHasNoEventAndNotUnknown`: a `Self:true` host → no event, `List()[0].Unknown()==false`.
  - `TestIPChange`: same MAC, new IP → `ip_changed`, `needPorts` has that ID, `ip_history` has 2 rows.
  - `TestIPConflict`: same IP with two MACs → one `ip_conflict`; again 30 min later → none; 61 min later → one more.
  - `TestGatewayMACChange`: the first discovery stores gw MAC A (no event); then B → `gateway_mac_changed`, `GatewayAlert().NewMAC=="B"`; B again → no new event.
  - `TestEmptyDiscovery`: `nil` and Self-only → `ErrEmptyDiscovery`, the `events` count does not change, `last_seen` does not change.
  - `TestApplyPorts`: first call `[22,23]` → no event, `RiskyOpen()` contains 23; second `[22,80]` → `port_opened 80`, `port_closed 23`; `auto_type` up to date.
  - `TestListOrder`: unknown `.50` comes before known `.2`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(inventory): apply discovery and port results`.

---

### Task 9: Inventory — user actions, watchlist, cleanup

**Files:** Create `internal/inventory/user.go`, `watch.go`, `prune.go`, `user_test.go`, `watch_test.go`, `prune_test.go`

**Interfaces:**
- Produces:

```go
func (inv *Inventory) Identify(ctx context.Context, id int64, name, notes, manualType string, known bool) error // name/notes CleanText(…,64/500); manualType "" or one of the classify types, otherwise ErrBadType
func (inv *Inventory) SetWatch(ctx context.Context, id int64, on bool, after time.Duration) error            // after 0 → the settings default; at least 1m
func (inv *Inventory) AckPort(ctx context.Context, id int64, port int, acked bool) error
func (inv *Inventory) ConfirmGateway(ctx context.Context) error // mac = pending_mac, pending_mac = ''
func (inv *Inventory) Delete(ctx context.Context, id int64) error
func (inv *Inventory) EvaluateWatch(ctx context.Context, lastGoodDiscovery time.Time) error
func (inv *Inventory) WatchedOffline(ctx context.Context) ([]Device, error)
func (inv *Inventory) Prune(ctx context.Context) error // events > 90d, scans > 30d
var ErrBadType error
```

`EvaluateWatch`: does nothing if `now.Year() < 2025`. Only `watched=1` devices; if `last_seen < now - watch_after` **and** `lastGoodDiscovery > last_seen + watch_after` (successful discoveries happened during that time but the device was not seen) → `online=0` + `EvDeviceOffline` (once). If `ApplyDiscovery` sees an offline watched device again → `online=1` + `EvDeviceOnline` (this rule is added to the "every device seen" step of Task 8; the test is here).

- [ ] **Step 1: Failing tests:**
  - `TestIdentify`: name `"<b>TV\x00"` → `"<b>TV"`; `manualType="toaster"` → `ErrBadType`; `known=true` → `Unknown()==false`.
  - `TestWatchOffline`: watched device, `after=15m`; evaluation 10 min later → no event; 20 min later with `lastGoodDiscovery` = now → `device_offline`; evaluating again → no second event; then seen in a discovery → `device_online`.
  - `TestWatchNoFalseOfflineWhenScansFailing`: 20 min later but `lastGoodDiscovery` = the device's `last_seen` → no event.
  - `TestWatchSkipsInsaneClock`: `now = 1970-01-01` → no event.
  - `TestUnwatchedNeverOffline`: an unwatched device not seen for 1 day → no event.
  - `TestConfirmGateway`: confirming after an alarm → `GatewayAlert()==nil`, the next discovery with B creates no event.
  - `TestPrune`: a 91-day-old event is deleted, an 89-day-old one stays.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(inventory): identify, watchlist, prune`.

---

### Task 10: Scheduler and scan runner

**Files:** Create `internal/scheduler/scheduler.go`, `scheduler_test.go`, `internal/app/runner.go`, `runner_test.go`

**Interfaces:**
- Produces:

```go
// scheduler
type Kind string
const KindDiscovery Kind = "discovery"; const KindPorts Kind = "ports"
type Job struct{ Kind Kind; DeviceID int64 } // KindPorts + DeviceID 0 = all online devices
type Intervals map[Kind]time.Duration
type Status struct{ Running *Job; RunningSince time.Time; Queued []Job; LastRun map[Kind]time.Time; LastErr map[Kind]string }
func New(run func(context.Context, Job) error, intervals func() Intervals, now func() time.Time) *Scheduler
func (s *Scheduler) Enqueue(j Job) bool // false if the same Job is queued/running; Ports/id is not added while Ports/0 is queued
func (s *Scheduler) Tick()              // adds periodic jobs that are due; now.Year()<2025 → nothing
func (s *Scheduler) Step(ctx context.Context) bool // runs one job from the queue (for tests); false if there is none
func (s *Scheduler) Run(ctx context.Context)       // Tick every 15 s + Step until the queue is empty; Enqueue wakes it at once
func (s *Scheduler) Status() Status

// app
type Runner struct {
	Inv      *inventory.Inventory
	Store    *store.Store
	Disc     lan.Discoverer
	Prober   lan.Prober
	Resolver lan.Resolver
	OUI      func(string) string
	Route    func() (iface string, gw netip.Addr, err error) // default: reads /proc/net/route
	IfaceNet func(iface string) (netip.Prefix, error)        // used when the CIDR setting is empty
	Enqueue  func(scheduler.Job) bool
	LastGoodDiscovery atomic.Value // time.Time
}
func (r *Runner) Run(ctx context.Context, j scheduler.Job) error
```

On first start discovery runs at once (no last run time = due); the port scan also starts right after discovery through `needPorts`. Interval 0 = that job is not added periodically (it can be added by hand). Every job is written to the `scans` table with start/end/found/error. Discovery: load settings → interface/route → prefix (`ValidateScanCIDR` of the setting or `IfaceNet`) → `Disc.Discover` → `Enrich` (reverse DNS per host with a 1 s timeout, one after another) → `ApplyDiscovery` → if successful, `LastGoodDiscovery` and `EvaluateWatch` → `Enqueue(Ports,id)` for each of `needPorts`. `ErrEmptyDiscovery` is recorded as an error.

- [ ] **Step 1: Failing tests:**
  - `TestTickDueJobs`: intervals {discovery:5m, ports:60m}; the first `Tick` adds both; `Step`×2; `Tick` 4 min later → empty; 6 min later → only discovery.
  - `TestTickInsaneClock`: `now=1970` → queue empty.
  - `TestEnqueueDedupe`: discovery twice → the second is `false`; Ports/7 while Ports/0 is queued → `false`.
  - `TestSequential`: a concurrent-call counter inside `run` never exceeds 1 (Run + 5 Enqueues, with `-race`).
  - `TestIntervalZeroDisables`.
  - `TestRunnerDiscoveryEnqueuesPorts` (fake Disc/Prober/Resolver, real temp DB): two hosts → `Enqueue` is called with two `Ports/id`; `scans` has one row, `found=2`.
  - `TestRunnerDiscoveryFailureNoEvents`: the fake Disc returns an error → `Run` errors, `events` empty, `scans.error` filled, `LastGoodDiscovery` unchanged.
  - `TestRunnerRejectsBadCIDRSetting`: `8.8.8.0/24` in the settings → error, Disc is not called.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** `go test -race ./internal/scheduler/ ./internal/app/` PASS.
- [ ] **Step 5: Commit** — `feat: scan scheduler and runner`.

---

### Task 11: Pi health readings

**Files:** Create `internal/health/health.go`, `statfs_linux.go`, `statfs_other.go`, `health_test.go`, `testdata/` (fake `/sys` and `/proc` files)

**Interfaces:**
- Produces:

```go
type Health struct {
	TempC            *float64
	MemTotal, MemAvailable uint64 // bytes
	DiskTotal, DiskFree    uint64 // partition holding DataDir
	Uptime           time.Duration
	ProcessRSS       uint64
	Throttled        *uint32
}
func (h Health) UnderVoltageNow() bool  // bit 0
func (h Health) UnderVoltageEver() bool // bit 16
func Read(root fs.FS, dataDir string) Health
```

Sources: `sys/class/thermal/thermal_zone0/temp` (millidegrees), `proc/meminfo` (`MemTotal`, `MemAvailable` kB), `proc/uptime`, `proc/self/status` (`VmRSS`), `sys/devices/platform/soc/soc:firmware/get_throttled` (hex, e.g. `0x50005`). Fields that cannot be read stay zero/nil; no error is returned. Disk via `statfs_linux.go`; zero on other OSes.

- [ ] **Step 1: Failing tests:** a full Pi sample with `fstest.MapFS` → `*TempC==48.3`, `MemTotal==443_000*1024`, `Uptime==12345s`, `UnderVoltageNow()==true`, `UnderVoltageEver()==true` (`0x50005`); empty FS → no panic, `TempC==nil`, `Throttled==nil`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(health): pi health readings`.

---

### Task 12: Authentication

**Files:** Create `internal/auth/auth.go`, `attempts.go`, `clientip.go`, `auth_test.go`, `attempts_test.go`, `clientip_test.go`

**Interfaces:**
- Produces:

```go
const BcryptCost = 10; const MinPasswordLen = 10
var ErrBadSetupCode, ErrWeakPassword, ErrUserExists, ErrNoUser, ErrBadCredentials, ErrLocked error
type Attempt struct{ IP string; At time.Time; Success bool }
func New(st *store.Store, now func() time.Time) *Auth
func (a *Auth) HasUser(ctx context.Context) (bool, error)
func (a *Auth) EnsureSetupCode(ctx context.Context) (code string, err error) // returns "" if a user exists; otherwise sha256(code) is stored in kv; every call makes a new code and invalidates the old one
func (a *Auth) Register(ctx context.Context, setupCode, username, password string) error
func (a *Auth) Login(ctx context.Context, ip, username, password string) error
func (a *Auth) Delay(ctx context.Context) time.Duration
func (a *Auth) ChangePassword(ctx context.Context, oldPw, newPw string) error
func (a *Auth) ResetPassword(ctx context.Context, newPw string) error // CLI; ErrNoUser if there is no user
func (a *Auth) Username(ctx context.Context) (string, error)
func (a *Auth) LoginHistory(ctx context.Context, limit int) ([]Attempt, error)
func (a *Auth) PruneAttempts(ctx context.Context) error
func ClientIP(r *http.Request, trusted []netip.Prefix) string
```

- Setup code: 10 random bytes → base32 (unpadded), 16 characters, shown as `XXXX-XXXX-XXXX-XXXX`; compared after removing dashes/spaces and upper-casing, with `subtle.ConstantTimeCompare` over sha256. A successful `Register` deletes the code.
- Username 1–32 characters, `CleanText`.
- `Login`: lockout check first (≥5 failures from this IP in the last 10 min → `ErrLocked`, the attempt is not recorded); bcrypt runs against a fixed dummy hash even when the username does not match (equal timing); the result goes into `login_attempts`; `last_login` on success.
- `Delay`: `f` = number of all failed attempts in the last 10 min; `f<20` → 0; otherwise `1s << ((f-20)/20)`, at most 8 s. The web layer waits this long before `Login`.
- `PruneAttempts`: rows older than 30 days and beyond the newest 1000 are deleted.
- `ClientIP`: the IP of `RemoteAddr`; only if that IP is in `trusted` is the **rightmost untrusted** address of `X-Forwarded-For` used.

- [ ] **Step 1: Failing tests:**
  - `TestRegisterFlow`: `EnsureSetupCode` returns a code; wrong code → `ErrBadSetupCode`; 9-character password → `ErrWeakPassword`; the right code (typed lower-case, without dashes) → ok; **`Register` again with the same code → `ErrUserExists`** and the username does not change; `EnsureSetupCode` now returns `""`.
  - `TestHashIsBcrypt`: `users.hash` starts with `$2a$10$`.
  - `TestLoginLockout`: 5 wrong → on the 6th attempt even the right password gives `ErrLocked`; 11 min later the right password → ok. Other IPs are not locked.
  - `TestGlobalDelay`: 1 failure each from 25 different IPs → `Delay()==1s`; 45 → `2s`; 400 → `8s`.
  - `TestResetPassword`, `TestChangePasswordRequiresOld`.
  - `TestPruneAttempts`: 1200 rows → 1000 remain; a 31-day-old row is deleted.
  - `TestClientIP`: without a trusted proxy, `X-Forwarded-For: 1.2.3.4` is ignored (`RemoteAddr` is returned); `RemoteAddr` trusted `192.168.1.2` and XFF `9.9.9.9, 192.168.1.50` → `192.168.1.50`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(auth): setup code, bcrypt login, lockout`.

---

### Task 13: Sessions and TLS

**Files:** Create `internal/session/session.go`, `session_test.go`, `internal/tlsutil/tlsutil.go`, `tlsutil_test.go`

**Interfaces:**
- Produces:

```go
// session
const CookieName = "honet_session"
type Session struct{ ID, Username, CSRF string; LastSeen time.Time }
func NewManager(idle func() time.Duration, now func() time.Time) *Manager
func (m *Manager) Create(w http.ResponseWriter, username string, secure bool) *Session // 32-byte ID, 32-byte CSRF, base64url
func (m *Manager) Get(r *http.Request) (*Session, bool) // deletes it and returns false if expired; LastSeen=now if valid
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request)
func (m *Manager) DestroyAll()                           // on password change
// tlsutil
func LoadOrCreate(dir string, now func() time.Time) (tls.Certificate, error)
```

Cookie: `Path=/`, `HttpOnly`, `SameSite=Strict`, `Secure` if `secure`; no `MaxAge` (browser session). Certificate: `honet-cert.pem` (0644), `honet-key.pem` (0600), ECDSA P-256, `NotBefore = now-1h`, `NotAfter = now+10y`, SAN: `os.Hostname()`, `<hostname>.local`, `localhost`, all interface IPv4s, `127.0.0.1`. Existing files are loaded, not regenerated. If `now.Year()<2025`, `NotBefore` is fixed at `2025-01-01` (so a boot without a clock does not make the certificate "not yet valid").

- [ ] **Step 1: Failing tests:** `TestSessionIdleExpiry` (idle 15m; Get ok 14 min later and the timer renews; false 16 min after that); `TestCookieFlags` (`HttpOnly`, `SameSite=Strict`, secure=true → `Secure`); `TestDestroyAll`; `TestTLSCreateThenLoad` (the first call creates the files, the second loads the same certificate, key file permissions 0600 on Linux — skip on Windows); `TestTLSInsaneClock`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat: sessions and self-signed tls`.

---

### Task 14: Web skeleton — middleware, setup, login, logout

**Files:** Create `internal/web/server.go`, `middleware.go`, `render.go`, `auth_handlers.go`, `assets.go`, `templates/layout.html`, `templates/setup.html`, `templates/login.html`, `static/vendor/bootstrap.min.css`, `static/vendor/bootstrap.bundle.min.js`, `static/honet.css`, `static/honet.js`, `web_test.go`, `auth_handlers_test.go`

**Interfaces:**
- Consumes: `auth.Auth`, `session.Manager`, `store.Store`, `inventory.Inventory`, `scheduler.Scheduler`, `health.Health`.
- Produces:

```go
type Deps struct {
	Store   *store.Store
	Auth    *auth.Auth
	Sess    *session.Manager
	Inv     *inventory.Inventory
	Sched   *scheduler.Scheduler
	Health  func() health.Health
	Secure  bool
	Version string
	DevAssets string // if not empty, templates/static from disk
	Now     func() time.Time
}
func New(d Deps) (http.Handler, error)
```

Behaviour:
- Security headers on every response: `Content-Security-Policy: default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`; with `Secure`, `Strict-Transport-Security: max-age=31536000`. `Cache-Control: no-store` on pages that need auth.
- With no user, every request (except static) goes to `/setup`; with a user, `/setup` → `/login`.
- Request without a session → `/login` (303). 401 for `/partials/*` (the JS reloads the page).
- CSRF: on POSTs with a session the `csrf` form field == `Session.CSRF` (constant time). For forms without a session (`/setup`, `/login`), double submit: a `honet_csrf` cookie (`SameSite=Strict`, `HttpOnly`) + hidden field. 403 on mismatch.
- `POST /login`: `time.Sleep(Auth.Delay())` (respects context cancellation), `ClientIP` with the `TrustedProxies` setting; success → session + `/`; `ErrLocked` → "Too many failed attempts. Try again in 10 minutes."; otherwise → "Invalid username or password." (does not say which one was wrong).
- `POST /logout` → delete the session, `/login`.
- `layout.html`: dark theme (`data-bs-theme="dark"`), the existing green accent `#00FF41` in `honet.css`; menu: Network · Events · Settings · Logout (no Phase 2 menus); `Version` in the footer.
- `honet.js`: refreshes the element with `data-refresh-url` every 30 s with `fetch`, skips while `document.hidden`, `location.reload()` on 401; `confirm()` on forms with `data-confirm`.
- The `dist` files of the latest Bootstrap 5.3 patch release are copied to `static/vendor/`; the version is written as a constant in `assets.go`.
- Static files: `Cache-Control: public, max-age=86400`.

- [ ] **Step 1: Failing tests** (`httptest`, temp DB):
  - `TestSecurityHeaders` (every page, no `'unsafe-inline'` in the CSP).
  - `TestRedirectsToSetupWhenNoUser`, `TestSetupThenLogin` (register with the setup code → `/login`; login → cookie → `/` 200).
  - `TestSetupRejectsReuse`: after registration, `POST /setup` with the same code → redirected to `/login`, the username does not change.
  - `TestCSRFRequired`: `POST /logout` with a session but no csrf → 403.
  - `TestLoginLockedMessage`, `TestXFFIgnoredWithoutTrustedProxy` (5 failed logins, each with a different XFF → the 6th attempt is still locked).
  - `TestTemplatesHaveNoInlineScriptOrStyle`: in all embedded templates `<script>` only with `src=`, no `style="`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(web): server, middleware, setup and login`.

---

### Task 15: Network page and device detail

**Files:** Create `internal/web/network_handlers.go`, `templates/network.html`, `templates/devices_partial.html`, `templates/device.html`, `templates/health_card.html`, `network_handlers_test.go`

**Interfaces:**
- Consumes: the Task 8–11 `Inventory` methods, `Scheduler.Enqueue/Status`, `Deps.Health`.

Routes (Go 1.22 `ServeMux` patterns):
- `GET /` — top bar: gateway warning (red, a "Confirm new MAC" form → `POST /gateway/confirm`), IP conflicts and the number of unknown devices, offline watched devices, last scan time and state ("Scanning…" / last error), `POST /scan` ("Scan now" → `Enqueue(Discovery)`; "A scan is already queued." if one is). Below, `devices_partial` (`data-refresh-url="/partials/devices"`) and the health card.
- `GET /partials/devices` — table; Bootstrap `table-responsive`; row: status icon (⚠ unknown / ✔ known / "this device"), name or `?`, IP, MAC (+ "random" badge), vendor, type, open ports (risky ones as red badges), last seen (relative: "2 min ago").
- `GET /devices/{id}` — Identify form (`POST /devices/{id}`: name, notes, type choice [Auto + classify types], known), Watch form (`POST /devices/{id}/watch`: on/off, minutes), port table (risk explanation + `POST /devices/{id}/ports/{port}/ack` "Mark as intentional"), IP history, last 50 events, "Scan ports now" (`POST /devices/{id}/scan` → `Enqueue(Ports,id)`), "Forget device" (`POST /devices/{id}/delete`, `data-confirm`).
- Health card: temperature, RAM, disk, uptime, Honet RSS; `UnderVoltageNow` → red "Under-voltage detected — check the power supply", `UnderVoltageEver` → yellow warning. Empty fields are not shown.

- [ ] **Step 1: Failing tests:**
  - `TestNetworkListsUnknownFirst` and `2 unknown devices` in the header.
  - `TestHostileHostnameEscaped`: hostname `<script>alert(1)</script>` → `&lt;script&gt;` in the body, no raw `<script>alert`.
  - `TestIdentifyUpdatesDevice` (POST with csrf → 303 → the name shows on the detail page).
  - `TestScanNowEnqueues` and "already queued" the second time.
  - `TestGatewayBannerAndConfirm`.
  - `TestRiskyPortBadgeAndAck`.
  - `TestPartialRequiresSession` → 401.
  - `TestHealthCardUnderVoltage`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(web): network page and device detail`.

---

### Task 16: Events and Settings pages, export, report

**Files:** Create `internal/web/events_handlers.go`, `settings_handlers.go`, `export_handlers.go`, `templates/events.html`, `templates/settings.html`, `templates/report.html`, `events_handlers_test.go`, `settings_handlers_test.go`, `export_handlers_test.go`

Routes:
- `GET /events` — the last 200 events, unread ones highlighted, an English label for the kind and a link to the device; `POST /events/read` marks all as read. Unread count badge in the menu (`UnreadCount` in the layout).
- `GET /settings`, `POST /settings` — CIDR (empty = automatic; a `ValidateScanCIDR` error is shown in the form), interface name, discovery and port intervals (minutes; 0 or ≥1), session timeout (5–240 min), watch default (min), trusted proxies (comma-separated CIDRs/IPs). "Saved." after saving.
- `POST /settings/password` — old + new + repeat; on success `DestroyAll` and `/login`.
- Login history: the last 50 (`LoginHistory`).
- `GET /export/devices.csv`, `GET /export/devices.json` — fields: name, known, type, ip, mac, vendor, hostname, open_ports, first_seen, last_seen. **No user, hash or login attempts.** CSV cells starting with `=`, `+`, `-`, `@` are prefixed with `'` (formula injection).
- `GET /report` — printable page (`@media print` styles in `honet.css`), device table + a summary of the last 7 days of events; a "Print / Save as PDF" button calls `window.print()` through `honet.js`.

- [ ] **Step 1: Failing tests:** `TestSettingsRejectsPublicCIDR` (form error, value not saved); `TestSettingsSaves`; `TestIntervalValidation` (0 ok, 1 ok, -1 and "abc" are errors); `TestPasswordChangeLogsOutAll`; `TestExportHasNoSecrets` (no username and no `$2a$` in the CSV/JSON body); `TestCSVFormulaEscaped` (name `=cmd()` → `'=cmd()`); `TestEventsMarkRead`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5: Commit** — `feat(web): events, settings, export, report`.

---

### Task 17: Wiring `serve` and `reset-password`

**Files:** Modify `cmd/honet/main.go`; Create `cmd/honet/serve.go`, `cmd/honet/reset.go`, `cmd/honet/serve_test.go`

**Interfaces:**
- Consumes: all packages.
- Produces: `func serve(ctx context.Context, cfg config.Config, stdout io.Writer) error`; `func resetPassword(cfg config.Config, in io.Reader, out io.Writer, readPw func() (string, error)) error`.

`serve`: `store.Open` → `auth.EnsureSetupCode`; if there is a code, a framed `HONET SETUP CODE: XXXX-XXXX-XXXX-XXXX` on stdout (shows up in the systemd journal) → `inventory.New` → `app.Runner` (`lan.NewARPDiscoverer(50, 2*time.Second)`, `lan.TCPProber{32, 800*time.Millisecond}`, `net.DefaultResolver`, `oui.Lookup`) → `scheduler.New` (intervals read from the settings on every `Tick`) → `go sched.Run(ctx)` (watch evaluation runs inside the Runner after every successful discovery) → once a day: `Inv.Prune`, `Auth.PruneAttempts`, `PRAGMA wal_checkpoint(TRUNCATE)` → TLS (`--cert/--key` or `tlsutil.LoadOrCreate(DataDir)`, `MinVersion: tls.VersionTLS12`) → `http.Server{ReadHeaderTimeout: 10s, ReadTimeout: 30s, WriteTimeout: 60s, IdleTimeout: 120s, MaxHeaderBytes: 16<<10}` → shutdown within 10 s on `SIGINT/SIGTERM`. Form bodies limited to 64 KB with `http.MaxBytesReader`.

`reset-password`: if there is no user, "No user yet; open the web UI to finish setup."; reads the password twice with `golang.org/x/term.ReadPassword`, checks that they match and have ≥10 characters, `Auth.ResetPassword`. Since the running service keeps sessions in memory, the output says "Restart honet to sign out existing sessions: sudo systemctl restart honet".

- [ ] **Step 1: Failing tests:** `TestServeStartsAndPrintsSetupCode` (temp dir, `--http --listen 127.0.0.1:0`; an inner helper `serveWith(deps)` is used so a fake discovery can be injected instead of `ARP`; `/setup` 200, `HONET SETUP CODE` on stdout; returns within 10 s after context cancellation); `TestResetPasswordNoUser`; `TestResetPasswordMismatch`; `TestResetPasswordOK`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `./build.ps1` four files.
- [ ] **Step 5: Commit** — `feat: serve and reset-password commands`.

---

### Task 18: systemd unit, install script, README

**Files:** Create `deploy/systemd/honet.service`, `deploy/install.sh`; Modify `README.md`

`honet.service`:

```ini
[Unit]
Description=Honet home network monitor
After=network-online.target time-sync.target
Wants=network-online.target

[Service]
User=honet
Group=honet
ExecStart=/usr/local/bin/honet serve
StateDirectory=honet
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryMax=96M
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`install.sh` (runs as root, `set -euo pipefail`): picks the right file by `uname -m` (`armv6l`→armv6, `armv7l`→armv7, `aarch64`→arm64, `x86_64`→amd64) — the file is expected as `honet-linux-*` in the script's directory; installs `/usr/local/bin/honet` (0755); creates the `honet` system user (`--system --no-create-home --shell /usr/sbin/nologin`) if missing; copies the unit; `systemctl daemon-reload && systemctl enable --now honet`; waits 5 s and prints the code with `journalctl -u honet -n 50 | grep -A2 "SETUP CODE"` and the `https://<ip>:8443` address. `--uninstall` removes it (does not delete the data, says how to).

README (English): what it does, the Zero W target, screenshot placeholders removed (renewed in Phase 2), building on Windows with `build.ps1`, `scp dist/honet-linux-armv6 deploy/install.sh pi@…` and `sudo ./install.sh`, the first-run setup code, `sudo -u honet honet reset-password`, data path, self-signed certificate warning, security notes (stated correctly: the database holds the bcrypt hash and login IPs; the export does not).

- [ ] **Step 1:** Write the files.
- [ ] **Step 2:** Verification: `bash -n deploy/install.sh` (Git Bash) reports no errors; `systemd-analyze verify` on the Pi in Task 19.
- [ ] **Step 3: Commit** — `feat(deploy): systemd unit, installer, README`.

---

### Task 19: Verification on the Zero W (manual, with the user)

**Files:** Create `docs/superpowers/plans/2026-11-23-honet-v2-phase1-pi-results.md` (measurement results)

- [ ] **Step 1:** `./build.ps1`; the user copies `dist/honet-linux-armv6` and `deploy/install.sh` to the Pi and runs `sudo ./install.sh`.
- [ ] **Step 2:** `systemd-analyze verify /etc/systemd/system/honet.service` without warnings; `systemctl status honet` active.
- [ ] **Step 3:** From a phone, `https://<pi-ip>:8443` → setup → login → the first discovery fills the list within 5 min; the Pi shows as "this device"; the router is recorded as the gateway.
- [ ] **Step 4:** Measurements and thresholds (spec §11): idle `ps -o rss= -C honet` < 30 MB; < 50 MB while scanning; `ls -l /usr/local/bin/honet` < 20 MB; `/24` discovery + port scan < 90 s (from the `scans` table). Values are written to the results file; if a threshold is exceeded, ARP rate/concurrency are tuned and measured again.
- [ ] **Step 5:** Turn Wi-Fi off and on briefly (e.g. `sudo ip link set wlan0 down; sleep 400; sudo ip link set wlan0 up` — with the user's approval) → no false "offline" events for watched devices, an error row in the `scans` table.
- [ ] **Step 6:** Commit the results file — `docs: phase 1 pi verification results`.
