# Honet v2 — Phase 2 Implementation Plan (scope testable with Docker)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On top of Phase 1, add "who is home", internet latency/speed measurement (with SVG charts), a Docker image, CI and an up-to-date README.

**Scope decision (user, 2026-11-23):** "It is not right to add things we cannot test." There is no Pi, and Docker Desktop has no Bluetooth adapter or WiFi card. So **Bluetooth and WiFi / fake access point detection are removed from this phase**; they will be handled in a separate phase once they can be tested on hardware. Presence relies on LAN devices only.

**Architecture:** The new measurements sit behind interfaces (ICMP pinger, Cloudflare HTTP); unit tests use fakes, the end-to-end test runs in Docker (real ICMP and real Cloudflare). The speed test enters the single-worker scheduler as a new `Kind`; the ping monitor runs outside the queue once a minute and skips while a speed test runs. Charts are inline SVG rendered on the server (SVG attributes + CSS classes, because the CSP forbids inline `style`).

**Tech Stack:** Go 1.27, `golang.org/x/net/icmp`, existing packages.

**Spec:** `docs/superpowers/specs/2026-11-23-honet-go-rewrite-design.md` (§5.4, §5.5.3–4, §5.5.6, §7, §8, §9, §12 Phase 2; BT/WiFi sections deferred). Phase 1 plan: `docs/superpowers/plans/2026-11-23-honet-v2-phase1.md`.

## Global Constraints

- The `CGO_ENABLED=0`, GOARCH=arm GOARM=6 build passes at the end of every task (`armbuild`).
- Default intervals: latency 1 min (outside the queue), speed test 3 hours; configurable, 0 = off.
- Latency: gateway + `1.1.1.1` + `8.8.8.8` (configurable, at most 4), 5 ICMP pings per target, 1 s timeout; DNS time; 5-minute summary (min/avg/max, jitter, loss %).
- Speed test: `https://speed.cloudflare.com/__down?bytes=N` and `/__up`; at most 10 s per direction; requests of increasing size; latency under load; bytes used recorded. Ookla and M-Lab are not used.
- Pi limit note: if download or upload ≥ threshold × 0.9, "may be limited by the Pi"; threshold default 25 Mbps, configurable 1–1000.
- Retention: ping summaries 30 days, speed tests 90 days, presence 30 days (each person's latest row is kept).
- While the clock year is < 2025: the scheduler starts no new jobs (existing `Tick` rule), presence and latency summaries are not written.
- UI language English; menu order: Network · People · Internet · Events · Settings · Logout.
- No external JS/chart library; CSP unchanged.
- Docker: `FROM scratch`, `network_mode: host`, `cap_drop: ALL` + `cap_add: NET_RAW`, `read_only`, data in `/data`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; push/merge only when the user asks.

## Review Focus

1. **ICMP unavailable** (no CAP_NET_RAW, ping_group_range closed). Expected: the monitor logs the error once, no summaries are written, no `internet_outage` is created, the Internet page says "Latency measurement is not available". → Task 5 test (`TestMonitorUnavailable`), Task 7 page test.
2. **Speed test endpoint stalls / no internet.** Expected: each direction is cut at `PerDir`, an error row is written, no event is created, the scheduler moves on to the next job. → Task 4 tests.
3. **Pi without a clock (no RTC).** Expected: while the year is < 2025, presence and latency summaries are not written. → Task 3 and Task 5 tests.
4. **The gateway does not answer either** (the Pi's connection dropped). Expected: not counted as an internet outage. → Task 5 test.
5. **A device linked to a person is deleted.** Expected: the link goes away (`ON DELETE CASCADE`), the person becomes "away", the page does not fail. → Task 3 test (`TestPersonDeviceDeletedCascades`).

---

## File structure

| File | Responsibility |
|---|---|
| `internal/store/schema.go`, `settings.go` (modified) | migration v2, new settings |
| `internal/scheduler/scheduler.go` (modified) | `KindSpeed` |
| `internal/inventory/people.go` | people, presence |
| `internal/inventory/internet.go` | latency/speed persistence, outage events |
| `internal/speedtest/speedtest.go` | Cloudflare speed test |
| `internal/netmon/netmon.go`, `icmp.go` | ping, DNS time, 5-min summary, monitor |
| `internal/web/chart.go` | SVG line chart and presence strip |
| `internal/web/people_handlers.go`, `internet_handlers.go` + templates | new pages |
| `internal/app/runner.go`, `cmd/honet/serve.go` (modified) | wiring |
| `Dockerfile`, `.dockerignore`, `deploy/docker/*` | Docker |
| `.github/workflows/ci.yml`, `release.yml` | CI |
| `README.md` (modified) | documentation |

---

### Task 1: Docker image and emulated ARMv6 smoke test

**Files:** Create `Dockerfile`, `.dockerignore`, `deploy/docker/docker-compose.yml`, `deploy/docker/smoke.sh`

- `Dockerfile`: `FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build` → cross build with `GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v}` (`-trimpath -ldflags "-s -w -X main.version=$VERSION"`), `ca-certificates`, empty `/data` → `FROM scratch`, CA certificates, `ENV HONET_DATA_DIR=/data`, `VOLUME /data`, `EXPOSE 8443`, `ENTRYPOINT ["/honet"]`, `CMD ["serve"]`. The user is root (in scratch, without file capabilities NET_RAW is only effective for root; it is bounded by `cap_drop: ALL`).
- `docker-compose.yml`: `image: ghcr.io/aliserifdemiralp/honet:latest`, `build: ../..`, `network_mode: host`, `cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `read_only: true`, `security_opt: [no-new-privileges:true]`, `volumes: [honet-data:/data]`, `restart: unless-stopped`, `mem_limit: 96m`.
- `smoke.sh PLATFORM`: builds the image with `--platform`, runs it with `-p 18443:8443`, waits at most 90 s for `/setup` to return 200, looks for `HONET SETUP CODE` in `docker logs`, removes the container; `smoke ok` / exit 1.

- [ ] **Step 1:** Write the files. **Step 2:** `bash deploy/docker/smoke.sh linux/amd64` → `smoke ok`. **Step 3:** `bash deploy/docker/smoke.sh linux/arm/v6` → `smoke ok`.
- [ ] **Step 4: Commit** — `feat(docker): scratch image, compose file, smoke test`.

---

### Task 2: Schema v2, settings, `KindSpeed`

**Files:** Modify `internal/store/schema.go`, `settings.go`, `internal/scheduler/scheduler.go` + tests

**Interfaces (Produces):**
- Migration v2:
  - `people(id INTEGER PK, name TEXT UNIQUE NOT NULL)`
  - `person_devices(person_id REFERENCES people(id) ON DELETE CASCADE, device_id REFERENCES devices(id) ON DELETE CASCADE, PRIMARY KEY(person_id, device_id))`
  - `presence(id PK, person_id REFERENCES people(id) ON DELETE CASCADE, state TEXT CHECK(state IN ('home','away')), at TEXT)` + index `(person_id, at)`
  - `latency_5m(at TEXT, target TEXT, min_ms, avg_ms, max_ms, jitter_ms, loss_pct, dns_ms REAL, PRIMARY KEY(at, target))`
  - `speedtests(id PK, at TEXT, down_mbps REAL, up_mbps REAL, loaded_ms REAL, bytes INTEGER, error TEXT NOT NULL DEFAULT '')`
- `store.Settings`: `SpeedInterval` (3h, `settings.speed_interval_s`), `LatencyInterval` (1m, `settings.latency_interval_s`), `LatencyTargets []string` (`{"1.1.1.1","8.8.8.8"}`, `settings.latency_targets` comma-separated; default when unset, empty string = no targets), `PiLimitMbps float64` (25, `settings.pi_limit_mbps`).
- `scheduler.KindSpeed Kind = "speedtest"`; `periodic = {Discovery, Ports, Speed}`.

- [ ] **Step 1: Failing tests:** `TestMigrationV2Tables` (`schema_version` = 2, the five tables exist); `TestSettingsPhase2Defaults`; `TestSettingsPhase2RoundTrip`; `TestTickSpeedKind` (`Intervals{KindSpeed: 3h}` → `speedtest` queued; `0` → none).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `armbuild`. **Step 5: Commit** — `feat(store): schema v2 and phase 2 settings`.

---

### Task 3: Who is home (presence)

**Files:** Create `internal/inventory/people.go`, `people_test.go`; Modify `internal/inventory/query.go` (calls from `Prune`)

**Interfaces (Produces):** `EvPersonArrived = "person_arrived"`, `EvPersonLeft = "person_left"`; `const HomeWindow = 10 * time.Minute`; `ErrBadName`.
- `type Person struct { ID int64; Name string; Home, Known bool; Since time.Time; Devices []Device }` (`Known` = at least one presence row exists).
- `AddPerson(ctx, name) (int64, error)` (`netutil.CleanText(name, 40)`, empty → `ErrBadName`, duplicate → `ErrBadName`), `DeletePerson(ctx, id)`, `LinkDevice(ctx, personID, deviceID)` (`ErrNotFound` if missing), `UnlinkDevice(ctx, personID, deviceID)`, `People(ctx) ([]Person, error)`.
- `EvaluatePresence(ctx) error` — writes nothing when the year is < 2025; for each person `home` if `MAX(last_seen)` of the linked devices ≥ `now − HomeWindow`; if it differs from the last row, a row + an event (no event for the first row). Event `detail` = person name.
- `type Span struct { From, To time.Time; Home bool }`; `PresenceDays(ctx, personID, days int) ([][]Span, error)` — local time, from the oldest day to today, split at midnight, today ends at `now`; empty before the first record.
- `PrunePresence(ctx)` — older than 30 days, except each person's latest row.

- [ ] **Step 1: Failing tests:** `TestPresenceHomeAway`, `TestPresenceAnyDevice`, `TestPresenceNoWriteWithBadClock`, `TestPresenceDaysSplitsAtMidnight`, `TestPrunePresenceKeepsLatest`, `TestPersonDeviceDeletedCascades`, `TestAddPersonCleansName`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `armbuild`. **Step 5: Commit** — `feat: presence (who is home)`.

---

### Task 4: Speed test

**Files:** Create `internal/speedtest/speedtest.go`, `speedtest_test.go`, `internal/inventory/internet.go`, `internet_test.go`

**Interfaces (Produces):**
- `speedtest.Result{DownMbps, UpMbps, LoadedMs float64; Bytes int64}`; `Tester{Client *http.Client; Base string; PerDir time.Duration}`; `DefaultBase = "https://speed.cloudflare.com"`; `func (t Tester) Run(ctx) (Result, error)`.
  - Download: `GET {Base}/__down?bytes=N`, N = 100_000, 1_000_000, 10_000_000, 25_000_000, 50_000_000, then 50_000_000 again; stop when time runs out, partial reads included. Mbps = bytes×8/duration/1e6. Upload: `POST {Base}/__up`, same sizes, zero-byte body. Latency under load: while downloading, `GET {Base}/__down?bytes=0` every 500 ms, median ms. Each direction uses `context.WithTimeout(PerDir)`; error if no bytes could be transferred in that direction; HTTP ≠ 200 is an error.
- `inventory`: `SaveSpeedTest(ctx, at, r, err) error`; `SpeedRow{At; DownMbps, UpMbps, LoadedMs float64; Bytes int64; Error string}`; `SpeedTests(ctx, since)`; `LastSpeedTest(ctx) (*SpeedRow, error)` (nil if none); `Prune` 90 days.

- [ ] **Step 1: Failing tests:** `TestSpeedMeasures`, `TestSpeedStopsAtDeadline`, `TestSpeedStalledServer`, `TestSpeedServerError`, `TestSaveSpeedTestError`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `armbuild`. **Step 5: Commit** — `feat: Cloudflare speed test`.

---

### Task 5: Latency monitor and outage detection

**Files:** Create `internal/netmon/netmon.go`, `icmp.go`, `netmon_test.go`; Modify `internal/inventory/internet.go`

**Interfaces (Produces):**
- `netmon.Pinger interface { Ping(ctx, ip netip.Addr, n int, timeout time.Duration) ([]time.Duration, error) }` — loss = `-1`. `NewICMP() Pinger`: `icmp.ListenPacket("ip4:icmp", "0.0.0.0")`, falling back to `"udp4"`; also builds on Windows (may only fail at run time). IPv6 targets use `ip6:ipv6-icmp` / `udp6`.
- `Sample{At; Target string; RTTs []time.Duration; DNS time.Duration}`; `Summary{At; Target string; MinMs, AvgMs, MaxMs, JitterMs, LossPct, DNSMs float64}`; `Summarize(at, target, rtts, dns) Summary`; `Aggregator.Add(s Sample) []Summary` (when the window changes, the previous window's summary per target; RTTs are merged, DNS averaged).
- `Monitor{Pinger; Resolver interface{LookupHost}; Gateway func() (netip.Addr, error); Targets func() []string; Busy func() bool; Save func(ctx, []Summary) error; Now func() time.Time; Log func(string)}`; `Once(ctx) error`; `Run(ctx, every func() time.Duration)`; `Err() error` (last ping error, for the page). The gateway target is stored under the name `"gateway"`.
- `inventory`: `EvInternetOutage`, `EvInternetRestored`; `SaveLatency(ctx, []netmon.Summary) error` (writes nothing when the year is < 2025; if all non-gateway targets have loss ≥ 80 and the gateway < 80 → `internet_outage` when no outage is open, kv `internet.outage_since`; if one internet target is < 80 → `internet_restored` when an outage is open); `Latency(ctx, since)`; `LatestLatency(ctx)`; `Outages(ctx, since)` → `[]OutageSpan{From, To}` from the events; `Prune` 30 days.

- [ ] **Step 1: Failing tests:** `TestSummaryMath`, `TestAllLost`, `TestAggregatorFlushesOnWindowChange`, `TestMonitorSkipsWhenBusy`, `TestMonitorUnavailable`, `TestOutageEvent`, `TestNoOutageWhenGatewayDown`, `TestLatencyNotSavedWithBadClock`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `armbuild`. **Step 5: Commit** — `feat: latency monitor and outage detection`.

---

### Task 6: SVG charts

**Files:** Create `internal/web/chart.go`, `chart_test.go`; Modify `internal/web/static/honet.css`

**Interfaces (Produces):** `Point{At; V float64; Gap bool}`, `Series{Name, Class string; Points []Point}`, `Band{From, To time.Time}`, `LineChart(title, unit string, from, to time.Time, series []Series, bands []Band) template.HTML` (`viewBox="0 0 720 180"`, a "nice" max of 1/2/5×10ⁿ, 4 grid lines, daily lines + `Mon 24` labels, polylines split at Gap, `<rect class="chart-outage">`, `role="img"`, `<title>`, no inline `style`, escaped text), `niceMax(v float64) float64`, `PresenceStrip(days [][]inventory.Span, labels []string) template.HTML` (18 px rows, `presence-home` rects).

- [ ] **Step 1: Failing tests:** `TestLineChartBasic`, `TestLineChartGapSplits`, `TestLineChartEscapes`, `TestNiceMax` (37→50, 120→200, 0→1), `TestOutageBand`, `TestPresenceStrip`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS. **Step 5: Commit** — `feat(web): server-side SVG charts`.

---

### Task 7: People and Internet pages, settings

**Files:** Create `internal/web/people_handlers.go`, `internet_handlers.go`, `templates/people.html`, `internet.html`, `people_internet_test.go`; Modify `server.go` (`Deps.Latency func() error`), `layout.html` (menu), `render.go` (`evlabel`), `settings_handlers.go`, `templates/settings.html`

- Routes: `GET /people`, `POST /people` (`name`), `POST /people/{id}/link` (`device` id), `POST /people/{id}/unlink`, `POST /people/{id}/delete`; `GET /internet`, `POST /internet/test` (`KindSpeed`, `?msg=queued|busy`).
- `/internet`: latest summary per target; last speed test + Pi limit note; "Test now"; two `LineChart`s of the last 7 days (Mbps and ms); outage bands; if `Deps.Latency()` returns an error, "Latency measurement is not available: …".
- `evlabel`: `person_arrived` "Arrived home", `person_left` "Left home", `internet_outage` "Internet outage", `internet_restored` "Internet restored"; `evclass`: outage `text-bg-danger`.
- Settings: `speed` (min; 0 or 60–1440), `latency` (min; 0 or 1–60), `targets` (comma-separated IPs; at most 4; invalid → 400), `pilimit` (1–1000).

- [ ] **Step 1: Failing tests:** `TestPeopleCreateLinkPresence`, `TestPeopleBadDevice`, `TestInternetPageCharts`, `TestInternetLatencyUnavailable`, `TestInternetTestNowQueues`, `TestSettingsPhase2Validation`, `TestNavOrder`, `TestPhase2CSRF`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS; `armbuild`. **Step 5: Commit** — `feat(web): people and internet pages`.

---

### Task 8: Wiring and Docker verification

**Files:** Modify `internal/app/runner.go`, `runner_test.go`, `cmd/honet/serve.go`, `serve_test.go`

- `Runner`: `Speed interface{ Run(context.Context) (speedtest.Result, error) }`; `KindSpeed` → `Speed.Run` → `SaveSpeedTest` (failures are recorded too, the job returns the error). `EvaluatePresence` after a successful discovery.
- `serve`: `serveDeps.Pinger`, `serveDeps.SpeedBase`; `Intervals[KindSpeed]`; a `netmon.Monitor` goroutine (`Busy` = the running job is `KindSpeed`); `maintain` gets presence/latency/speed pruning through `Prune`.

- [ ] **Step 1: Failing tests:** `TestRunnerSpeedJob`, `TestRunnerSpeedJobRecordsFailure`, `TestRunnerDiscoveryEvaluatesPresence`, `TestServePhase2Pages` (`/people`, `/internet` without login → 303 `/login`).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** `go test ./...` PASS; `./build.ps1`.
- [ ] **Step 5: Docker verification:** `smoke.sh linux/arm/v6`; in the container, setup → login → a person + device on People; a real ping summary on the Internet page (instead of waiting for the 5-minute window, observe `Once` + a window change) and a real Cloudflare speed test ("Test now"). If ICMP does not work through Docker Desktop's NAT, write a ruling.
- [ ] **Step 6: Commit** — `feat: wire presence and internet monitoring`.

---

### Task 9: CI and release flow

**Files:** Create `.github/workflows/ci.yml`, `release.yml`

- `ci.yml`: `push`/`pull_request`; `actions/setup-go` (`go-version-file: go.mod`); `go vet ./...`; `go test -race ./...`; ARMv6 build.
- `release.yml`: on a `v*` tag, tests → four binaries + `sha256sums.txt` → `gh release create … --generate-notes`; QEMU + buildx + ghcr login + `platforms: linux/arm/v6,linux/arm/v7,linux/arm64,linux/amd64`, tags `:${GITHUB_REF_NAME}` and `:latest` (owner lower-cased).

- [ ] **Step 1:** Write. **Step 2:** YAML parse check. **Step 3: Commit** — `ci: test workflow and tagged releases`.

---

### Task 10: README

- Features: People, Internet (Cloudflare; at most ~60 MB per test, every 3 hours by default; configurable; Pi ~25 Mbps note); Bluetooth/WiFi "once they can be tested on hardware" note.
- Docker section (compose, setup code, host network, a warning that on Docker Desktop ARP only sees the virtual network), Releases section (`sha256sum -c`).

- [ ] **Step 1:** Write. **Step 2:** Check that commands/flags exist in the code. **Step 3: Commit** — `docs: phase 2 README`.
