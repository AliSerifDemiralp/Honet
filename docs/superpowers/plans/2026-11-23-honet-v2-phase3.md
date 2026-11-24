# Honet v2 — Phase 3: Scanning, identification, dashboard

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. TDD for every behaviour change.

**Goal:** Scan ranges that are not on a local interface, guess what "?" devices are, add selectable port scans, a dashboard that shows all data at a glance, a self-refreshing UI, and modals instead of browser dialogs.

**User request (2026-11-23):** scanning 192.168.0.0/24 did not work; the "?" devices should be identified (nmap at least showed something); port scans should be possible; the UI should refresh periodically; alerts should be modals instead of JS dialogs; the landing page should be a dashboard of all data.

**Diagnosis:** The user's network is 192.168.1.0/24. On Docker Desktop the container is on 172.17.0.0/16; ARP only works on the attached network. ICMP and TCP from the container reach 192.168.1.x (NAT). So ranges that are not attached need a ping + TCP sweep.

## Global Constraints
- Phase 1/2 constraints still apply (no CGO, ARMv6, CSP unchanged: no inline script/style, no external libraries).
- Routed scans only for RFC 1918 ranges, /22 or smaller (existing validation).
- Wide port scans are started manually only (extended profiles); the periodic scan stays "common". At most 65535 ports per job.
- Background refresh does not extend the session idle timeout.
- Success messages are self-closing toasts; confirmations and errors are modals; no `window.confirm`/`alert`.

## Tasks

### Task 1: Routed scan (sweep)
- `lan.SweepDiscoverer{Pinger netmon.Pinger; Dial func; Ports []int; Concurrency int; Timeout time.Duration}`: per IP an ICMP ping (1 packet) and TCP connects (80, 443, 22, 445, 139, 53, 8080, 62078, 7000; no 5353). A connection that is accepted **or refused (RST)** → alive. MAC empty.
- `Runner.discover`: ARP if the target range is inside the interface network, otherwise sweep. If the sweep is empty too, error: `no device answered in X; this host is on Y`.
- Settings page hint: "This host: 172.17.0.2/16 on eth0".
- Tests: `TestSweepAliveOnRefused`, `TestSweepICMPOnly`, `TestSweepSkipsSilent`, `TestRunnerUsesSweepOffLink`, `TestRunnerOffLinkEmptyErrorNamesSubnet`.

### Task 2: Device identification
- Schema v3: `devices.netbios TEXT`, `devices.http_info TEXT`.
- `lan.NetBIOSName(ctx, ip, timeout)` (UDP 137 node status), `lan.HTTPInfo(ctx, ip, port)` (`<title>` and `Server`, 64 KB / 2 s limit, read-only without TLS verification).
- `classify`: new types `printer` (9100/631/515), `camera` (554/8554), `nas` (5000+5001, 548, 2049), `media_player` (8008/8009, 7000 non-Apple), `apple_mobile` port 62078 → `phone_or_tablet`; gateway → `router`; HTTP title keywords (router/modem/printer/camera/nas/tv).
- `DisplayName` order: name → hostname → NetBIOS → HTTP title → `<Type> · <Vendor>` → `<Type> at <IP>`. No "?" remains.
- Tests: `TestNetBIOSParse`, `TestHTTPInfoTitle`, `TestHTTPInfoLimits`, `TestClassifyNewTypes`, `TestDisplayNameFallbacks`, `TestGatewayIsRouter`.

### Task 3: Port scan profiles
- `lan.ParsePortSpec("22,80,8000-8100")` (1–65535, at most 65535 ports), profiles: `common` (46), `well-known` (1–1024), `extended` (1–10000), `all` (1–65535), `custom`.
- `scheduler.Job.Ports string` (empty = common); deduplication covers Ports too.
- `ApplyPorts(ctx, id, probed, open)`: only probed ports can close.
- Service names: `lan.ServiceName(port)` (small embedded table).
- Device page: profile choice + custom range + "Scanning N ports…" while running.
- Tests: `TestParsePortSpec`, `TestJobPortsDedupe`, `TestApplyPortsPartialScanKeepsOthers`, `TestScanDeviceProfile`, `TestScanDeviceBadSpec`.

### Task 4: Dashboard
- `/` = dashboard: device summary (total/online/unknown/risky ports, last scan, Scan now), alerts (gateway MAC, outage, risky ports, watched device offline), People (home/away), Internet (last latency, last speed, small chart), last 8 events, Pi health.
- Device list at `/devices`; menu: Dashboard · Devices · People · Internet · Events · Settings.
- Tests: `TestDashboardShowsAllSections`, `TestDevicesPageMoved`, `TestNavOrder` updated.

### Task 5: Live UI
- A GET with the `X-Honet-Partial: 1` header → only the `content` block. `honet.js` refreshes the `<main>` content every 15 s; it skips while the tab is hidden, a modal is open, or a form field has focus or changes; if the session has ended it reloads the page.
- Session: partial requests do not update `lastSeen` (`Manager.Peek`).
- Tests: `TestPartialRendersContentOnly`, `TestPartialDoesNotExtendSession`.

### Task 6: Modals
- Layout: confirm modal, error modal, toast container. `data-confirm` → modal; `.Error` → error modal when the page opens; `.Flash` → toast.
- Tests: `TestLayoutHasModals`, `TestErrorRenderedForModal`; the JS is verified by hand in Docker.

### Task 7: Docker verification
- A real scan of 192.168.1.0/24, identification, port profiles, dashboard screenshot.
