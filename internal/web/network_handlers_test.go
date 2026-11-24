package web

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
)

func h(ip, mac string) lan.Host { return lan.Host{IP: netip.MustParseAddr(ip), MAC: mac} }

func seed(t *testing.T, e *env, hosts ...lan.Host) []int64 {
	t.Helper()
	ids, err := e.inv.ApplyDiscovery(bg, hosts, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestNetworkListsUnknownFirst(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.2", "AA:00:00:00:00:02"), h("192.168.1.50", "AA:00:00:00:00:50"), h("192.168.1.60", "AA:00:00:00:00:60"))
	e.inv.Identify(bg, ids[0], "Living room TV", "", "", true)
	s := body(b.get("/devices"))
	if !strings.Contains(s, "2 unknown devices") {
		t.Fatal("unknown count missing")
	}
	if strings.Index(s, "192.168.1.50") > strings.Index(s, "Living room TV") {
		t.Fatal("unknown device not listed first")
	}
}

func TestHostileHostnameEscaped(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	evil := h("192.168.1.9", "AA:00:00:00:00:09")
	evil.Hostname = "<script>alert(1)</script>"
	seed(t, e, evil)
	for _, p := range []string{"/", "/devices"} {
		s := body(b.get(p))
		if strings.Contains(s, "<script>alert") || !strings.Contains(s, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Fatalf("%s not escaped", p)
		}
	}
}

func TestPartialIsFragment(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	s := body(b.partial("/devices"))
	if strings.Contains(s, "<html") || !strings.Contains(s, "192.168.1.9") {
		t.Fatal("partial should be a bare fragment with devices")
	}
}

func TestIdentifyUpdatesDevice(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	tok := b.pageCSRF()
	w := b.post(path, url.Values{"csrf": {tok}, "name": {"Printer"}, "notes": {"office"}, "type": {"iot_or_embedded"}, "known": {"on"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, body(w))
	}
	s := body(b.get(path))
	if !strings.Contains(s, "Printer") || !strings.Contains(s, "office") {
		t.Fatal("detail page missing new values")
	}
	if w := b.post(path, url.Values{"csrf": {tok}, "type": {"toaster"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad type %d", w.Code)
	}
	if w := b.get("/devices/999"); w.Code != http.StatusNotFound {
		t.Fatalf("missing device %d", w.Code)
	}
}

func TestScanNowEnqueues(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	if w := b.post("/scan", url.Values{"csrf": {tok}}); !strings.Contains(w.Header().Get("Location"), "msg=queued") {
		t.Fatalf("%v", w.Header())
	}
	if w := b.post("/scan", url.Values{"csrf": {tok}}); !strings.Contains(w.Header().Get("Location"), "msg=busy") {
		t.Fatalf("%v", w.Header())
	}
	if !strings.Contains(body(b.get("/?msg=busy")), "A scan is already queued.") {
		t.Fatal("flash missing")
	}
}

func TestGatewayBannerAndConfirm(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	gw := netip.MustParseAddr("192.168.1.1")
	other := h("192.168.1.2", "AA:00:00:00:00:02")
	e.inv.ApplyDiscovery(bg, []lan.Host{h("192.168.1.1", "AA:AA:AA:AA:AA:01"), other}, gw)
	e.inv.ApplyDiscovery(bg, []lan.Host{h("192.168.1.1", "BB:BB:BB:BB:BB:02"), other}, gw)
	if s := body(b.get("/")); !strings.Contains(s, "gateway") || !strings.Contains(s, "BB:BB:BB:BB:BB:02") {
		t.Fatal("gateway banner missing")
	}
	tok := b.pageCSRF()
	b.post("/gateway/confirm", url.Values{"csrf": {tok}})
	if a, _ := e.inv.GatewayAlert(bg); a != nil {
		t.Fatal("not confirmed")
	}
}

func TestRiskyPortBadgeAndAck(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	e.inv.ApplyPorts(bg, ids[0], []int{22, 23})
	if s := body(b.get("/")); !strings.Contains(s, "Telnet") {
		t.Fatal("risky badge missing")
	}
	path := fmt.Sprintf("/devices/%d", ids[0])
	if s := body(b.get(path)); !strings.Contains(s, "plain text") {
		t.Fatal("risk reason missing")
	}
	tok := b.pageCSRF()
	b.post(path+"/ports/23/ack", url.Values{"csrf": {tok}, "acked": {"1"}})
	d, _, _, _ := e.inv.Get(bg, ids[0])
	if len(d.RiskyOpen()) != 0 {
		t.Fatal("ack not stored")
	}
}

func TestWatchAndDelete(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	tok := b.pageCSRF()
	b.post(path+"/watch", url.Values{"csrf": {tok}, "watch": {"on"}, "minutes": {"30"}})
	d, _, _, _ := e.inv.Get(bg, ids[0])
	if !d.Watched || d.WatchAfter.Minutes() != 30 {
		t.Fatalf("%+v", d)
	}
	if w := b.post(path+"/scan", url.Values{"csrf": {tok}}); w.Code != http.StatusSeeOther {
		t.Fatalf("scan %d", w.Code)
	}
	if q := e.sched.Status().Queued; len(q) != 1 || q[0].DeviceID != ids[0] {
		t.Fatalf("queue %+v", q)
	}
	b.post(path+"/delete", url.Values{"csrf": {tok}})
	if w := b.get(path); w.Code != http.StatusNotFound {
		t.Fatalf("after delete %d", w.Code)
	}
}

func TestHealthCardUnderVoltage(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	v := uint32(1)
	temp := 51.5
	e.hl.Throttled = &v
	e.hl.TempC = &temp
	s := body(b.get("/"))
	if !strings.Contains(s, "Under-voltage detected") || !strings.Contains(s, "51.5") {
		t.Fatal("health card")
	}
}
