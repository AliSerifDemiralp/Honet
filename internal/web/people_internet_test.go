package web

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
)

func addDevice(t *testing.T, e *env, ip, mac string) int64 {
	t.Helper()
	hosts := []lan.Host{{IP: netip.MustParseAddr(ip), MAC: mac}, {IP: netip.MustParseAddr("192.168.1.250"), MAC: "02:00:00:00:00:fe"}}
	if _, err := e.inv.ApplyDiscovery(bg, hosts, netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	devs, _ := e.inv.List(bg)
	for _, d := range devs {
		if d.MAC == mac {
			return d.ID
		}
	}
	t.Fatal("device not stored")
	return 0
}

func TestPeopleCreateLinkPresence(t *testing.T) {
	e := newEnv(t)
	dev := addDevice(t, e, "192.168.1.10", "aa:bb:cc:00:00:01")
	b := e.loggedIn()
	tok := b.pageCSRF()
	if w := b.post("/people", url.Values{"csrf": {tok}, "name": {"Ayşe"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, body(w))
	}
	ps, _ := e.inv.People(bg)
	if len(ps) != 1 {
		t.Fatalf("%+v", ps)
	}
	w := b.post(fmt.Sprintf("/people/%d/link", ps[0].ID), url.Values{"csrf": {tok}, "device": {fmt.Sprint(dev)}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("link: %d %s", w.Code, body(w))
	}
	if err := e.inv.EvaluatePresence(bg); err != nil {
		t.Fatal(err)
	}
	page := body(b.get("/people"))
	if !strings.Contains(page, "Ayşe") || !strings.Contains(page, ">Home<") || !strings.Contains(page, "<svg") {
		t.Fatal(page)
	}
	w = b.post(fmt.Sprintf("/people/%d/unlink", ps[0].ID), url.Values{"csrf": {tok}, "device": {fmt.Sprint(dev)}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unlink: %d", w.Code)
	}
	if w := b.post(fmt.Sprintf("/people/%d/delete", ps[0].ID), url.Values{"csrf": {tok}}); w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", w.Code)
	}
	if ps, _ := e.inv.People(bg); len(ps) != 0 {
		t.Fatal("person not deleted")
	}
}

func TestPeopleBadInput(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	if w := b.post("/people", url.Values{"csrf": {tok}, "name": {"   "}}); w.Code != http.StatusBadRequest {
		t.Fatalf("blank name: %d", w.Code)
	}
	id, _ := e.inv.AddPerson(bg, "Ali")
	for _, dev := range []string{"xx", "9999", ""} {
		w := b.post(fmt.Sprintf("/people/%d/link", id), url.Values{"csrf": {tok}, "device": {dev}})
		if w.Code != http.StatusBadRequest {
			t.Errorf("device %q: %d", dev, w.Code)
		}
	}
	if w := b.post("/people/9999/delete", url.Values{"csrf": {tok}}); w.Code != http.StatusNotFound {
		t.Fatalf("missing person: %d", w.Code)
	}
}

func TestInternetPageCharts(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 3; i++ {
		at := e.now.Add(time.Duration(i-3) * 5 * time.Minute)
		e.inv.SaveLatency(bg, []netmon.Summary{
			{At: at, Target: "gateway", AvgMs: 2, MinMs: 1, MaxMs: 3},
			{At: at, Target: "1.1.1.1", AvgMs: 20, MinMs: 15, MaxMs: 30, DNSMs: 12},
		})
	}
	e.inv.SaveSpeedTest(bg, e.now.Add(-time.Hour), speedtest.Result{DownMbps: 24, UpMbps: 6, LoadedMs: 40, Bytes: 30e6}, nil)
	b := e.loggedIn()
	page := body(b.get("/internet"))
	if n := strings.Count(page, "<svg"); n != 2 {
		t.Fatalf("svg count %d\n%s", n, page)
	}
	if !strings.Contains(page, "may be limited by the Pi") || !strings.Contains(page, "1.1.1.1") {
		t.Fatal(page)
	}
	e.inv.SaveSpeedTest(bg, e.now, speedtest.Result{DownMbps: 10, UpMbps: 2, LoadedMs: 40, Bytes: 1e6}, nil)
	if strings.Contains(body(b.get("/internet")), "may be limited by the Pi") {
		t.Fatal("10 Mbps is not near the Pi limit")
	}
}

func TestInternetLatencyUnavailable(t *testing.T) {
	e := newEnv(t)
	e.latErr = fmt.Errorf("%w: operation not permitted", netmon.ErrUnavailable)
	b := e.loggedIn()
	page := body(b.get("/internet"))
	if !strings.Contains(page, "Latency measurement is not available") {
		t.Fatal(page)
	}
}

func TestInternetTestNowQueues(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	w := b.post("/internet/test", url.Values{"csrf": {tok}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/internet?msg=testqueued" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	q := e.sched.Status().Queued
	if len(q) != 1 || q[0].Kind != scheduler.KindSpeed {
		t.Fatalf("%+v", q)
	}
	w = b.post("/internet/test", url.Values{"csrf": {tok}})
	if w.Header().Get("Location") != "/internet?msg=testbusy" {
		t.Fatal(w.Header().Get("Location"))
	}
}

func TestSettingsPhase2Validation(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	for _, bad := range []map[string]string{
		{"targets": "1.1.1.1,not-an-ip"},
		{"targets": "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9"},
		{"speed": "30"}, {"speed": "2000"}, {"latency": "61"}, {"pilimit": "0"}, {"pilimit": "abc"},
	} {
		if w := b.post("/settings", settingsForm(tok, bad)); w.Code != http.StatusBadRequest {
			t.Errorf("%v accepted (%d)", bad, w.Code)
		}
	}
	w := b.post("/settings", settingsForm(tok, map[string]string{"speed": "0", "latency": "5",
		"targets": " 9.9.9.9, 2606:4700:4700::1111 ", "pilimit": "40.5"}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, body(w))
	}
	s, _ := e.st.LoadSettings(bg)
	if s.SpeedInterval != 0 || s.LatencyInterval != 5*time.Minute || s.PiLimitMbps != 40.5 ||
		strings.Join(s.LatencyTargets, ",") != "9.9.9.9,2606:4700:4700::1111" {
		t.Fatalf("%+v", s)
	}
}

func TestNavOrder(t *testing.T) {
	e := newEnv(t)
	page := body(e.loggedIn().get("/"))
	last := -1
	for _, item := range []string{`href="/">Dashboard`, `href="/devices">Devices`, `href="/people">People`, `href="/internet">Internet`, `href="/events" id="nav-events">Events`, `href="/settings">Settings`} {
		i := strings.Index(page, item)
		if i <= last {
			t.Fatalf("%s out of order (%d after %d)", item, i, last)
		}
		last = i
	}
}

func TestPhase2CSRF(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	id, _ := e.inv.AddPerson(bg, "Ali")
	for _, p := range []string{"/people", fmt.Sprintf("/people/%d/link", id), fmt.Sprintf("/people/%d/unlink", id),
		fmt.Sprintf("/people/%d/delete", id), "/internet/test"} {
		if w := b.post(p, url.Values{"name": {"x"}}); w.Code != http.StatusForbidden {
			t.Errorf("%s without csrf: %d", p, w.Code)
		}
	}
}

func TestLatencyChartSlowIntervalDrawsLines(t *testing.T) {
	e := newEnv(t)
	s, _ := e.st.LoadSettings(bg)
	s.LatencyInterval = 30 * time.Minute
	e.st.SaveSettings(bg, s)
	for i := 0; i < 4; i++ {
		at := e.now.Add(time.Duration(i-4) * 30 * time.Minute).Truncate(5 * time.Minute)
		e.inv.SaveLatency(bg, []netmon.Summary{{At: at, Target: "gateway", AvgMs: 2}})
	}
	page := body(e.loggedIn().get("/internet"))
	if strings.Count(page, "<polyline") != 1 || strings.Contains(page, "<circle") {
		t.Fatal("30-minute samples should form one line")
	}
}
