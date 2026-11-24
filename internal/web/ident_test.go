package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDeviceShowsGuess(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	e.inv.ApplyPorts(bg, ids[0], []int{80, 9100})
	e.inv.SetHTTPInfo(bg, ids[0], "<b>LaserJet</b>")
	s := body(b.get(fmt.Sprintf("/devices/%d", ids[0])))
	for _, want := range []string{"Web page", ">New device<", "&lt;b&gt;LaserJet&lt;/b&gt;", ">Printer<", `<option value="nas">NAS</option>`} {
		if !strings.Contains(s, want) {
			t.Errorf("device page missing %q", want)
		}
	}
	list := body(b.get("/devices"))
	if strings.Contains(list, ">?<") || !strings.Contains(list, "Quiet device at 192.168.1.10") {
		t.Fatal("list still shows ? for unnamed device")
	}
}

func TestScanDeviceProfile(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	tok := b.pageCSRF()
	w := b.post(path+"/scan", url.Values{"csrf": {tok}, "profile": {"well-known"}})
	if !strings.Contains(w.Header().Get("Location"), "msg=queued") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	b.post(path+"/scan", url.Values{"csrf": {tok}, "profile": {"custom"}, "custom": {"8000-8100, 22"}})
	q := e.sched.Status().Queued
	if len(q) < 2 || q[len(q)-2].Ports != "1-1024" || q[len(q)-1].Ports != "22,8000-8100" {
		t.Fatalf("%+v", q)
	}
	s := body(b.get(path))
	for _, want := range []string{`name="profile"`, `value="well-known"`, `name="custom"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestScanDeviceBadSpec(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	tok := b.pageCSRF()
	w := b.post(path+"/scan", url.Values{"csrf": {tok}, "profile": {"custom"}, "custom": {"<x>99999"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(body(w), "not a port number") || strings.Contains(body(w), "<x>") {
		t.Fatalf("%d %s", w.Code, body(w))
	}
	if len(e.sched.Status().Queued) != 0 {
		t.Fatal("queued a bad scan")
	}
}

func TestPortServiceShown(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	e.inv.ApplyPorts(bg, ids[0], []int{9100})
	if s := body(b.get(fmt.Sprintf("/devices/%d", ids[0]))); !strings.Contains(s, `9100 <span class="text-secondary small">printer</span>`) {
		t.Fatal("service name missing")
	}
}
