package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
)

func TestLayoutHasModals(t *testing.T) {
	e := newEnv(t)
	s := body(e.loggedIn().get("/"))
	for _, want := range []string{`id="confirm-modal"`, `id="confirm-text"`, `id="confirm-ok"`, `class="toast-container`} {
		if !strings.Contains(s, want) {
			t.Errorf("layout missing %s", want)
		}
	}
	// Modals live outside <main> so a live refresh does not remove them.
	if strings.Index(s, `id="confirm-modal"`) < strings.Index(s, "</main>") {
		t.Error("confirm modal inside <main>")
	}
}

func TestErrorRenderedForModal(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	tok := b.pageCSRF()
	w := b.post(fmt.Sprintf("/devices/%d/scan", ids[0]), url.Values{"csrf": {tok}, "profile": {"custom"}, "custom": {"0"}})
	s := body(w)
	if w.Code != http.StatusBadRequest || !strings.Contains(s, `id="error-modal"`) || !strings.Contains(s, "not a port number") {
		t.Fatalf("%d %s", w.Code, s)
	}
	if strings.Contains(s, `<div class="alert alert-danger" role="alert">Port scan`) {
		t.Fatal("error still rendered as inline alert")
	}
}

func TestFlashIsToast(t *testing.T) {
	e := newEnv(t)
	s := body(e.loggedIn().get("/?msg=queued"))
	i := strings.Index(s, `class="toast`)
	if i < 0 || !strings.Contains(s[i:], "Scan queued.") {
		t.Fatal("flash not rendered as toast")
	}
	if strings.Contains(s, `alert alert-success`) {
		t.Fatal("flash still an inline alert")
	}
}

func TestNoBrowserDialogs(t *testing.T) {
	js, err := assets.ReadFile("static/honet.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"window.confirm", "window.alert", "alert(", "prompt("} {
		if strings.Contains(string(js), bad) {
			t.Errorf("honet.js uses %s", bad)
		}
	}
}

func TestStopPortScan(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	tok := b.pageCSRF()
	b.post(path+"/scan", url.Values{"csrf": {tok}, "profile": {"all"}})
	w := b.post(path+"/scan/stop", url.Values{"csrf": {tok}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "msg=stopped") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if q := e.sched.Status().Queued; len(q) != 0 {
		t.Fatalf("queue %+v", q)
	}
	if !strings.Contains(body(b.get(path+"?msg=stopped")), "Port scan stopped.") {
		t.Fatal("flash")
	}
}

func TestScanStateIgnoresOfflineDevice(t *testing.T) {
	st := scheduler.Status{Running: &scheduler.Job{Kind: scheduler.KindPorts}}
	if n, _ := portScanState(st, inventory.Device{ID: 3, Online: false}); n != 0 {
		t.Fatal("offline device is not in an all-devices scan")
	}
	if n, _ := portScanState(st, inventory.Device{ID: 3, Online: true}); n != len(lan.CommonPorts) {
		t.Fatalf("%d", n)
	}
	st = scheduler.Status{Running: &scheduler.Job{Kind: scheduler.KindPorts, DeviceID: 3, Ports: "1-10"}}
	if n, _ := portScanState(st, inventory.Device{ID: 3}); n != 10 {
		t.Fatalf("%d", n)
	}
}

func TestDevicesFragmentRouteRemoved(t *testing.T) {
	e := newEnv(t)
	if w := e.loggedIn().get("/partials/devices"); w.Code != http.StatusNotFound {
		t.Fatalf("%d", w.Code)
	}
}

func TestProbedWithoutOpenPorts(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	path := fmt.Sprintf("/devices/%d", ids[0])
	if !strings.Contains(body(b.get(path)), "Not probed yet.") {
		t.Fatal("unprobed")
	}
	e.inv.ApplyPorts(bg, ids[0], nil)
	if s := body(b.get(path)); !strings.Contains(s, "No open ports found") || strings.Contains(s, "Not probed yet.") {
		t.Fatal("probed device still says not probed")
	}
}
