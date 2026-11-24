package web

import (
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
)

func TestDashboardShowsAllSections(t *testing.T) {
	e := newEnv(t)
	dev := addDevice(t, e, "192.168.1.10", "aa:bb:cc:00:00:01")
	e.inv.ApplyPorts(bg, dev, []int{23})
	pid, _ := e.inv.AddPerson(bg, "Ayşe")
	e.inv.LinkDevice(bg, pid, dev)
	e.inv.EvaluatePresence(bg)
	e.inv.SaveSpeedTest(bg, e.now.Add(-time.Hour), speedtest.Result{DownMbps: 87.5, UpMbps: 21.25}, nil)
	at := e.now.Add(-10 * time.Minute)
	e.inv.SaveLatency(bg, []netmon.Summary{{At: at, Target: netmon.GatewayTarget, AvgMs: 0.04}, {At: at, Target: "1.1.1.1", AvgMs: 14.5}})
	s := body(e.loggedIn().get("/"))
	for _, want := range []string{
		"Dashboard", ">2<", "Total devices", "Online now", "Unknown", // device summary
		"Scan now", "Telnet", // risky port alert
		"Ayşe", "Home", // people
		"87.5", "21.2", "14.5 ms", "0.04 ms", // internet
		"Recent events", "New device", // events
		"Honet host", // health
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestDashboardEmpty(t *testing.T) {
	e := newEnv(t)
	s := body(e.loggedIn().get("/"))
	for _, want := range []string{"No devices yet", "No people yet", "No speed test yet"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestDevicesPageMoved(t *testing.T) {
	e := newEnv(t)
	addDevice(t, e, "192.168.1.10", "aa:bb:cc:00:00:01")
	b := e.loggedIn()
	s := body(b.get("/devices"))
	if !strings.Contains(s, "192.168.1.10") || !strings.Contains(s, `class="nav-link active" href="/devices"`) {
		t.Fatal("devices page")
	}
	if d := body(b.get("/devices/1")); !strings.Contains(d, `href="/devices">← Devices`) {
		t.Fatal("device page back link")
	}
}
