package inventory

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
)

func TestNewDeviceEvent(t *testing.T) {
	inv, _, st := newInv(t)
	hosts := []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02"), host("192.168.1.3", "AA:00:00:00:00:03")}
	need, err := inv.ApplyDiscovery(ctx, hosts, noGW)
	if err != nil {
		t.Fatal(err)
	}
	if len(need) != 2 || countEvents(t, st, EvNewDevice) != 2 || len(mustList(t, inv)) != 2 {
		t.Fatalf("need %v events %d", need, countEvents(t, st, EvNewDevice))
	}
	for _, id := range need {
		inv.ApplyPorts(ctx, id, nil)
	}
	need, err = inv.ApplyDiscovery(ctx, hosts, noGW)
	if err != nil || len(need) != 0 || countEvents(t, st, EvNewDevice) != 2 {
		t.Fatalf("second pass need %v err %v", need, err)
	}
}

func TestSelfHasNoEventAndNotUnknown(t *testing.T) {
	inv, _, st := newInv(t)
	self := host("192.168.1.10", "B8:27:EB:00:00:01")
	self.Self = true
	if _, err := inv.ApplyDiscovery(ctx, []lan.Host{self, host("192.168.1.2", "AA:00:00:00:00:02")}, noGW); err != nil {
		t.Fatal(err)
	}
	if countEvents(t, st, EvNewDevice) != 1 {
		t.Fatal("self produced an event")
	}
	for _, d := range mustList(t, inv) {
		if d.Self && d.Unknown() {
			t.Fatal("self counted as unknown")
		}
	}
}

func TestIPChange(t *testing.T) {
	inv, c, st := newInv(t)
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02")}, noGW)
	c.advance(time.Minute)
	need, err := inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.9", "AA:00:00:00:00:02")}, noGW)
	if err != nil || len(need) != 1 || countEvents(t, st, EvIPChanged) != 1 {
		t.Fatalf("need %v err %v", need, err)
	}
	_, ips, _, err := inv.Get(ctx, need[0])
	if err != nil || len(ips) != 2 {
		t.Fatalf("ip history %v %v", ips, err)
	}
	if d := mustList(t, inv)[0]; d.LastIP.String() != "192.168.1.9" {
		t.Fatalf("last ip %v", d.LastIP)
	}
}

func TestIPConflict(t *testing.T) {
	inv, c, st := newInv(t)
	hosts := []lan.Host{host("192.168.1.5", "AA:00:00:00:00:01"), host("192.168.1.5", "AA:00:00:00:00:02")}
	inv.ApplyDiscovery(ctx, hosts, noGW)
	if n := countEvents(t, st, EvIPConflict); n != 1 {
		t.Fatalf("conflicts %d", n)
	}
	c.advance(30 * time.Minute)
	inv.ApplyDiscovery(ctx, hosts, noGW)
	if n := countEvents(t, st, EvIPConflict); n != 1 {
		t.Fatalf("conflicts after 30m %d", n)
	}
	c.advance(31 * time.Minute)
	inv.ApplyDiscovery(ctx, hosts, noGW)
	if n := countEvents(t, st, EvIPConflict); n != 2 {
		t.Fatalf("conflicts after 61m %d", n)
	}
}

func TestGatewayMACChange(t *testing.T) {
	inv, _, st := newInv(t)
	gw := netip.MustParseAddr("192.168.1.1")
	other := host("192.168.1.2", "AA:00:00:00:00:02")
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "AA:AA:AA:AA:AA:01"), other}, gw)
	if countEvents(t, st, EvGatewayMACChanged) != 0 {
		t.Fatal("first sighting raised alarm")
	}
	if a, _ := inv.GatewayAlert(ctx); a != nil {
		t.Fatal("unexpected alert")
	}
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "BB:BB:BB:BB:BB:02"), other}, gw)
	a, err := inv.GatewayAlert(ctx)
	if err != nil || a == nil || a.NewMAC != "BB:BB:BB:BB:BB:02" || a.OldMAC != "AA:AA:AA:AA:AA:01" {
		t.Fatalf("alert %+v %v", a, err)
	}
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "BB:BB:BB:BB:BB:02"), other}, gw)
	if n := countEvents(t, st, EvGatewayMACChanged); n != 1 {
		t.Fatalf("events %d", n)
	}
}

func TestEmptyDiscovery(t *testing.T) {
	inv, c, st := newInv(t)
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02")}, noGW)
	before := mustList(t, inv)[0].LastSeen
	c.advance(time.Hour)
	self := host("192.168.1.10", "B8:27:EB:00:00:01")
	self.Self = true
	for _, hs := range [][]lan.Host{nil, {self}} {
		if _, err := inv.ApplyDiscovery(ctx, hs, noGW); !errors.Is(err, ErrEmptyDiscovery) {
			t.Fatalf("err %v", err)
		}
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 1 || !mustList(t, inv)[0].LastSeen.Equal(before) {
		t.Fatalf("events %d", n)
	}
}

func TestApplyPorts(t *testing.T) {
	inv, _, st := newInv(t)
	need, _ := inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02")}, noGW)
	id := need[0]
	if err := inv.ApplyPorts(ctx, id, []int{22, 23}); err != nil {
		t.Fatal(err)
	}
	if countEvents(t, st, EvPortOpened) != 0 {
		t.Fatal("first probe should not emit port events")
	}
	d := mustList(t, inv)[0]
	if r := d.RiskyOpen(); len(r) != 1 || r[0].Port != 23 {
		t.Fatalf("risky %+v", r)
	}
	if err := inv.ApplyPorts(ctx, id, []int{22, 80}); err != nil {
		t.Fatal(err)
	}
	if countEvents(t, st, EvPortOpened) != 1 || countEvents(t, st, EvPortClosed) != 1 {
		t.Fatal("port events")
	}
	d = mustList(t, inv)[0]
	if !reflect.DeepEqual(d.OpenPorts(), []int{22, 80}) || d.AutoType != "server" {
		t.Fatalf("ports %v type %s", d.OpenPorts(), d.AutoType)
	}
}

func TestApplyPortsAfterEmptyFirstProbe(t *testing.T) {
	inv, _, st := newInv(t)
	need, _ := inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02")}, noGW)
	inv.ApplyPorts(ctx, need[0], nil)
	inv.ApplyPorts(ctx, need[0], []int{23})
	if countEvents(t, st, EvPortOpened) != 1 {
		t.Fatal("port opened after an empty first probe must be reported")
	}
}

func TestListOrder(t *testing.T) {
	inv, _, _ := newInv(t)
	need, _ := inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02"), host("192.168.1.50", "AA:00:00:00:00:50")}, noGW)
	if err := inv.Identify(ctx, need[0], "Router", "", "", true); err != nil {
		t.Fatal(err)
	}
	l := mustList(t, inv)
	if l[0].LastIP.String() != "192.168.1.50" || l[1].Name != "Router" {
		t.Fatalf("%+v", l)
	}
}

func TestApplyPortsPartialScanKeepsOthers(t *testing.T) {
	inv, _, st := newInv(t)
	id := seen(t, inv, "192.168.1.30", "AA:00:00:00:00:30")
	if err := inv.ApplyPorts(ctx, id, []int{22, 80}); err != nil {
		t.Fatal(err)
	}
	// A wide scan finds 5357 too; a later common scan does not probe 5357.
	if err := inv.ApplyPortScan(ctx, id, []int{22, 80, 5357}, []int{22, 80, 5357}); err != nil {
		t.Fatal(err)
	}
	if err := inv.ApplyPortScan(ctx, id, []int{22, 80}, []int{22}); err != nil {
		t.Fatal(err)
	}
	d, _, _, _ := inv.Get(ctx, id)
	if got := d.OpenPorts(); len(got) != 2 || got[0] != 22 || got[1] != 5357 {
		t.Fatalf("open %v", got)
	}
	if n := countEvents(t, st, EvPortClosed); n != 1 {
		t.Fatalf("closed events %d", n)
	}
}

func TestUnprobedDeviceQueuedAgain(t *testing.T) {
	inv, _, _ := newInv(t)
	hosts := []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02"), host("192.168.1.3", "AA:00:00:00:00:03")}
	first, _ := inv.ApplyDiscovery(ctx, hosts, noGW)
	if len(first) != 2 {
		t.Fatalf("%v", first)
	}
	inv.ApplyPorts(ctx, first[0], []int{22})
	again, _ := inv.ApplyDiscovery(ctx, hosts, noGW)
	if len(again) != 1 || again[0] != first[1] {
		t.Fatalf("port scan interrupted: %v should be queued again", again)
	}
}
