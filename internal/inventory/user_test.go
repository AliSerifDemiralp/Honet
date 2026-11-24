package inventory

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

func oneDevice(t *testing.T, inv *Inventory) int64 {
	t.Helper()
	need, err := inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.2", "AA:00:00:00:00:02"), host("192.168.1.3", "AA:00:00:00:00:03")}, noGW)
	if err != nil {
		t.Fatal(err)
	}
	return need[0]
}

func TestIdentify(t *testing.T) {
	inv, _, _ := newInv(t)
	id := oneDevice(t, inv)
	if err := inv.Identify(ctx, id, "<b>TV\x00", "", "toaster", false); !errors.Is(err, ErrBadType) {
		t.Fatalf("err %v", err)
	}
	if err := inv.Identify(ctx, id, "<b>TV\x00", "n", "smart_tv", true); err != nil {
		t.Fatal(err)
	}
	d, _, _, _ := inv.Get(ctx, id)
	if d.Name != "<b>TV" || d.Unknown() || d.Type() != "smart_tv" {
		t.Fatalf("%+v", d)
	}
	if err := inv.Identify(ctx, 999, "x", "", "", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing device: %v", err)
	}
}

func rescan(t *testing.T, inv *Inventory, hosts ...lan.Host) {
	t.Helper()
	if _, err := inv.ApplyDiscovery(ctx, hosts, noGW); err != nil {
		t.Fatal(err)
	}
}

func TestWatchOffline(t *testing.T) {
	inv, c, st := newInv(t)
	id := oneDevice(t, inv)
	if err := inv.SetWatch(ctx, id, true, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	other := host("192.168.1.3", "AA:00:00:00:00:03")
	c.advance(10 * time.Minute)
	rescan(t, inv, other)
	inv.EvaluateWatch(ctx, c.now())
	if countEvents(t, st, EvDeviceOffline) != 0 {
		t.Fatal("offline too early")
	}
	c.advance(10 * time.Minute)
	rescan(t, inv, other)
	inv.EvaluateWatch(ctx, c.now())
	if countEvents(t, st, EvDeviceOffline) != 1 {
		t.Fatal("expected offline")
	}
	off, _ := inv.WatchedOffline(ctx)
	if len(off) != 1 || off[0].ID != id {
		t.Fatalf("offline list %+v", off)
	}
	inv.EvaluateWatch(ctx, c.now())
	if countEvents(t, st, EvDeviceOffline) != 1 {
		t.Fatal("duplicate offline")
	}
	rescan(t, inv, host("192.168.1.2", "AA:00:00:00:00:02"), other)
	if countEvents(t, st, EvDeviceOnline) != 1 {
		t.Fatal("expected online")
	}
}

func TestWatchNoFalseOfflineWhenScansFailing(t *testing.T) {
	inv, c, st := newInv(t)
	id := oneDevice(t, inv)
	inv.SetWatch(ctx, id, true, 15*time.Minute)
	lastGood := c.now()
	c.advance(20 * time.Minute)
	inv.EvaluateWatch(ctx, lastGood)
	if countEvents(t, st, EvDeviceOffline) != 0 {
		t.Fatal("offline raised although no scan succeeded")
	}
}

func TestWatchSkipsInsaneClock(t *testing.T) {
	inv, c, st := newInv(t)
	id := oneDevice(t, inv)
	inv.SetWatch(ctx, id, true, time.Minute)
	c.t = time.Unix(0, 0).UTC()
	inv.EvaluateWatch(ctx, c.now())
	if countEvents(t, st, EvDeviceOffline) != 0 {
		t.Fatal("evaluated with 1970 clock")
	}
}

func TestUnwatchedNeverOffline(t *testing.T) {
	inv, c, st := newInv(t)
	oneDevice(t, inv)
	c.advance(24 * time.Hour)
	rescan(t, inv, host("192.168.1.3", "AA:00:00:00:00:03"))
	inv.EvaluateWatch(ctx, c.now())
	if countEvents(t, st, EvDeviceOffline) != 0 {
		t.Fatal("unwatched device went offline")
	}
}

func TestSetWatchDefaultAndMinimum(t *testing.T) {
	inv, _, st := newInv(t)
	id := oneDevice(t, inv)
	if err := inv.SetWatch(ctx, id, true, 0); err != nil {
		t.Fatal(err)
	}
	d, _, _, _ := inv.Get(ctx, id)
	if d.WatchAfter != store.DefaultSettings().WatchAfter {
		t.Fatalf("default %v", d.WatchAfter)
	}
	_ = st
	inv.SetWatch(ctx, id, true, 10*time.Second)
	d, _, _, _ = inv.Get(ctx, id)
	if d.WatchAfter != time.Minute {
		t.Fatalf("minimum %v", d.WatchAfter)
	}
}

func TestAckPort(t *testing.T) {
	inv, _, _ := newInv(t)
	id := oneDevice(t, inv)
	inv.ApplyPorts(ctx, id, []int{23})
	if err := inv.AckPort(ctx, id, 23, true); err != nil {
		t.Fatal(err)
	}
	d, _, _, _ := inv.Get(ctx, id)
	if len(d.RiskyOpen()) != 0 {
		t.Fatal("acked port still risky")
	}
}

func TestConfirmGateway(t *testing.T) {
	inv, _, st := newInv(t)
	gw := netip.MustParseAddr("192.168.1.1")
	other := host("192.168.1.2", "AA:00:00:00:00:02")
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "AA:AA:AA:AA:AA:01"), other}, gw)
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "BB:BB:BB:BB:BB:02"), other}, gw)
	if err := inv.ConfirmGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if a, _ := inv.GatewayAlert(ctx); a != nil {
		t.Fatal("alert after confirm")
	}
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "BB:BB:BB:BB:BB:02"), other}, gw)
	if countEvents(t, st, EvGatewayMACChanged) != 1 {
		t.Fatal("confirmed MAC raised alarm")
	}
}

func TestDelete(t *testing.T) {
	inv, _, _ := newInv(t)
	id := oneDevice(t, inv)
	inv.ApplyPorts(ctx, id, []int{22})
	if err := inv.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := inv.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestPrune(t *testing.T) {
	inv, c, st := newInv(t)
	at := func(d time.Duration) string { return store.FormatTime(c.now().Add(-d)) }
	st.DB.Exec(`INSERT INTO events(at, kind) VALUES (?, 'x'), (?, 'y')`, at(91*24*time.Hour), at(89*24*time.Hour))
	st.DB.Exec(`INSERT INTO scans(kind, started) VALUES ('d', ?), ('d', ?)`, at(31*24*time.Hour), at(29*24*time.Hour))
	if err := inv.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var ev, sc int
	st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&ev)
	st.DB.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&sc)
	if ev != 1 || sc != 1 {
		t.Fatalf("events %d scans %d", ev, sc)
	}
}
