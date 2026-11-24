package inventory

import (
	"net/netip"
	"testing"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
)

func TestDisplayNameFallbacks(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.40")
	cases := []struct {
		d    Device
		want string
	}{
		{Device{Name: "Salon TV", Hostname: "lgtv"}, "Salon TV"},
		{Device{Self: true}, "Honet (this device)"},
		{Device{Hostname: "DESKTOP-AB12", HTTPInfo: "x"}, "DESKTOP-AB12"},
		{Device{HTTPInfo: "Archer C6", Vendor: "TP-Link"}, "Archer C6"},
		{Device{AutoType: "printer", Vendor: "HP Inc.", LastIP: ip}, "Printer · HP Inc."},
		{Device{AutoType: "printer", ManualType: "camera", LastIP: ip}, "Camera at 192.168.1.40"},
		{Device{AutoType: "unknown", LastIP: ip}, "Device at 192.168.1.40"},
	}
	for _, c := range cases {
		if got := c.d.DisplayName(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.d, got, c.want)
		}
	}
}

func TestGatewayDeviceIsRouter(t *testing.T) {
	inv, _, _ := newInv(t)
	gw := netip.MustParseAddr("192.168.1.1")
	inv.ApplyDiscovery(ctx, []lan.Host{host("192.168.1.1", "AA:AA:AA:AA:AA:01"), host("192.168.1.2", "AA:00:00:00:00:02")}, gw)
	for _, d := range mustList(t, inv) {
		if want := d.LastIP == gw; (d.AutoType == "router") != want || d.Gateway != want {
			t.Fatalf("%+v", d)
		}
	}
}

func TestSetHTTPInfoReclassifies(t *testing.T) {
	inv, _, _ := newInv(t)
	id := seen(t, inv, "192.168.1.30", "AA:00:00:00:00:30")
	if err := inv.ApplyPorts(ctx, id, []int{80}); err != nil {
		t.Fatal(err)
	}
	if err := inv.SetHTTPInfo(ctx, id, "  HP LaserJet\x07 Pro  "); err != nil {
		t.Fatal(err)
	}
	d, _, _, err := inv.Get(ctx, id)
	if err != nil || d.HTTPInfo != "HP LaserJet Pro" || d.AutoType != "printer" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestGatewayFlagClearedWhenUnknown(t *testing.T) {
	inv, _, _ := newInv(t)
	gw := netip.MustParseAddr("192.168.1.1")
	hosts := []lan.Host{host("192.168.1.1", "AA:AA:AA:AA:AA:01"), host("192.168.1.2", "AA:00:00:00:00:02")}
	inv.ApplyDiscovery(ctx, hosts, gw)
	inv.ApplyDiscovery(ctx, hosts, netip.Addr{}) // e.g. scanning a range this host is not on
	for _, d := range mustList(t, inv) {
		if d.Gateway || d.AutoType == "router" {
			t.Fatalf("stale gateway flag: %+v", d)
		}
	}
}
