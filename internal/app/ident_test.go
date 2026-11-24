package app

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
)

func TestRunnerNetBIOSFillsMissingHostname(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"},
	}}
	r, _, _ := newRunner(t, d)
	var mu sync.Mutex
	var asked []string
	r.NetBIOS = func(ctx context.Context, ip netip.Addr) string {
		mu.Lock()
		asked = append(asked, ip.String())
		mu.Unlock()
		if ip.String() == "192.168.1.2" {
			return "DESKTOP-AB12"
		}
		return ""
	}
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v", asked)
	}
	names := map[string]string{}
	devs, _ := r.Inv.List(context.Background())
	for _, dv := range devs {
		names[dv.LastIP.String()] = dv.Hostname
	}
	if names["192.168.1.2"] != "DESKTOP-AB12" || names["192.168.1.3"] != "" {
		t.Fatalf("%v", names)
	}
}

func TestRunnerProbeReadsWebTitle(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"},
	}}
	r, _, queued := newRunner(t, d)
	r.Prober = fakeProber{open: []int{22, 443, 8080}}
	var asked []int
	r.HTTPInfo = func(ctx context.Context, ip netip.Addr, port int) string {
		asked = append(asked, port)
		return "HP LaserJet Pro"
	}
	ctx := context.Background()
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(ctx, (*queued)[0]); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != 443 {
		t.Fatalf("asked %v", asked)
	}
	dv, _, _, _ := r.Inv.Get(ctx, (*queued)[0].DeviceID)
	if dv.HTTPInfo != "HP LaserJet Pro" || dv.AutoType != "printer" {
		t.Fatalf("%+v", dv)
	}
}

func TestRunnerProbeNoWebNoTitle(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"}, {IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"}}}
	r, _, queued := newRunner(t, d)
	called := false
	r.HTTPInfo = func(context.Context, netip.Addr, int) string { called = true; return "x" }
	r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery})
	r.Run(context.Background(), (*queued)[0])
	if called {
		t.Fatal("HTTP probed without a web port")
	}
}

type recProber struct{ got *[]int }

func (p recProber) Probe(ctx context.Context, ip netip.Addr, ports []int) ([]int, error) {
	*p.got = ports
	return []int{22}, nil
}

func TestRunnerUsesJobPorts(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"}, {IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"}}}
	r, _, queued := newRunner(t, d)
	var got []int
	r.Prober = recProber{&got}
	ctx := context.Background()
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery})
	id := (*queued)[0].DeviceID
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id, Ports: "8000-8002"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 8000 {
		t.Fatalf("%v", got)
	}
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id}); err != nil || len(got) != len(lan.CommonPorts) {
		t.Fatalf("%d %v", len(got), err)
	}
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id, Ports: "0-5"}); err == nil {
		t.Fatal("bad spec ran")
	}
}

func TestRunnerCommonScanKeepsWideScanPorts(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"}, {IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"}}}
	r, _, queued := newRunner(t, d)
	ctx := context.Background()
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery})
	id := (*queued)[0].DeviceID
	r.Prober = fakeProber{open: []int{22, 5357}}
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id, Ports: "1-6000"})
	r.Prober = fakeProber{open: []int{22}}
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id})
	dv, _, _, _ := r.Inv.Get(ctx, id)
	if got := dv.OpenPorts(); len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestRunnerProbeWaitsAfterSweep(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"}, {IP: netip.MustParseAddr("192.168.1.3"), MAC: "AA:00:00:00:00:03"}}}
	r, _, queued := newRunner(t, d)
	var waited []time.Duration
	r.Sleep = func(ctx context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	ctx := context.Background()
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery}) // on-link: ARP, no wait
	r.Run(ctx, (*queued)[0])
	if len(waited) != 0 {
		t.Fatalf("waited after ARP discovery: %v", waited)
	}
	r.Sweep = &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("10.0.0.5")}, {IP: netip.MustParseAddr("10.0.0.6")}}}
	set, _ := r.Store.LoadSettings(ctx)
	set.CIDR = "10.0.0.0/24"
	r.Store.SaveSettings(ctx, set)
	*queued = nil
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	r.Run(ctx, (*queued)[0])
	r.Run(ctx, (*queued)[1])
	if len(waited) != 1 || waited[0] <= 0 || waited[0] > SweepSettle {
		t.Fatalf("waits %v: want one wait right after the sweep", waited)
	}
}
