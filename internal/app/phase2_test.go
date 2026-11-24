package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
)

type fakeSpeed struct {
	r   speedtest.Result
	err error
}

func (f fakeSpeed) Run(context.Context) (speedtest.Result, error) { return f.r, f.err }

func TestRunnerSpeedJob(t *testing.T) {
	r, st, _ := newRunner(t, &fakeDisc{})
	r.Speed = fakeSpeed{r: speedtest.Result{DownMbps: 21, UpMbps: 4, Bytes: 9e6}}
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindSpeed}); err != nil {
		t.Fatal(err)
	}
	last, _ := r.Inv.LastSpeedTest(context.Background())
	if last == nil || last.DownMbps != 21 || last.Error != "" {
		t.Fatalf("%+v", last)
	}
	var kind string
	st.DB.QueryRow(`SELECT kind FROM scans`).Scan(&kind)
	if kind != "speedtest" {
		t.Fatalf("scan kind %q", kind)
	}
}

func TestRunnerSpeedJobRecordsFailure(t *testing.T) {
	r, st, _ := newRunner(t, &fakeDisc{})
	r.Speed = fakeSpeed{err: errors.New("download: no data transferred")}
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindSpeed}); err == nil {
		t.Fatal("want the job to fail")
	}
	last, _ := r.Inv.LastSpeedTest(context.Background())
	if last == nil || last.Error == "" {
		t.Fatalf("%+v", last)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 0 {
		t.Fatalf("events %d", n)
	}
}

func TestRunnerSpeedJobNotConfigured(t *testing.T) {
	r, _, _ := newRunner(t, &fakeDisc{})
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindSpeed}); err == nil {
		t.Fatal("want an error without a tester")
	}
}

func TestRunnerDiscoveryEvaluatesPresence(t *testing.T) {
	d := &fakeDisc{hosts: []lan.Host{
		{IP: netip.MustParseAddr("192.168.1.1"), MAC: "AA:00:00:00:00:01"},
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "AA:00:00:00:00:02"},
	}}
	r, _, _ := newRunner(t, d)
	ctx := context.Background()
	r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery})
	devs, _ := r.Inv.List(ctx)
	pid, _ := r.Inv.AddPerson(ctx, "Ali")
	r.Inv.LinkDevice(ctx, pid, devs[0].ID)
	if err := r.Run(ctx, scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	ps, _ := r.Inv.People(ctx)
	if len(ps) != 1 || !ps[0].Known || !ps[0].Home {
		t.Fatalf("%+v", ps)
	}
}

func TestRunnerUsesSweepOffLink(t *testing.T) {
	arp := &fakeDisc{}
	sweep := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("10.0.5.1")}, {IP: netip.MustParseAddr("10.0.5.20")}}}
	r, st, _ := newRunner(t, arp)
	r.Sweep = sweep
	s, _ := st.LoadSettings(context.Background())
	s.CIDR = "10.0.5.0/24"
	st.SaveSettings(context.Background(), s)
	if err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery}); err != nil {
		t.Fatal(err)
	}
	if arp.called || !sweep.called {
		t.Fatalf("arp %v sweep %v", arp.called, sweep.called)
	}
	devs, _ := r.Inv.List(context.Background())
	if len(devs) != 2 {
		t.Fatalf("%+v", devs)
	}
}

func TestRunnerOnLinkUsesARP(t *testing.T) {
	arp := &fakeDisc{hosts: []lan.Host{{IP: netip.MustParseAddr("192.168.1.5"), MAC: "AA:00:00:00:00:05"}}}
	sweep := &fakeDisc{}
	r, _, _ := newRunner(t, arp)
	r.Sweep = sweep
	r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery})
	if !arp.called || sweep.called {
		t.Fatalf("arp %v sweep %v", arp.called, sweep.called)
	}
}

func TestRunnerOffLinkEmptyErrorNamesSubnet(t *testing.T) {
	r, st, _ := newRunner(t, &fakeDisc{})
	r.Sweep = &fakeDisc{}
	s, _ := st.LoadSettings(context.Background())
	s.CIDR = "10.0.5.0/24"
	st.SaveSettings(context.Background(), s)
	err := r.Run(context.Background(), scheduler.Job{Kind: scheduler.KindDiscovery})
	if err == nil || !strings.Contains(err.Error(), "10.0.5.0/24") || !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Fatalf("%v", err)
	}
}
