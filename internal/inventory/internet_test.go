package inventory

import (
	"errors"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
)

func TestSaveSpeedTestError(t *testing.T) {
	inv, c, st := newInv(t)
	if last, err := inv.LastSpeedTest(ctx); err != nil || last != nil {
		t.Fatalf("empty: %v %v", last, err)
	}
	if err := inv.SaveSpeedTest(ctx, c.t, speedtest.Result{DownMbps: 20, UpMbps: 5, LoadedMs: 30, Bytes: 1000}, nil); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Hour)
	if err := inv.SaveSpeedTest(ctx, c.t, speedtest.Result{}, errors.New("download: no data")); err != nil {
		t.Fatal(err)
	}
	rows, err := inv.SpeedTests(ctx, c.t.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].DownMbps != 20 || rows[1].Error != "download: no data" {
		t.Fatalf("%+v", rows)
	}
	last, _ := inv.LastSpeedTest(ctx)
	if last == nil || last.Error == "" || !last.At.Equal(c.t) {
		t.Fatalf("last %+v", last)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 0 {
		t.Fatalf("events %d", n)
	}
}

func TestPruneSpeedTests(t *testing.T) {
	inv, c, _ := newInv(t)
	inv.SaveSpeedTest(ctx, c.t.Add(-91*24*time.Hour), speedtest.Result{DownMbps: 1}, nil)
	inv.SaveSpeedTest(ctx, c.t.Add(-89*24*time.Hour), speedtest.Result{DownMbps: 2}, nil)
	if err := inv.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := inv.SpeedTests(ctx, c.t.Add(-365*24*time.Hour))
	if len(rows) != 1 || rows[0].DownMbps != 2 {
		t.Fatalf("%+v", rows)
	}
}

func win(c *clock, target string, loss float64) netmon.Summary {
	return netmon.Summary{At: c.t.Truncate(5 * time.Minute), Target: target, AvgMs: 10, LossPct: loss}
}

func TestOutageEvent(t *testing.T) {
	inv, c, st := newInv(t)
	down := func() []netmon.Summary {
		return []netmon.Summary{win(c, "gateway", 0), win(c, "1.1.1.1", 100), win(c, "8.8.8.8", 100)}
	}
	if err := inv.SaveLatency(ctx, down()); err != nil {
		t.Fatal(err)
	}
	c.advance(5 * time.Minute)
	inv.SaveLatency(ctx, down())
	if n := countEvents(t, st, EvInternetOutage); n != 1 {
		t.Fatalf("outage events %d", n)
	}
	c.advance(5 * time.Minute)
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 0), win(c, "1.1.1.1", 0), win(c, "8.8.8.8", 100)})
	if n := countEvents(t, st, EvInternetRestored); n != 1 {
		t.Fatalf("restored events %d", n)
	}
	spans, err := inv.Outages(ctx, c.t.Add(-time.Hour))
	if err != nil || len(spans) != 1 || !spans[0].To.After(spans[0].From) {
		t.Fatalf("%+v %v", spans, err)
	}
	rows, _ := inv.Latency(ctx, c.t.Add(-time.Hour))
	if len(rows) != 9 {
		t.Fatalf("rows %d", len(rows))
	}
	latest, _ := inv.LatestLatency(ctx)
	if len(latest) != 3 || latest[0].Target != "1.1.1.1" {
		t.Fatalf("%+v", latest)
	}
}

func TestNoOutageWhenGatewayDown(t *testing.T) {
	inv, _, st := newInv(t)
	c := &clock{t: inv.now()}
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 100), win(c, "1.1.1.1", 100)})
	if n := countEvents(t, st, EvInternetOutage); n != 0 {
		t.Fatalf("outage events %d", n)
	}
}

func TestLatencyNotSavedWithBadClock(t *testing.T) {
	inv, c, st := newInv(t)
	c.t = time.Date(1970, 1, 1, 0, 3, 0, 0, time.UTC)
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 0), win(c, "1.1.1.1", 100)})
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM latency_5m`).Scan(&n)
	if n != 0 || countEvents(t, st, EvInternetOutage) != 0 {
		t.Fatalf("rows %d", n)
	}
}

func TestOutageClosedWhenTargetsRemoved(t *testing.T) {
	inv, c, st := newInv(t)
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 0), win(c, "1.1.1.1", 100)})
	c.advance(5 * time.Minute)
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 0)})
	if n := countEvents(t, st, EvInternetRestored); n != 1 {
		t.Fatalf("restored events %d", n)
	}
	var detail string
	st.DB.QueryRow(`SELECT detail FROM events WHERE kind = ?`, EvInternetRestored).Scan(&detail)
	if detail != "no longer monitored" {
		t.Fatalf("detail %q", detail)
	}
}

func TestOpenOutageEndsWhereDataEnds(t *testing.T) {
	inv, c, _ := newInv(t)
	inv.SaveLatency(ctx, []netmon.Summary{win(c, "gateway", 0), win(c, "1.1.1.1", 100)})
	lastWin := c.t.Truncate(5 * time.Minute)
	c.advance(10 * time.Hour) // monitor turned off: no more summaries
	spans, _ := inv.Outages(ctx, c.t.Add(-24*time.Hour))
	if len(spans) != 1 || spans[0].To.After(lastWin.Add(netmon.Window)) {
		t.Fatalf("%+v", spans)
	}
}
