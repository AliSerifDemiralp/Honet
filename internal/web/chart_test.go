package web

import (
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
)

var t0 = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func hrs(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

func TestLineChartBasic(t *testing.T) {
	out := string(LineChart("Speed", "Mbps", hrs(0), hrs(24), []Series{
		{Name: "Down", Class: "chart-a", Points: []Point{{At: hrs(1), V: 10}, {At: hrs(5), V: 20}}},
	}, nil))
	if strings.Count(out, "<polyline") != 1 || !strings.Contains(out, `viewBox="0 0 720 180"`) {
		t.Fatal(out)
	}
	if strings.Contains(out, "style=") {
		t.Fatal("inline style is blocked by the CSP")
	}
	if !strings.Contains(out, `role="img"`) || !strings.Contains(out, "<title>") {
		t.Fatal("chart needs an accessible name")
	}
}

func TestLineChartGapSplits(t *testing.T) {
	out := string(LineChart("x", "ms", hrs(0), hrs(24), []Series{{Name: "a", Class: "chart-a", Points: []Point{
		{At: hrs(1), V: 1}, {At: hrs(2), V: 2}, {At: hrs(3), Gap: true}, {At: hrs(4), V: 3}, {At: hrs(5), V: 4},
	}}}, nil))
	if n := strings.Count(out, "<polyline"); n != 2 {
		t.Fatalf("polylines %d", n)
	}
}

func TestLineChartSinglePointVisible(t *testing.T) {
	out := string(LineChart("x", "ms", hrs(0), hrs(24), []Series{{Name: "a", Class: "chart-a", Points: []Point{{At: hrs(1), V: 1}}}}, nil))
	if !strings.Contains(out, "<circle") {
		t.Fatal("a lone point must still be drawn")
	}
}

func TestLineChartEscapes(t *testing.T) {
	out := string(LineChart("<b>", "ms", hrs(0), hrs(24), []Series{{Name: "<script>", Class: "chart-a", Points: []Point{{At: hrs(1), V: 1}, {At: hrs(2), V: 1}}}}, nil))
	if strings.Contains(out, "<script>") || strings.Contains(out, "<b>") || !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal(out)
	}
}

func TestNiceMax(t *testing.T) {
	for in, want := range map[float64]float64{37: 50, 120: 200, 0: 1, 1: 1, 4.2: 5, 0.3: 0.5, 950: 1000} {
		if got := niceMax(in); got != want {
			t.Errorf("niceMax(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestOutageBand(t *testing.T) {
	out := string(LineChart("x", "ms", hrs(0), hrs(24), nil, []Band{{From: hrs(2), To: hrs(3)}}))
	if strings.Count(out, `class="chart-outage"`) != 1 {
		t.Fatal(out)
	}
}

func TestPresenceStrip(t *testing.T) {
	day2 := t0.AddDate(0, 0, 1)
	days := [][]inventory.Span{
		nil,
		{{From: day2, To: day2.Add(6 * time.Hour), Home: false}, {From: day2.Add(6 * time.Hour), To: day2.Add(18 * time.Hour), Home: true}},
	}
	out := string(PresenceStrip(days, []string{"Sun 22", "Mon 23"}))
	if strings.Count(out, `class="presence-home"`) != 1 || strings.Contains(out, "style=") {
		t.Fatal(out)
	}
	// 06:00–18:00 of a 720-wide day track that starts at x=60: x = 60+165, width 330
	if !strings.Contains(out, `x="225"`) || !strings.Contains(out, `width="330"`) {
		t.Fatal(out)
	}
}
