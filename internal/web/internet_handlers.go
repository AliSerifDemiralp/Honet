package web

import (
	"html/template"
	"net/http"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
)

func (s *server) internetRoutes() {
	s.mux.HandleFunc("GET /internet", s.internetPage)
	s.mux.HandleFunc("POST /internet/test", s.internetTest)
}

type internetData struct {
	Latest       []netmon.Summary
	LatErr       string
	LatencyOff   bool
	Last         *inventory.SpeedRow
	Limited      bool
	PiLimit      float64
	SpeedOff     bool
	SpeedRunning bool
	SpeedChart   template.HTML
	LatChart     template.HTML
}

var seriesClasses = []string{"chart-a", "chart-b", "chart-c"}

// latencyGap is the longest pause between latency points drawn as one
// line: two missed measurements, but at least 15 minutes.
func latencyGap(interval time.Duration) time.Duration {
	return max(15*time.Minute, 2*interval+netmon.Window)
}

// latencySeries turns latency rows into one line per target, broken where
// measurements are missing.
func latencySeries(lat []netmon.Summary, interval time.Duration, loc *time.Location) []Series {
	var series []Series
	index := map[string]int{}
	last := map[string]time.Time{}
	maxGap := latencyGap(interval)
	for _, l := range lat {
		i, ok := index[l.Target]
		if !ok {
			i = len(series)
			index[l.Target] = i
			series = append(series, Series{Name: l.Target, Class: seriesClasses[i%len(seriesClasses)]})
		}
		at := l.At.In(loc)
		if p, ok := last[l.Target]; ok && at.Sub(p) > maxGap {
			series[i].Points = append(series[i].Points, Point{At: p, Gap: true})
		}
		last[l.Target] = at
		series[i].Points = append(series[i].Points, Point{At: at, V: l.AvgMs, Gap: l.LossPct >= 100})
	}
	return series
}

func (s *server) internetPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.Now()
	from := now.Add(-7 * 24 * time.Hour)
	set := s.settings(ctx)
	d := internetData{PiLimit: set.PiLimitMbps, LatencyOff: set.LatencyInterval == 0, SpeedOff: set.SpeedInterval == 0}
	if s.Latency != nil {
		if err := s.Latency(); err != nil {
			d.LatErr = err.Error()
		}
	}
	if st := s.Sched.Status(); st.Running != nil && st.Running.Kind == scheduler.KindSpeed {
		d.SpeedRunning = true
	}
	var err error
	if d.Latest, err = s.Inv.LatestLatency(ctx); err != nil {
		s.serverError(w, err)
		return
	}
	if d.Last, err = s.Inv.LastSpeedTest(ctx); err != nil {
		s.serverError(w, err)
		return
	}
	if d.Last != nil && d.Last.Error == "" && set.PiLimitMbps > 0 {
		lim := set.PiLimitMbps * 0.9
		d.Limited = d.Last.DownMbps >= lim || d.Last.UpMbps >= lim
	}
	outages, err := s.Inv.Outages(ctx, from)
	if err != nil {
		s.serverError(w, err)
		return
	}
	bands := make([]Band, len(outages))
	for i, o := range outages {
		bands[i] = Band{From: o.From, To: o.To}
	}

	tests, err := s.Inv.SpeedTests(ctx, from)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(tests) > 0 {
		down := Series{Name: "Download", Class: "chart-a"}
		up := Series{Name: "Upload", Class: "chart-b"}
		for _, t := range tests {
			gap := t.Error != ""
			down.Points = append(down.Points, Point{At: t.At.In(now.Location()), V: t.DownMbps, Gap: gap})
			up.Points = append(up.Points, Point{At: t.At.In(now.Location()), V: t.UpMbps, Gap: gap})
		}
		d.SpeedChart = LineChart("Speed, last 7 days", "Mbps", from, now, []Series{down, up}, bands)
	}

	lat, err := s.Inv.Latency(ctx, from)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(lat) > 0 {
		d.LatChart = LineChart("Average latency, last 7 days", "ms", from, now, latencySeries(lat, set.LatencyInterval, now.Location()), bands)
	}
	s.render(w, r, 200, "internet", "layout", page{Title: "Internet", Nav: "internet", Data: d})
}

func (s *server) internetTest(w http.ResponseWriter, r *http.Request) {
	msg := "testbusy"
	if s.Sched.Enqueue(scheduler.Job{Kind: scheduler.KindSpeed}) {
		msg = "testqueued"
	}
	http.Redirect(w, r, "/internet?msg="+msg, http.StatusSeeOther)
}
