package web

import (
	"html/template"
	"net/http"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netmon"
)

type dashboardData struct {
	networkData
	People    []inventory.Person
	Latest    []netmon.Summary
	LastSpeed *inventory.SpeedRow
	LatChart  template.HTML
	Events    []inventory.Event
}

// dashboardPage shows everything at a glance: devices, alerts, people,
// internet, recent events and the host's health.
func (s *server) dashboardPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nd, err := s.networkData(r)
	if err != nil {
		s.serverError(w, err)
		return
	}
	d := dashboardData{networkData: nd, Latest: nd.latest}
	if d.People, err = s.Inv.People(ctx); err != nil {
		s.serverError(w, err)
		return
	}
	if d.LastSpeed, err = s.Inv.LastSpeedTest(ctx); err != nil {
		s.serverError(w, err)
		return
	}
	if d.Events, err = s.Inv.Events(ctx, 8); err != nil {
		s.serverError(w, err)
		return
	}
	now := s.Now()
	from := now.Add(-24 * time.Hour)
	lat, err := s.Inv.Latency(ctx, from)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(lat) > 0 {
		d.LatChart = LineChart("Latency, last 24 hours", "ms", from, now, latencySeries(lat, s.settings(ctx).LatencyInterval, now.Location()), nil)
	}
	s.render(w, r, 200, "dashboard", "layout", page{Title: "Dashboard", Nav: "dashboard", Data: d})
}
