package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/classify"
	"github.com/AliSerifDemiralp/honet/internal/health"
	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
)

func (s *server) networkRoutes() {
	s.mux.HandleFunc("GET /{$}", s.dashboardPage)
	s.mux.HandleFunc("GET /devices", s.networkPage)
	s.mux.HandleFunc("POST /scan", s.scanNow)
	s.mux.HandleFunc("POST /gateway/confirm", s.confirmGateway)
	s.mux.HandleFunc("GET /devices/{id}", s.devicePage)
	s.mux.HandleFunc("POST /devices/{id}", s.identify)
	s.mux.HandleFunc("POST /devices/{id}/watch", s.watch)
	s.mux.HandleFunc("POST /devices/{id}/ports/{port}/ack", s.ackPort)
	s.mux.HandleFunc("POST /devices/{id}/scan", s.scanDevice)
	s.mux.HandleFunc("POST /devices/{id}/scan/stop", s.stopDeviceScan)
	s.mux.HandleFunc("POST /devices/{id}/delete", s.deleteDevice)
}

type scanState struct {
	Running      string
	RunningSince time.Time
	LastRun      time.Time
	LastErr      string
}

type riskyDevice struct {
	Device inventory.Device
	Ports  []inventory.Port
}

type networkData struct {
	Devices      []inventory.Device
	Unknown      int
	Online       int
	Risky        []riskyDevice
	InternetDown bool
	Offline      []inventory.Device
	Gateway      *inventory.GatewayAlert
	Conflicts    []inventory.Event
	Scan         scanState
	Health       health.Health

	latest []netmon.Summary
}

func scanStateOf(st scheduler.Status) scanState {
	out := scanState{LastRun: st.LastRun[scheduler.KindDiscovery], LastErr: st.LastErr[scheduler.KindDiscovery]}
	if st.Running != nil {
		out.RunningSince = st.RunningSince
		if st.Running.Kind == scheduler.KindDiscovery {
			out.Running = "Discovering devices…"
		} else {
			out.Running = "Probing ports…"
		}
	}
	return out
}

func (s *server) networkData(r *http.Request) (networkData, error) {
	ctx := r.Context()
	var d networkData
	var err error
	if d.Devices, err = s.Inv.List(ctx); err != nil {
		return d, err
	}
	for _, dev := range d.Devices {
		if dev.Unknown() {
			d.Unknown++
		}
		if dev.Watched && !dev.Online {
			d.Offline = append(d.Offline, dev)
		}
		if dev.Online {
			d.Online++
		}
		if rp := dev.RiskyOpen(); len(rp) > 0 {
			d.Risky = append(d.Risky, riskyDevice{dev, rp})
		}
	}
	if d.latest, err = s.Inv.LatestLatency(ctx); err != nil {
		return d, err
	}
	inet, down := 0, 0
	for _, l := range d.latest {
		if l.Target != netmon.GatewayTarget {
			inet++
			if l.LossPct >= 80 {
				down++
			}
		}
	}
	// Only a recent measurement counts: the monitor may have been turned off.
	d.InternetDown = inet > 0 && down == inet && s.Now().Sub(d.latest[0].At) < time.Hour
	if d.Gateway, err = s.Inv.GatewayAlert(ctx); err != nil {
		return d, err
	}
	evs, err := s.Inv.Events(ctx, 200)
	if err != nil {
		return d, err
	}
	cutoff := s.Now().Add(-24 * time.Hour)
	for _, e := range evs {
		if e.Kind == inventory.EvIPConflict && !e.Read && e.At.After(cutoff) {
			d.Conflicts = append(d.Conflicts, e)
		}
	}
	d.Scan = scanStateOf(s.Sched.Status())
	if s.Health != nil {
		d.Health = s.Health()
	}
	return d, nil
}

func (s *server) networkPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.networkData(r)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, 200, "network", "layout", page{Title: "Devices", Nav: "devices", Data: d})
}

func (s *server) scanNow(w http.ResponseWriter, r *http.Request) {
	msg := "busy"
	if s.Sched.Enqueue(scheduler.Job{Kind: scheduler.KindDiscovery}) {
		msg = "queued"
	}
	next := "/"
	if r.PostFormValue("next") == "/devices" {
		next = "/devices"
	}
	http.Redirect(w, r, next+"?msg="+msg, http.StatusSeeOther)
}

func (s *server) confirmGateway(w http.ResponseWriter, r *http.Request) {
	if err := s.Inv.ConfirmGateway(r.Context()); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/?msg=confirmed", http.StatusSeeOther)
}

type deviceData struct {
	Device   inventory.Device
	IPs      []inventory.IPRecord
	Events   []inventory.Event
	Types    []string
	Profiles []struct{ ID, Label string }
	Scanning int  // ports being scanned on this device now
	Queued   bool // a port scan of this device is waiting
	Custom   string
}

// portScanState reports whether a port scan covering d is running (and how
// many ports it probes) or queued. Scans of all devices only cover online ones.
func portScanState(st scheduler.Status, d inventory.Device) (scanning int, queued bool) {
	covers := func(j scheduler.Job) bool {
		return j.Kind == scheduler.KindPorts && (j.DeviceID == d.ID || (j.DeviceID == 0 && d.Online))
	}
	if j := st.Running; j != nil && covers(*j) {
		ports, _ := lan.JobPorts(j.Ports)
		scanning = len(ports)
	}
	for _, j := range st.Queued {
		if covers(j) {
			queued = true
		}
	}
	return scanning, queued
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// deviceErr maps inventory errors to HTTP responses; it returns true if it wrote one.
func (s *server) deviceErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, inventory.ErrNotFound):
		http.Error(w, "No such device.", http.StatusNotFound)
	case errors.Is(err, inventory.ErrBadType):
		http.Error(w, "Unknown device type.", http.StatusBadRequest)
	default:
		s.serverError(w, err)
	}
	return true
}

func (s *server) devicePage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, ips, evs, err := s.Inv.Get(r.Context(), id)
	if s.deviceErr(w, err) {
		return
	}
	s.renderDevice(w, r, 200, d, ips, evs, "", "")
}

func (s *server) renderDevice(w http.ResponseWriter, r *http.Request, code int, d inventory.Device, ips []inventory.IPRecord, evs []inventory.Event, custom, errMsg string) {
	data := deviceData{Device: d, IPs: ips, Events: evs, Types: classify.Types, Profiles: lan.Profiles, Custom: custom}
	data.Scanning, data.Queued = portScanState(s.Sched.Status(), d)
	s.render(w, r, code, "device", "layout", page{Title: d.DisplayName(), Nav: "devices", Error: errMsg, Data: data})
}

func backToDevice(w http.ResponseWriter, r *http.Request, id int64, msg string) {
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=%s", id, msg), http.StatusSeeOther)
}

func (s *server) identify(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.Inv.Identify(r.Context(), id, r.PostFormValue("name"), r.PostFormValue("notes"),
		r.PostFormValue("type"), r.PostFormValue("known") == "on")
	if s.deviceErr(w, err) {
		return
	}
	backToDevice(w, r, id, "saved")
}

func (s *server) watch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	mins, _ := strconv.Atoi(r.PostFormValue("minutes"))
	if mins < 0 || mins > 7*24*60 {
		http.Error(w, "Minutes must be between 1 and 10080.", http.StatusBadRequest)
		return
	}
	err := s.Inv.SetWatch(r.Context(), id, r.PostFormValue("watch") == "on", time.Duration(mins)*time.Minute)
	if s.deviceErr(w, err) {
		return
	}
	backToDevice(w, r, id, "saved")
}

func (s *server) ackPort(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	port, err := strconv.Atoi(r.PathValue("port"))
	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}
	if s.deviceErr(w, s.Inv.AckPort(r.Context(), id, port, r.PostFormValue("acked") == "1")) {
		return
	}
	backToDevice(w, r, id, "saved")
}

func (s *server) scanDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Inv.IPOf(r.Context(), id); s.deviceErr(w, err) {
		return
	}
	custom := r.PostFormValue("custom")
	_, spec, err := lan.ProfilePorts(r.PostFormValue("profile"), custom)
	if err != nil {
		d, ips, evs, gerr := s.Inv.Get(r.Context(), id)
		if s.deviceErr(w, gerr) {
			return
		}
		s.renderDevice(w, r, http.StatusBadRequest, d, ips, evs, netutil.CleanText(custom, 200), "Port scan: "+err.Error())
		return
	}
	msg := "busy"
	if s.Sched.Enqueue(scheduler.Job{Kind: scheduler.KindPorts, DeviceID: id, Ports: spec}) {
		msg = "queued"
	}
	backToDevice(w, r, id, msg)
}

// stopDeviceScan stops a running or queued port scan of one device.
func (s *server) stopDeviceScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.Sched.Cancel(func(j scheduler.Job) bool { return j.Kind == scheduler.KindPorts && j.DeviceID == id })
	backToDevice(w, r, id, "stopped")
}

func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s.deviceErr(w, s.Inv.Delete(r.Context(), id)) {
		return
	}
	http.Redirect(w, r, "/?msg=deleted", http.StatusSeeOther)
}
