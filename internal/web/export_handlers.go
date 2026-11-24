package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// exportRow is the public view of a device. It deliberately carries no
// account, password or login data.
type exportRow struct {
	Name      string `json:"name"`
	Known     bool   `json:"known"`
	Type      string `json:"type"`
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Hostname  string `json:"hostname"`
	OpenPorts []int  `json:"open_ports"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

func exportRows(devs []inventory.Device) []exportRow {
	out := make([]exportRow, 0, len(devs))
	for _, d := range devs {
		ports := d.OpenPorts()
		if ports == nil {
			ports = []int{}
		}
		out = append(out, exportRow{Name: d.Name, Known: d.Known, Type: d.Type(), IP: d.LastIP.String(), MAC: d.MAC,
			Vendor: d.Vendor, Hostname: d.Hostname, OpenPorts: ports,
			FirstSeen: store.FormatTime(d.FirstSeen), LastSeen: store.FormatTime(d.LastSeen)})
	}
	return out
}

func attachment(w http.ResponseWriter, name, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
}

// csvSafe stops spreadsheet apps from treating a cell as a formula.
func csvSafe(s string) string {
	if s != "" && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
		return "'" + s
	}
	return s
}

func (s *server) exportCSV(w http.ResponseWriter, r *http.Request) {
	devs, err := s.Inv.List(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	attachment(w, "honet-devices.csv", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	cw.Write([]string{"name", "known", "type", "ip", "mac", "vendor", "hostname", "open_ports", "first_seen", "last_seen"})
	for _, x := range exportRows(devs) {
		cw.Write([]string{csvSafe(x.Name), strconv.FormatBool(x.Known), x.Type, x.IP, x.MAC, csvSafe(x.Vendor),
			csvSafe(x.Hostname), joinInts(x.OpenPorts), x.FirstSeen, x.LastSeen})
	}
	cw.Flush()
}

func (s *server) exportJSON(w http.ResponseWriter, r *http.Request) {
	devs, err := s.Inv.List(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	attachment(w, "honet-devices.json", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(exportRows(devs))
}

type kindCount struct {
	Kind  string
	Count int
}

type reportData struct {
	Generated time.Time
	Devices   []inventory.Device
	Counts    []kindCount
	Events    []inventory.Event
	Total     int
}

// reportEventRows caps the event table; the per-kind counts stay complete.
const reportEventRows = 500

func (s *server) report(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devs, err := s.Inv.List(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	cutoff := s.Now().Add(-7 * 24 * time.Hour)
	counts, err := s.Inv.EventCounts(ctx, cutoff)
	if err != nil {
		s.serverError(w, err)
		return
	}
	recent, err := s.Inv.EventsSince(ctx, cutoff, reportEventRows)
	if err != nil {
		s.serverError(w, err)
		return
	}
	d := reportData{Generated: s.Now(), Devices: devs, Events: recent}
	for k, n := range counts {
		d.Counts = append(d.Counts, kindCount{k, n})
		d.Total += n
	}
	sort.Slice(d.Counts, func(i, j int) bool { return d.Counts[i].Kind < d.Counts[j].Kind })
	s.render(w, r, 200, "report", "layout", page{Title: "Report", Data: d})
}

func (s *server) eventsPage(w http.ResponseWriter, r *http.Request) {
	evs, err := s.Inv.Events(r.Context(), 200)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, 200, "events", "layout", page{Title: "Events", Nav: "events", Data: evs})
}

func (s *server) eventsRead(w http.ResponseWriter, r *http.Request) {
	if err := s.Inv.MarkAllRead(r.Context()); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/events?msg=read", http.StatusSeeOther)
}
