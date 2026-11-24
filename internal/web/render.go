package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/classify"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
)

//go:embed templates static
var assets embed.FS

// page is the data every template receives.
type page struct {
	Title   string
	Nav     string
	User    string
	CSRF    string
	Unread  int
	Version string
	Flash   string
	Error   string
	Data    any
	Live    bool // the page refreshes itself in the background
}

type templates struct {
	files  fs.FS
	reload bool
	mu     sync.Mutex
	sets   map[string]*template.Template
}

var funcs = template.FuncMap{
	"ago":       ago,
	"when":      func(t time.Time) string { return t.Local().Format("02.01.2006 15:04") },
	"ports":     joinInts,
	"bytes":     humanBytes,
	"ibytes":    func(n int64) string { return humanBytes(uint64(max(n, 0))) },
	"typelabel": classify.Label,
	"asset":     asset,
	"ms": func(v float64) string {
		if v < 1 {
			return fmt.Sprintf("%.2f ms", v)
		}
		return fmt.Sprintf("%.1f ms", v)
	},
	"service": lan.ServiceName,
	"dur":     humanDur,
	"deref":   func(p *float64) float64 { return *p },
	"evlabel": func(k string) string {
		if l, ok := eventLabels[k]; ok {
			return l
		}
		return k
	},
	"evclass": func(k string) string {
		switch k {
		case "gateway_mac_changed", "ip_conflict", "device_offline", "internet_outage":
			return "text-bg-danger"
		case "new_device", "port_opened":
			return "text-bg-warning"
		case "internet_restored", "person_arrived":
			return "text-bg-success"
		}
		return "text-bg-secondary"
	},
}

var eventLabels = map[string]string{
	"new_device":          "New device",
	"ip_changed":          "IP changed",
	"ip_conflict":         "IP conflict",
	"gateway_mac_changed": "Gateway MAC changed",
	"port_opened":         "Port opened",
	"port_closed":         "Port closed",
	"device_offline":      "Went offline",
	"device_online":       "Back online",
	"person_arrived":      "Arrived home",
	"person_left":         "Left home",
	"internet_outage":     "Internet outage",
	"internet_restored":   "Internet restored",
}

func loadTemplates(files fs.FS, reload bool) (*templates, error) {
	t := &templates{files: files, reload: reload, sets: map[string]*template.Template{}}
	pages, err := fs.Glob(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		if _, err := t.parse(name); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *templates) parse(name string) (*template.Template, error) {
	patterns := []string{"templates/layout.html", "templates/" + name + ".html"}
	if parts, _ := fs.Glob(t.files, "templates/partials/*.html"); len(parts) > 0 {
		patterns = append(patterns, "templates/partials/*.html")
	}
	set, err := template.New(name).Funcs(funcs).ParseFS(t.files, patterns...)
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", name, err)
	}
	t.mu.Lock()
	t.sets[name] = set
	t.mu.Unlock()
	return set, nil
}

func (t *templates) get(name string) (*template.Template, error) {
	if t.reload {
		return t.parse(name)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	set, ok := t.sets[name]
	if !ok {
		return nil, fmt.Errorf("no template %s", name)
	}
	return set, nil
}

// render executes the named page (or a block inside it) into w.
func (s *server) render(w http.ResponseWriter, r *http.Request, status int, name, block string, p page) {
	if sess := sessionFrom(r); sess != nil {
		p.User = sess.Username
		p.CSRF = sess.CSRF
		p.Unread, _ = s.Inv.UnreadCount(r.Context())
	}
	p.Version = s.Version
	if p.Flash == "" {
		p.Flash = flashes[r.URL.Query().Get("msg")]
	}
	set, err := s.tmpl.get(name)
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Only a page fetched with GET can be fetched again; a POST response
	// (a form with errors) must not refresh away the user's input.
	p.Live = p.User != "" && r.Method == http.MethodGet && status == http.StatusOK
	w.Header().Add("Vary", "X-Honet-Partial")
	if block == "layout" && isPartial(r) && p.User != "" {
		block = "content"
		w.Header().Set("X-Honet-Unread", strconv.Itoa(p.Unread))
	}
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, block, p); err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// flashes maps ?msg= codes to fixed messages, so no user text is reflected.
var flashes = map[string]string{
	"saved":         "Saved.",
	"queued":        "Scan queued.",
	"stopped":       "Port scan stopped.",
	"busy":          "A scan is already queued.",
	"pwchanged":     "Password changed. Please sign in again.",
	"registered":    "Admin account created. Please sign in.",
	"confirmed":     "Gateway MAC confirmed.",
	"deleted":       "Device forgotten.",
	"read":          "All events marked as read.",
	"personadded":   "Person added.",
	"persondeleted": "Person removed.",
	"linked":        "Device linked.",
	"unlinked":      "Device unlinked.",
	"testqueued":    "Speed test queued. It takes about 20 seconds; reload the page to see the result.",
	"testbusy":      "A speed test is already queued or running.",
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ", ")
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDur(d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}
