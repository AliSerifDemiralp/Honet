package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

func (s *server) settingsRoutes() {
	s.mux.HandleFunc("GET /settings", s.settingsPage)
	s.mux.HandleFunc("POST /settings", s.settingsSubmit)
	s.mux.HandleFunc("POST /settings/password", s.passwordSubmit)
	s.mux.HandleFunc("GET /events", s.eventsPage)
	s.mux.HandleFunc("POST /events/read", s.eventsRead)
	s.mux.HandleFunc("GET /export/devices.csv", s.exportCSV)
	s.mux.HandleFunc("GET /export/devices.json", s.exportJSON)
	s.mux.HandleFunc("GET /report", s.report)
}

// settingsFields holds form values as strings so invalid input is redisplayed.
type settingsFields struct {
	CIDR, Interface, Discovery, Ports, Session, Watch, Proxies string
	Speed, Latency, Targets, PiLimit                           string
}

type settingsData struct {
	HostNet  string
	Form     settingsFields
	Username string
	History  []auth.Attempt
}

func minutes(d time.Duration) string { return strconv.Itoa(int(d / time.Minute)) }

func formFromSettings(v store.Settings) settingsFields {
	px := make([]string, len(v.TrustedProxies))
	for i, p := range v.TrustedProxies {
		px[i] = p.String()
	}
	return settingsFields{CIDR: v.CIDR, Interface: v.Interface, Discovery: minutes(v.DiscoveryInterval),
		Ports: minutes(v.PortInterval), Session: minutes(v.SessionIdle), Watch: minutes(v.WatchAfter),
		Proxies: strings.Join(px, ", "), Speed: minutes(v.SpeedInterval), Latency: minutes(v.LatencyInterval),
		Targets: strings.Join(v.LatencyTargets, ", "), PiLimit: strconv.FormatFloat(v.PiLimitMbps, 'f', -1, 64)}
}

// maxLatencyTargets bounds the pings sent every minute.
const maxLatencyTargets = 4

func parseMinutes(label, raw string, min, max int, allowZero bool) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 || n > max || (n < min && !(allowZero && n == 0)) {
		if allowZero {
			return 0, fmt.Errorf("%s must be 0 (off) or between %d and %d minutes", label, min, max)
		}
		return 0, fmt.Errorf("%s must be between %d and %d minutes", label, min, max)
	}
	return time.Duration(n) * time.Minute, nil
}

func (f settingsFields) parse() (store.Settings, error) {
	v := store.DefaultSettings()
	var err error
	if c := strings.TrimSpace(f.CIDR); c != "" {
		p, err := netutil.ValidateScanCIDR(c)
		if err != nil {
			return v, fmt.Errorf("Scan range: %w", err)
		}
		v.CIDR = p.String()
	}
	v.Interface = netutil.CleanText(f.Interface, 15)
	if v.DiscoveryInterval, err = parseMinutes("Discovery interval", f.Discovery, 1, 1440, true); err != nil {
		return v, err
	}
	if v.PortInterval, err = parseMinutes("Port scan interval", f.Ports, 1, 10080, true); err != nil {
		return v, err
	}
	if v.SessionIdle, err = parseMinutes("Session timeout", f.Session, 5, 240, false); err != nil {
		return v, err
	}
	if v.WatchAfter, err = parseMinutes("Offline alert delay", f.Watch, 1, 10080, false); err != nil {
		return v, err
	}
	for _, raw := range strings.Split(f.Proxies, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return v, fmt.Errorf("Trusted proxy %q is not an IP address or CIDR", raw)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		v.TrustedProxies = append(v.TrustedProxies, p.Masked())
	}
	if v.SpeedInterval, err = parseMinutes("Speed test interval", f.Speed, 60, 1440, true); err != nil {
		return v, err
	}
	if v.LatencyInterval, err = parseMinutes("Latency interval", f.Latency, 1, 60, true); err != nil {
		return v, err
	}
	v.LatencyTargets = nil
	for _, raw := range strings.Split(f.Targets, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return v, fmt.Errorf("Latency target %q is not an IP address", raw)
		}
		v.LatencyTargets = append(v.LatencyTargets, a.String())
	}
	if len(v.LatencyTargets) > maxLatencyTargets {
		return v, fmt.Errorf("At most %d latency targets", maxLatencyTargets)
	}
	lim, err := strconv.ParseFloat(strings.TrimSpace(f.PiLimit), 64)
	if err != nil || lim < 1 || lim > 1000 {
		return v, errors.New("Pi speed limit must be between 1 and 1000 Mbps")
	}
	v.PiLimitMbps = lim
	return v, nil
}

func (s *server) renderSettings(w http.ResponseWriter, r *http.Request, status int, f settingsFields, errMsg string) {
	user, _ := s.Auth.Username(r.Context())
	hist, err := s.Auth.LoginHistory(r.Context(), 50)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, status, "settings", "layout", page{Title: "Settings", Nav: "settings", Error: errMsg,
		Data: settingsData{Form: f, Username: user, History: hist, HostNet: s.hostNet()}})
}

func (s *server) hostNet() string {
	if s.HostNet == nil {
		return ""
	}
	return s.HostNet()
}

func (s *server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, 200, formFromSettings(s.settings(r.Context())), "")
}

func (s *server) settingsSubmit(w http.ResponseWriter, r *http.Request) {
	f := settingsFields{CIDR: r.PostFormValue("cidr"), Interface: r.PostFormValue("interface"),
		Discovery: r.PostFormValue("discovery"), Ports: r.PostFormValue("ports"), Session: r.PostFormValue("session"),
		Watch: r.PostFormValue("watch"), Proxies: r.PostFormValue("proxies"), Speed: r.PostFormValue("speed"),
		Latency: r.PostFormValue("latency"), Targets: r.PostFormValue("targets"), PiLimit: r.PostFormValue("pilimit")}
	v, err := f.parse()
	if err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, f, err.Error())
		return
	}
	if err := s.Store.SaveSettings(r.Context(), v); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/settings?msg=saved", http.StatusSeeOther)
}

func (s *server) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	form := formFromSettings(s.settings(r.Context()))
	if r.PostFormValue("new") != r.PostFormValue("confirm") {
		s.renderSettings(w, r, http.StatusBadRequest, form, "New passwords do not match.")
		return
	}
	ip := auth.ClientIP(r, s.settings(r.Context()).TrustedProxies)
	err := s.Auth.ChangePassword(r.Context(), ip, r.PostFormValue("old"), r.PostFormValue("new"))
	switch {
	case errors.Is(err, auth.ErrLocked):
		s.renderSettings(w, r, http.StatusTooManyRequests, form, "Too many wrong passwords. Try again in 10 minutes.")
		return
	case errors.Is(err, auth.ErrBadCredentials):
		s.renderSettings(w, r, http.StatusBadRequest, form, "Current password is wrong.")
		return
	case errors.Is(err, auth.ErrWeakPassword):
		s.renderSettings(w, r, http.StatusBadRequest, form, "New password must be at least 10 characters.")
		return
	case err != nil:
		s.renderSettings(w, r, http.StatusBadRequest, form, err.Error())
		return
	}
	s.Sess.DestroyAll()
	s.Sess.Destroy(w, r)
	http.Redirect(w, r, "/login?msg=pwchanged", http.StatusSeeOther)
}
