package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/store"
)

func settingsForm(tok string, over map[string]string) url.Values {
	v := url.Values{"csrf": {tok}, "cidr": {""}, "interface": {""}, "discovery": {"5"}, "ports": {"60"},
		"session": {"15"}, "watch": {"15"}, "proxies": {""},
		"speed": {"180"}, "latency": {"1"}, "targets": {"1.1.1.1, 8.8.8.8"}, "pilimit": {"25"}}
	for k, x := range over {
		v.Set(k, x)
	}
	return v
}

func TestSettingsRejectsPublicCIDR(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	w := b.post("/settings", settingsForm(tok, map[string]string{"cidr": "8.8.8.0/24"}))
	if w.Code != http.StatusBadRequest || !strings.Contains(body(w), "private") {
		t.Fatalf("%d", w.Code)
	}
	if s, _ := e.st.LoadSettings(bg); s.CIDR != "" {
		t.Fatalf("saved %q", s.CIDR)
	}
}

func TestSettingsSaves(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	w := b.post("/settings", settingsForm(tok, map[string]string{"cidr": "192.168.1.0/24", "discovery": "2", "ports": "0", "proxies": "192.168.1.2, 10.0.0.0/8"}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, body(w))
	}
	s, _ := e.st.LoadSettings(bg)
	if s.CIDR != "192.168.1.0/24" || s.DiscoveryInterval != 2*time.Minute || s.PortInterval != 0 || len(s.TrustedProxies) != 2 || s.TrustedProxies[0].String() != "192.168.1.2/32" {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(body(b.get("/settings")), "192.168.1.0/24") {
		t.Fatal("form does not show saved value")
	}
}

func TestIntervalValidation(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	for _, bad := range []map[string]string{{"discovery": "-1"}, {"ports": "abc"}, {"session": "1"}, {"watch": "0"}, {"proxies": "nonsense"}} {
		if w := b.post("/settings", settingsForm(tok, bad)); w.Code != http.StatusBadRequest {
			t.Errorf("%v accepted (%d)", bad, w.Code)
		}
	}
	for _, good := range []map[string]string{{"discovery": "0"}, {"discovery": "1"}} {
		if w := b.post("/settings", settingsForm(tok, good)); w.Code != http.StatusSeeOther {
			t.Errorf("%v rejected (%d)", good, w.Code)
		}
	}
}

func TestPasswordChangeLogsOutAll(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	w := b.post("/settings/password", url.Values{"csrf": {tok}, "old": {"wrong one!!"}, "new": {"brand new pass"}, "confirm": {"brand new pass"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong old accepted: %d", w.Code)
	}
	w = b.post("/settings/password", url.Values{"csrf": {tok}, "old": {testPW}, "new": {"brand new pass"}, "confirm": {"brand new pass"}})
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Fatalf("%d", w.Code)
	}
	if w := b.get("/"); w.Code != http.StatusSeeOther {
		t.Fatal("session survived password change")
	}
}

func TestLoginHistoryShown(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	if s := body(b.get("/settings")); !strings.Contains(s, "192.168.1.77") {
		t.Fatal("login history missing")
	}
}

func TestExportHasNoSecrets(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	for _, p := range []string{"/export/devices.csv", "/export/devices.json"} {
		w := b.get(p)
		s := body(w)
		if w.Code != 200 || !strings.Contains(s, "192.168.1.9") || strings.Contains(s, "$2a$") || strings.Contains(s, "admin") || strings.Contains(s, "192.168.1.77") {
			t.Fatalf("%s: %d %s", p, w.Code, s)
		}
		if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
			t.Fatalf("%s not an attachment", p)
		}
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(body(b.get("/export/devices.json"))), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
}

func TestCSVFormulaEscaped(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	e.inv.Identify(bg, ids[0], "=cmd()", "", "", true)
	if s := body(b.get("/export/devices.csv")); !strings.Contains(s, "'=cmd()") {
		t.Fatalf("%s", s)
	}
}

func TestEventsMarkRead(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	s := body(b.get("/events"))
	if !strings.Contains(s, "New device") || !strings.Contains(s, "text-bg-danger") {
		t.Fatal("events page / unread badge")
	}
	tok := b.pageCSRF()
	b.post("/events/read", url.Values{"csrf": {tok}})
	if n, _ := e.inv.UnreadCount(bg); n != 0 {
		t.Fatalf("unread %d", n)
	}
}

func TestReportPage(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"))
	s := body(b.get("/report"))
	if !strings.Contains(s, "192.168.1.9") || !strings.Contains(s, "data-print") {
		t.Fatal("report")
	}
}

func TestReportCountsWholeWeek(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tx, err := e.st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1200; i++ {
		at := store.FormatTime(e.now.Add(-time.Duration(i) * time.Minute))
		if _, err := tx.Exec(`INSERT INTO events(at, kind, detail) VALUES (?, 'port_closed', '')`, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if s := body(b.get("/report")); !strings.Contains(s, "Port closed: 1200") {
		t.Fatal("report does not count every event of the week")
	}
}

func TestPasswordChangeGuessingLocks(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	tok := b.pageCSRF()
	form := func(old string) url.Values {
		return url.Values{"csrf": {tok}, "old": {old}, "new": {"another password"}, "confirm": {"another password"}}
	}
	for i := 0; i < 5; i++ {
		if w := b.post("/settings/password", form("wrong guess")); w.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := b.post("/settings/password", form(testPW)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after 5 wrong guesses: %d", w.Code)
	}
}

func TestSettingsShowsHostNetwork(t *testing.T) {
	e := newEnv(t)
	e.hostNet = "172.17.0.2/16 on eth0"
	if page := body(e.loggedIn().get("/settings")); !strings.Contains(page, "This host: 172.17.0.2/16 on eth0") {
		t.Fatal(page)
	}
}
