package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (b *browser) partial(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("X-Honet-Partial", "1")
	return b.do(r)
}

func TestPartialRendersContentOnly(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	for _, p := range []string{"/", "/devices", "/people", "/internet", "/events"} {
		w := b.partial(p)
		s := body(w)
		if w.Code != 200 || strings.Contains(s, "<html") || strings.Contains(s, "<nav class=\"navbar") || !strings.Contains(s, "<h1") {
			t.Fatalf("%s: %d %.200s", p, w.Code, s)
		}
		if w.Header().Get("X-Honet-Unread") == "" || !strings.Contains(w.Header().Get("Vary"), "X-Honet-Partial") {
			t.Fatalf("%s: headers %v", p, w.Header())
		}
	}
	if s := body(b.get("/")); !strings.Contains(s, "<html") {
		t.Fatal("full page broken")
	}
}

func TestPartialDoesNotExtendSession(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	e.now = e.now.Add(14 * time.Minute)
	if w := b.partial("/"); w.Code != 200 {
		t.Fatalf("partial %d", w.Code)
	}
	e.now = e.now.Add(2 * time.Minute)
	if w := b.partial("/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired partial %d", w.Code)
	}
	if w := b.get("/"); w.Code != http.StatusSeeOther {
		t.Fatalf("background refresh kept the session alive: %d", w.Code)
	}
}

func TestLayoutLiveHooks(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	s := body(b.get("/devices"))
	for _, want := range []string{`<body data-live="15">`, `<main id="main"`, `id="nav-events"`, `id="live-status"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(s, "data-refresh-url") {
		t.Error("old per-table refresh still present")
	}
	if strings.Contains(body(e.browser().get("/login")), "data-live") {
		t.Error("login page refreshes itself")
	}
}

func TestErrorPageNotLive(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	ids := seed(t, e, h("192.168.1.9", "AA:00:00:00:00:09"), h("192.168.1.10", "AA:00:00:00:00:10"))
	tok := b.pageCSRF()
	w := b.post(fmt.Sprintf("/devices/%d/scan", ids[0]), url.Values{"csrf": {tok}, "profile": {"custom"}, "custom": {"0"}})
	if w.Code != http.StatusBadRequest || strings.Contains(body(w), "data-live") {
		t.Fatalf("%d", w.Code)
	}
}
