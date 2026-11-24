package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/health"
	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/session"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

var bg = context.Background()

type env struct {
	t       *testing.T
	h       http.Handler
	st      *store.Store
	auth    *auth.Auth
	inv     *inventory.Inventory
	sched   *scheduler.Scheduler
	sess    *session.Manager
	hl      health.Health
	now     time.Time
	latErr  error
	hostNet string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, now: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	now := func() time.Time { return e.now }
	e.auth = auth.New(st, now)
	e.inv = inventory.New(st, now)
	e.sched = scheduler.New(func(context.Context, scheduler.Job) error { return nil }, func() scheduler.Intervals { return nil }, now)
	e.sess = session.NewManager(func() time.Duration { return 15 * time.Minute }, now)
	h, err := New(Deps{
		Store: st, Auth: e.auth, Sess: e.sess, Inv: e.inv, Sched: e.sched,
		Health: func() health.Health { return e.hl }, Version: "test", Now: now,
		Latency: func() error { return e.latErr },
		HostNet: func() string { return e.hostNet },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

// browser keeps cookies between requests.
type browser struct {
	e       *env
	cookies map[string]*http.Cookie
	remote  string
}

func (e *env) browser() *browser {
	return &browser{e: e, cookies: map[string]*http.Cookie{}, remote: "192.168.1.77:40000"}
}

func (b *browser) do(r *http.Request) *httptest.ResponseRecorder {
	r.RemoteAddr = b.remote
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.e.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

func (b *browser) get(path string) *httptest.ResponseRecorder {
	return b.do(httptest.NewRequest("GET", path, nil))
}

func (b *browser) post(path string, form url.Values, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return b.do(r)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrf fetches path and returns the csrf token embedded in its form.
func (b *browser) csrf(path string) string {
	w := b.get(path)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		b.e.t.Fatalf("no csrf token on %s (status %d)", path, w.Code)
	}
	return m[1]
}

func body(w *httptest.ResponseRecorder) string {
	b, _ := io.ReadAll(w.Result().Body)
	return string(b)
}

const testPW = "correct horse"

// loggedIn registers the admin and returns a logged-in browser.
func (e *env) loggedIn() *browser {
	e.t.Helper()
	code, err := e.auth.EnsureSetupCode(bg)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.auth.Register(bg, code, "admin", testPW); err != nil {
		e.t.Fatal(err)
	}
	b := e.browser()
	tok := b.csrf("/login")
	w := b.post("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {testPW}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		e.t.Fatalf("login: %d %s", w.Code, body(w))
	}
	return b
}

// pageCSRF returns the session csrf token from an authenticated page.
func (b *browser) pageCSRF() string { return b.csrf("/") }
