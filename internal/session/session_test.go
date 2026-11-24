package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func cookieReq(c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	return r
}

func create(t *testing.T, m *Manager, secure bool) (*Session, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	s := m.Create(w, "admin", secure)
	cs := w.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies %v", cs)
	}
	return s, cs[0]
}

func TestSessionIdleExpiry(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	m := NewManager(func() time.Duration { return 15 * time.Minute }, c.now)
	s, ck := create(t, m, false)
	if len(s.ID) < 40 || len(s.CSRF) < 40 || s.ID == s.CSRF {
		t.Fatalf("tokens %q %q", s.ID, s.CSRF)
	}
	c.t = c.t.Add(14 * time.Minute)
	if got, ok := m.Get(cookieReq(ck)); !ok || got.Username != "admin" {
		t.Fatal("session lost before idle timeout")
	}
	c.t = c.t.Add(14 * time.Minute)
	if _, ok := m.Get(cookieReq(ck)); !ok {
		t.Fatal("activity should extend the session")
	}
	c.t = c.t.Add(16 * time.Minute)
	if _, ok := m.Get(cookieReq(ck)); ok {
		t.Fatal("session survived idle timeout")
	}
	if _, ok := m.Get(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("no cookie accepted")
	}
}

func TestCookieFlags(t *testing.T) {
	m := NewManager(func() time.Duration { return time.Hour }, time.Now)
	_, ck := create(t, m, true)
	if ck.Name != CookieName || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || !ck.Secure || ck.Path != "/" {
		t.Fatalf("%+v", ck)
	}
	_, ck = create(t, m, false)
	if ck.Secure {
		t.Fatal("secure on plain http")
	}
}

func TestDestroy(t *testing.T) {
	m := NewManager(func() time.Duration { return time.Hour }, time.Now)
	_, ck := create(t, m, false)
	_, ck2 := create(t, m, false)
	w := httptest.NewRecorder()
	m.Destroy(w, cookieReq(ck))
	if _, ok := m.Get(cookieReq(ck)); ok {
		t.Fatal("destroyed session valid")
	}
	if _, ok := m.Get(cookieReq(ck2)); !ok {
		t.Fatal("other session destroyed")
	}
	m.DestroyAll()
	if _, ok := m.Get(cookieReq(ck2)); ok {
		t.Fatal("DestroyAll left a session")
	}
}

func TestCreateSweepsExpiredSessions(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	m := NewManager(func() time.Duration { return 15 * time.Minute }, c.now)
	create(t, m, false)
	create(t, m, false)
	c.t = c.t.Add(16 * time.Minute)
	create(t, m, false)
	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d sessions kept; expired ones should be swept", n)
	}
}

func TestPeekDoesNotExtend(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	m := NewManager(func() time.Duration { return 15 * time.Minute }, c.now)
	_, ck := create(t, m, false)
	c.t = c.t.Add(14 * time.Minute)
	if s, ok := m.Peek(cookieReq(ck)); !ok || s.Username != "admin" {
		t.Fatal("peek lost a live session")
	}
	c.t = c.t.Add(2 * time.Minute)
	if _, ok := m.Peek(cookieReq(ck)); ok {
		t.Fatal("peek extended the session")
	}
	if _, ok := m.Get(cookieReq(ck)); ok {
		t.Fatal("session survived idle timeout after peeks")
	}
}
