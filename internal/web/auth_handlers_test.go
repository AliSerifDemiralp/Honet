package web

import (
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	for _, p := range []string{"/setup", "/static/honet.css", "/nope"} {
		w := b.get(p)
		h := w.Header()
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s csp %q", p, csp)
		}
		if h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s headers %v", p, h)
		}
	}
}

func TestRedirectsToSetupWhenNoUser(t *testing.T) {
	e := newEnv(t)
	w := e.browser().get("/")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestStaticWithoutLogin(t *testing.T) {
	e := newEnv(t)
	w := e.browser().get("/static/vendor/bootstrap.min.css")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "max-age") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

func TestSetupThenLogin(t *testing.T) {
	e := newEnv(t)
	code, _ := e.auth.EnsureSetupCode(bg)
	b := e.browser()
	tok := b.csrf("/setup")
	w := b.post("/setup", url.Values{"csrf": {tok}, "code": {code}, "username": {"admin"}, "password": {testPW}, "confirm": {"different!!"}})
	if w.Code != 200 || !strings.Contains(body(w), "Passwords do not match") {
		t.Fatalf("mismatch: %d", w.Code)
	}
	w = b.post("/setup", url.Values{"csrf": {tok}, "code": {code}, "username": {"admin"}, "password": {testPW}, "confirm": {testPW}})
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Fatalf("setup: %d %s", w.Code, body(w))
	}
	tok = b.csrf("/login")
	w = b.post("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {testPW}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login %d", w.Code)
	}
	if w := b.get("/"); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("home %d %v", w.Code, w.Header())
	}
}

func TestSetupRejectsReuse(t *testing.T) {
	e := newEnv(t)
	code, _ := e.auth.EnsureSetupCode(bg)
	b := e.browser()
	tok := b.csrf("/setup")
	b.post("/setup", url.Values{"csrf": {tok}, "code": {code}, "username": {"admin"}, "password": {testPW}, "confirm": {testPW}})
	w := b.post("/setup", url.Values{"csrf": {tok}, "code": {code}, "username": {"mallory"}, "password": {testPW}, "confirm": {testPW}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("%d", w.Code)
	}
	if u, _ := e.auth.Username(bg); u != "admin" {
		t.Fatalf("username %q", u)
	}
}

func TestLoginFormNeedsCSRF(t *testing.T) {
	e := newEnv(t)
	e.loggedIn()
	b := e.browser()
	w := b.post("/login", url.Values{"username": {"admin"}, "password": {testPW}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("%d", w.Code)
	}
}

func TestCSRFRequired(t *testing.T) {
	e := newEnv(t)
	b := e.loggedIn()
	if w := b.post("/logout", url.Values{}); w.Code != http.StatusForbidden {
		t.Fatalf("%d", w.Code)
	}
	tok := b.pageCSRF()
	if w := b.post("/logout", url.Values{"csrf": {tok}}); w.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", w.Code)
	}
	if w := b.get("/"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("after logout %d", w.Code)
	}
}

func TestPartialNeeds401(t *testing.T) {
	e := newEnv(t)
	e.loggedIn()
	if w := e.browser().partial("/"); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
}

func failLogin(b *browser, n int, hdr ...string) string {
	var last string
	for i := 0; i < n; i++ {
		tok := b.csrf("/login")
		var h []string
		if len(hdr) > 0 {
			h = []string{"X-Forwarded-For", hdr[0] + "." + string(rune('1'+i))}
		}
		last = body(b.post("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {"wrong password"}}, h...))
	}
	return last
}

func TestLoginLockedMessage(t *testing.T) {
	e := newEnv(t)
	e.loggedIn()
	b := e.browser()
	if msg := failLogin(b, 1); !strings.Contains(msg, "Invalid username or password.") {
		t.Fatalf("%s", msg)
	}
	failLogin(b, 4)
	tok := b.csrf("/login")
	w := b.post("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {testPW}})
	if w.Code != 200 || !strings.Contains(body(w), "Too many failed attempts") {
		t.Fatalf("%d", w.Code)
	}
}

func TestXFFIgnoredWithoutTrustedProxy(t *testing.T) {
	e := newEnv(t)
	e.loggedIn()
	b := e.browser()
	failLogin(b, 5, "9.9.9")
	tok := b.csrf("/login")
	w := b.post("/login", url.Values{"csrf": {tok}, "username": {"admin"}, "password": {testPW}}, "X-Forwarded-For", "8.8.8.8")
	if !strings.Contains(body(w), "Too many failed attempts") {
		t.Fatal("spoofed X-Forwarded-For bypassed the lock")
	}
}

var (
	scriptRe = regexp.MustCompile(`<script(\s[^>]*)?>`)
)

func TestTemplatesHaveNoInlineScriptOrStyle(t *testing.T) {
	err := fs.WalkDir(assets, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := fs.ReadFile(assets, p)
		s := string(b)
		if strings.Contains(s, `style="`) || strings.Contains(s, "<style") {
			t.Errorf("%s has inline style", p)
		}
		for _, m := range scriptRe.FindAllString(s, -1) {
			if !strings.Contains(m, "src=") {
				t.Errorf("%s has inline script %q", p, m)
			}
		}
		if strings.Contains(s, " on") && regexp.MustCompile(`\son[a-z]+=`).MatchString(s) {
			t.Errorf("%s has an inline event handler", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
