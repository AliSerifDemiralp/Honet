package web

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/AliSerifDemiralp/honet/internal/session"
)

const csp = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

const maxForm = 64 << 10

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if s.Secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxForm)
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

func sessionFrom(r *http.Request) *session.Session {
	s, _ := r.Context().Value(ctxKey{}).(*session.Session)
	return s
}

// gate enforces first-run setup, login and CSRF for everything but static files.
func (s *server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		hasUser, err := s.Auth.HasUser(r.Context())
		if err != nil {
			s.serverError(w, err)
			return
		}
		switch {
		case !hasUser && p != "/setup":
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		case !hasUser:
			next.ServeHTTP(w, r)
			return
		case p == "/setup":
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		case p == "/login":
			next.ServeHTTP(w, r)
			return
		}
		background := r.Method == http.MethodGet && isPartial(r)
		get := s.Sess.Get
		if background {
			get = s.Sess.Peek
		}
		sess, ok := get(r)
		if !ok {
			if background {
				http.Error(w, "session expired", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !tokenEqual(r.PostFormValue("csrf"), sess.CSRF) {
			http.Error(w, "Invalid form token. Reload the page and try again.", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

func tokenEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const preCSRFCookie = "honet_csrf"

// preAuthToken returns the double-submit token for login/setup forms,
// setting its cookie when missing.
func (s *server) preAuthToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(preCSRFCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := session.Token()
	http.SetCookie(w, &http.Cookie{Name: preCSRFCookie, Value: tok, Path: "/", HttpOnly: true,
		Secure: s.Secure, SameSite: http.SameSiteStrictMode})
	return tok
}

func (s *server) checkPreAuth(r *http.Request) bool {
	c, err := r.Cookie(preCSRFCookie)
	return err == nil && tokenEqual(r.PostFormValue("csrf"), c.Value)
}

// isPartial reports whether the request is a background refresh that wants
// only the page content.
func isPartial(r *http.Request) bool { return r.Header.Get("X-Honet-Partial") == "1" }
