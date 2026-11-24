package web

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
)

type authForm struct {
	Token    string
	Username string
}

func (s *server) setupPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, 200, "setup", "layout", page{Title: "Setup", Data: authForm{Token: s.preAuthToken(w, r)}})
}

func (s *server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(r) {
		http.Error(w, "Invalid form token. Reload the page and try again.", http.StatusForbidden)
		return
	}
	user := r.PostFormValue("username")
	fail := func(msg string) {
		s.render(w, r, 200, "setup", "layout", page{Title: "Setup", Error: msg,
			Data: authForm{Token: s.preAuthToken(w, r), Username: user}})
	}
	if r.PostFormValue("password") != r.PostFormValue("confirm") {
		fail("Passwords do not match.")
		return
	}
	err := s.Auth.Register(r.Context(), r.PostFormValue("code"), user, r.PostFormValue("password"))
	switch {
	case errors.Is(err, auth.ErrUserExists):
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.Is(err, auth.ErrBadSetupCode):
		fail("Wrong setup code. Find the current code in the honet log (journalctl -u honet).")
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrBadUsername):
		fail(err.Error() + ".")
	case err != nil:
		log.Printf("web: setup: %v", err)
		fail("Could not create the account; see the honet log.")
	default:
		http.Redirect(w, r, "/login?msg=registered", http.StatusSeeOther)
	}
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Sess.Get(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, 200, "login", "layout", page{Title: "Sign in", Data: authForm{Token: s.preAuthToken(w, r)}})
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.checkPreAuth(r) {
		http.Error(w, "Invalid form token. Reload the page and try again.", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	if d, err := s.Auth.Delay(ctx); err == nil && d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return
		}
	}
	user := r.PostFormValue("username")
	ip := auth.ClientIP(r, s.settings(ctx).TrustedProxies)
	err := s.Auth.Login(ctx, ip, user, r.PostFormValue("password"))
	if err != nil {
		msg := "Invalid username or password."
		if errors.Is(err, auth.ErrLocked) {
			msg = "Too many failed attempts. Try again in 10 minutes."
		} else if !errors.Is(err, auth.ErrBadCredentials) {
			s.serverError(w, err)
			return
		}
		s.render(w, r, 200, "login", "layout", page{Title: "Sign in", Error: msg,
			Data: authForm{Token: s.preAuthToken(w, r), Username: user}})
		return
	}
	s.Sess.Create(w, user, s.Secure)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.Sess.Destroy(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
