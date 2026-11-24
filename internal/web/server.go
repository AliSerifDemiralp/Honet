// Package web serves honet's HTML interface.
package web

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/health"
	"github.com/AliSerifDemiralp/honet/internal/inventory"
	"github.com/AliSerifDemiralp/honet/internal/scheduler"
	"github.com/AliSerifDemiralp/honet/internal/session"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// Deps are the services the web layer uses.
type Deps struct {
	Store     *store.Store
	Auth      *auth.Auth
	Sess      *session.Manager
	Inv       *inventory.Inventory
	Sched     *scheduler.Scheduler
	Health    func() health.Health
	Latency   func() error  // last latency monitor error, nil if it works
	HostNet   func() string // "192.168.1.10/24 on wlan0", "" if unknown
	Secure    bool
	Version   string
	DevAssets string
	Now       func() time.Time
}

type server struct {
	Deps
	files fs.FS
	tmpl  *templates
	mux   *http.ServeMux
}

// New builds the HTTP handler.
func New(d Deps) (http.Handler, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	files := fs.FS(assets)
	if d.DevAssets != "" {
		files = os.DirFS(d.DevAssets)
	}
	t, err := loadTemplates(files, d.DevAssets != "")
	if err != nil {
		return nil, err
	}
	s := &server{Deps: d, files: files, tmpl: t, mux: http.NewServeMux()}
	s.routes()
	return s.securityHeaders(s.gate(s.mux)), nil
}

func (s *server) routes() {
	static, _ := fs.Sub(s.files, "static")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	s.mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	}))
	s.mux.HandleFunc("GET /setup", s.setupPage)
	s.mux.HandleFunc("POST /setup", s.setupSubmit)
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginSubmit)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.networkRoutes()
	s.settingsRoutes()
	s.peopleRoutes()
	s.internetRoutes()
}

func (s *server) serverError(w http.ResponseWriter, err error) {
	log.Printf("web: %v", err)
	http.Error(w, "Internal error; see the honet log.", http.StatusInternalServerError)
}

func (s *server) settings(ctx context.Context) store.Settings {
	v, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return store.DefaultSettings()
	}
	return v
}
