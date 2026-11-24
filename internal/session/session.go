// Package session keeps login sessions in memory. A restart logs everyone out.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// CookieName is the session cookie.
const CookieName = "honet_session"

// Session is one logged-in browser.
type Session struct {
	ID       string
	Username string
	CSRF     string
	LastSeen time.Time
}

// Manager stores sessions.
type Manager struct {
	idle func() time.Duration
	now  func() time.Time

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager returns a manager whose sessions expire after idle() of inactivity.
func NewManager(idle func() time.Duration, now func() time.Time) *Manager {
	return &Manager{idle: idle, now: now, sessions: map[string]*Session{}}
}

// Token returns a 32-byte random URL-safe token.
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create starts a session and sets its cookie.
func (m *Manager) Create(w http.ResponseWriter, username string, secure bool) *Session {
	now := m.now()
	s := &Session{ID: Token(), Username: username, CSRF: Token(), LastSeen: now}
	idle := m.idle()
	m.mu.Lock()
	for id, old := range m.sessions { // drop sessions that expired unseen
		if now.Sub(old.LastSeen) > idle {
			delete(m.sessions, id)
		}
	}
	m.sessions[s.ID] = s
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: s.ID, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
	return s
}

// Get returns the request's live session, refreshing its activity time.
func (m *Manager) Get(r *http.Request) (*Session, bool) { return m.lookup(r, true) }

// Peek returns the request's live session without counting the request as
// activity, so automatic background refreshes cannot keep a session alive.
func (m *Manager) Peek(r *http.Request) (*Session, bool) { return m.lookup(r, false) }

func (m *Manager) lookup(r *http.Request, touch bool) (*Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[c.Value]
	if !ok {
		return nil, false
	}
	if now.Sub(s.LastSeen) > m.idle() {
		delete(m.sessions, s.ID)
		return nil, false
	}
	if touch {
		s.LastSeen = now
	}
	cp := *s
	return &cp, true
}

// Destroy ends the request's session and clears its cookie.
func (m *Manager) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		m.mu.Lock()
		delete(m.sessions, c.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// DestroyAll ends every session (after a password change).
func (m *Manager) DestroyAll() {
	m.mu.Lock()
	m.sessions = map[string]*Session{}
	m.mu.Unlock()
}
