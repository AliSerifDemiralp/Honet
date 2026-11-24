// Package auth manages the single admin account, first-run setup codes and
// login throttling.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// Limits.
const (
	BcryptCost     = 10
	MinPasswordLen = 10
	maxFailures    = 5
	lockWindow     = 10 * time.Minute
)

// Errors.
var (
	ErrBadSetupCode   = errors.New("invalid setup code")
	ErrWeakPassword   = errors.New("password must be at least 10 characters")
	ErrBadUsername    = errors.New("username must be 1-32 characters")
	ErrUserExists     = errors.New("an admin account already exists")
	ErrNoUser         = errors.New("no admin account yet")
	ErrBadCredentials = errors.New("invalid username or password")
	ErrLocked         = errors.New("too many failed attempts")
)

const setupKey = "auth.setup_code_sha256"

// Attempt is one login attempt.
type Attempt struct {
	IP      string
	At      time.Time
	Success bool
}

// Auth is the authentication service.
type Auth struct {
	st  *store.Store
	now func() time.Time

	// loginMu serializes Login so concurrent requests cannot all pass the
	// failure-count check before any of them records its attempt. It also
	// keeps parallel bcrypt from saturating a single-core Pi.
	loginMu sync.Mutex
}

// New returns an Auth over st.
func New(st *store.Store, now func() time.Time) *Auth { return &Auth{st: st, now: now} }

var (
	dummyOnce sync.Once
	dummyHash []byte
)

// dummy returns a hash to compare against when the username is wrong, so
// both paths take the same time.
func dummy() []byte {
	dummyOnce.Do(func() {
		dummyHash, _ = bcrypt.GenerateFromPassword([]byte("honet-dummy-password"), BcryptCost)
	})
	return dummyHash
}

// HasUser reports whether the admin account exists.
func (a *Auth) HasUser(ctx context.Context) (bool, error) {
	var n int
	err := a.st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n > 0, err
}

// Username returns the admin username.
func (a *Auth) Username(ctx context.Context) (string, error) {
	var u string
	err := a.st.DB.QueryRowContext(ctx, `SELECT username FROM users WHERE id = 1`).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoUser
	}
	return u, err
}

func normalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
}

func hashCode(s string) string {
	h := sha256.Sum256([]byte(normalizeCode(s)))
	return hex.EncodeToString(h[:])
}

// EnsureSetupCode creates a new one-time setup code (invalidating any
// previous one) while no admin exists. It returns "" once an admin exists.
func (a *Auth) EnsureSetupCode(ctx context.Context) (string, error) {
	has, err := a.HasUser(ctx)
	if err != nil || has {
		return "", err
	}
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if err := a.st.SetKV(ctx, setupKey, hashCode(raw)); err != nil {
		return "", err
	}
	return raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16], nil
}

func checkPassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return ErrWeakPassword
	}
	if len(pw) > 72 { // bcrypt limit
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// Register creates the admin account using the current setup code.
func (a *Auth) Register(ctx context.Context, setupCode, username, password string) error {
	if has, err := a.HasUser(ctx); err != nil {
		return err
	} else if has {
		return ErrUserExists
	}
	want, ok, err := a.st.GetKV(ctx, setupKey)
	if err != nil {
		return err
	}
	if !ok || subtle.ConstantTimeCompare([]byte(want), []byte(hashCode(setupCode))) != 1 {
		return ErrBadSetupCode
	}
	username = netutil.CleanText(username, 64)
	if username == "" || utf8.RuneCountInString(username) > 32 {
		return ErrBadUsername
	}
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	return a.st.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users(id, username, hash, created_at) VALUES (1, ?, ?, ?)`,
			username, string(hash), store.FormatTime(a.now())); err != nil {
			return ErrUserExists
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM kv WHERE key = ?`, setupKey)
		return err
	})
}

func (a *Auth) failures(ctx context.Context, ip string) (int, error) {
	since := store.FormatTime(a.now().Add(-lockWindow))
	var n int
	var err error
	if ip == "" {
		err = a.st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND at >= ?`, since).Scan(&n)
	} else {
		err = a.st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND at >= ?`, ip, since).Scan(&n)
	}
	return n, err
}

// Login checks credentials for a client IP and records the attempt.
func (a *Auth) Login(ctx context.Context, ip, username, password string) error {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	n, err := a.failures(ctx, ip)
	if err != nil {
		return err
	}
	if n >= maxFailures {
		return ErrLocked
	}
	var user, hash string
	err = a.st.DB.QueryRowContext(ctx, `SELECT username, hash FROM users WHERE id = 1`).Scan(&user, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	ok := false
	if err == nil && subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1 {
		ok = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	} else {
		_ = bcrypt.CompareHashAndPassword(dummy(), []byte(password))
	}
	now := store.FormatTime(a.now())
	if _, err := a.st.DB.ExecContext(ctx, `INSERT INTO login_attempts(ip, at, success) VALUES (?, ?, ?)`, ip, now, ok); err != nil {
		return err
	}
	if !ok {
		return ErrBadCredentials
	}
	_, err = a.st.DB.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = 1`, now)
	return err
}

// Delay is how long to wait before checking a login, growing with the
// number of failures from all addresses in the last 10 minutes.
func (a *Auth) Delay(ctx context.Context) (time.Duration, error) {
	f, err := a.failures(ctx, "")
	if err != nil || f < 20 {
		return 0, err
	}
	shift := (f - 20) / 20
	if shift > 3 {
		shift = 3
	}
	return time.Second << shift, nil
}

func (a *Auth) setHash(ctx context.Context, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	res, err := a.st.DB.ExecContext(ctx, `UPDATE users SET hash = ? WHERE id = 1`, string(hash))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoUser
	}
	return nil
}

// ChangePassword replaces the password after checking the old one. Wrong
// guesses count as failed sign-ins from ip, so a stolen session cannot be
// used to guess the password without hitting the lockout.
func (a *Auth) ChangePassword(ctx context.Context, ip, oldPw, newPw string) error {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	n, err := a.failures(ctx, ip)
	if err != nil {
		return err
	}
	if n >= maxFailures {
		return ErrLocked
	}
	var hash string
	if err := a.st.DB.QueryRowContext(ctx, `SELECT hash FROM users WHERE id = 1`).Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoUser
		}
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPw)) != nil {
		if _, err := a.st.DB.ExecContext(ctx, `INSERT INTO login_attempts(ip, at, success) VALUES (?, ?, 0)`,
			ip, store.FormatTime(a.now())); err != nil {
			return err
		}
		return ErrBadCredentials
	}
	return a.setHash(ctx, newPw)
}

// ResetPassword sets a new password without the old one (CLI use only).
func (a *Auth) ResetPassword(ctx context.Context, newPw string) error {
	if has, err := a.HasUser(ctx); err != nil {
		return err
	} else if !has {
		return ErrNoUser
	}
	return a.setHash(ctx, newPw)
}

// LoginHistory returns the newest attempts.
func (a *Auth) LoginHistory(ctx context.Context, limit int) ([]Attempt, error) {
	rows, err := a.st.DB.QueryContext(ctx, `SELECT ip, at, success FROM login_attempts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var at Attempt
		var ts string
		if err := rows.Scan(&at.IP, &ts, &at.Success); err != nil {
			return nil, err
		}
		at.At, _ = store.ParseTime(ts)
		out = append(out, at)
	}
	return out, rows.Err()
}

// PruneAttempts keeps at most the newest 1000 attempts from the last 30 days.
func (a *Auth) PruneAttempts(ctx context.Context) error {
	if a.now().Year() >= 2025 {
		if _, err := a.st.DB.ExecContext(ctx, `DELETE FROM login_attempts WHERE at < ?`,
			store.FormatTime(a.now().Add(-30*24*time.Hour))); err != nil {
			return err
		}
	}
	_, err := a.st.DB.ExecContext(ctx, `DELETE FROM login_attempts WHERE id NOT IN (SELECT id FROM login_attempts ORDER BY id DESC LIMIT 1000)`)
	return err
}

// ClientIP returns the client address. X-Forwarded-For is honoured only when
// the direct peer is a trusted proxy; then the right-most untrusted entry wins.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !inAny(peer.Unmap(), trusted) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		if !inAny(ip.Unmap(), trusted) {
			return ip.String()
		}
	}
	return host
}

func inAny(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
