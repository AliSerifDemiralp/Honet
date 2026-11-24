package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/store"
)

var ctx = context.Background()

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newAuth(t *testing.T) (*Auth, *clock, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	return New(st, c.now), c, st
}

const pw = "correct horse"

func registered(t *testing.T) (*Auth, *clock, *store.Store) {
	a, c, st := newAuth(t)
	code, err := a.EnsureSetupCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Register(ctx, code, "admin", pw); err != nil {
		t.Fatal(err)
	}
	return a, c, st
}

func TestRegisterFlow(t *testing.T) {
	a, _, st := newAuth(t)
	code, err := a.EnsureSetupCode(ctx)
	if err != nil || len(code) != 19 || strings.Count(code, "-") != 3 {
		t.Fatalf("code %q %v", code, err)
	}
	if err := a.Register(ctx, "AAAA-BBBB-CCCC-DDDD", "admin", pw); !errors.Is(err, ErrBadSetupCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := a.Register(ctx, code, "admin", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak: %v", err)
	}
	if err := a.Register(ctx, code, "", pw); !errors.Is(err, ErrBadUsername) {
		t.Fatalf("empty user: %v", err)
	}
	sloppy := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	if err := a.Register(ctx, sloppy, "admin", pw); err != nil {
		t.Fatal(err)
	}
	if err := a.Register(ctx, code, "mallory", pw); !errors.Is(err, ErrUserExists) {
		t.Fatalf("reuse: %v", err)
	}
	if u, _ := a.Username(ctx); u != "admin" {
		t.Fatalf("user %q", u)
	}
	if c, _ := a.EnsureSetupCode(ctx); c != "" {
		t.Fatal("setup code after registration")
	}
	var hash string
	st.DB.QueryRow(`SELECT hash FROM users`).Scan(&hash)
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Fatalf("hash %q", hash)
	}
}

func TestNewSetupCodeInvalidatesOld(t *testing.T) {
	a, _, _ := newAuth(t)
	old, _ := a.EnsureSetupCode(ctx)
	a.EnsureSetupCode(ctx)
	if err := a.Register(ctx, old, "admin", pw); !errors.Is(err, ErrBadSetupCode) {
		t.Fatalf("%v", err)
	}
}

func TestLoginLockout(t *testing.T) {
	a, c, _ := registered(t)
	if err := a.Login(ctx, "1.1.1.1", "admin", pw); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Login(ctx, "1.1.1.1", "admin", "wrong password"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := a.Login(ctx, "1.1.1.1", "admin", pw); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected lock: %v", err)
	}
	if err := a.Login(ctx, "2.2.2.2", "admin", pw); err != nil {
		t.Fatalf("other ip: %v", err)
	}
	c.t = c.t.Add(11 * time.Minute)
	if err := a.Login(ctx, "1.1.1.1", "admin", pw); err != nil {
		t.Fatalf("after lock: %v", err)
	}
	if err := a.Login(ctx, "3.3.3.3", "nobody", pw); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestGlobalDelay(t *testing.T) {
	a, _, st := registered(t)
	add := func(n int) {
		for i := 0; i < n; i++ {
			st.DB.Exec(`INSERT INTO login_attempts(ip, at, success) VALUES (?, ?, 0)`, fmt.Sprintf("10.0.%d.%d", i/250, i%250), store.FormatTime(time.Date(2026, 11, 23, 11, 55, 0, 0, time.UTC)))
		}
	}
	add(25)
	if d, _ := a.Delay(ctx); d != time.Second {
		t.Fatalf("25 -> %v", d)
	}
	add(20)
	if d, _ := a.Delay(ctx); d != 2*time.Second {
		t.Fatalf("45 -> %v", d)
	}
	add(355)
	if d, _ := a.Delay(ctx); d != 8*time.Second {
		t.Fatalf("400 -> %v", d)
	}
}

func TestResetPassword(t *testing.T) {
	a, _, _ := newAuth(t)
	if err := a.ResetPassword(ctx, "new password!"); !errors.Is(err, ErrNoUser) {
		t.Fatalf("%v", err)
	}
	a, _, _ = registered(t)
	if err := a.ResetPassword(ctx, "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("%v", err)
	}
	if err := a.ResetPassword(ctx, "new password!"); err != nil {
		t.Fatal(err)
	}
	if err := a.Login(ctx, "1.1.1.1", "admin", "new password!"); err != nil {
		t.Fatal(err)
	}
}

func TestChangePasswordRequiresOld(t *testing.T) {
	a, _, _ := registered(t)
	if err := a.ChangePassword(ctx, "9.9.9.9", "nope nope nope", "another password"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("%v", err)
	}
	if err := a.ChangePassword(ctx, "9.9.9.9", pw, "another password"); err != nil {
		t.Fatal(err)
	}
	if err := a.Login(ctx, "1.1.1.1", "admin", "another password"); err != nil {
		t.Fatal(err)
	}
}

func TestPruneAttempts(t *testing.T) {
	a, c, st := registered(t)
	old := store.FormatTime(c.t.Add(-31 * 24 * time.Hour))
	st.DB.Exec(`INSERT INTO login_attempts(ip, at, success) VALUES ('x', ?, 1)`, old)
	tx, _ := st.DB.Begin()
	for i := 0; i < 1200; i++ {
		tx.Exec(`INSERT INTO login_attempts(ip, at, success) VALUES ('y', ?, 1)`, store.FormatTime(c.t))
	}
	tx.Commit()
	if err := a.PruneAttempts(ctx); err != nil {
		t.Fatal(err)
	}
	var n, nOld int
	st.DB.QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&n)
	st.DB.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE ip = 'x'`).Scan(&nOld)
	if n != 1000 || nOld != 0 {
		t.Fatalf("n %d old %d", n, nOld)
	}
	h, _ := a.LoginHistory(ctx, 50)
	if len(h) != 50 {
		t.Fatalf("history %d", len(h))
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.30:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIP(r, nil); got != "192.168.1.30" {
		t.Fatalf("untrusted: %s", got)
	}
	trusted := []netip.Prefix{netip.MustParsePrefix("192.168.1.2/32")}
	r.RemoteAddr = "192.168.1.2:5555"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 192.168.1.50")
	if got := ClientIP(r, trusted); got != "192.168.1.50" {
		t.Fatalf("trusted: %s", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := ClientIP(r, trusted); got != "192.168.1.2" {
		t.Fatalf("no header: %s", got)
	}
}

func TestLockoutHoldsUnderConcurrency(t *testing.T) {
	a, _, st := registered(t)
	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- a.Login(ctx, "10.0.0.9", "admin", "wrong password") }()
	}
	for i := 0; i < n; i++ {
		<-errs
	}
	var fails int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE success = 0`).Scan(&fails); err != nil {
		t.Fatal(err)
	}
	if fails > maxFailures {
		t.Fatalf("%d password checks ran for one IP; lockout allows %d", fails, maxFailures)
	}
}

func TestChangePasswordLockedAfterFailures(t *testing.T) {
	a, _, _ := registered(t)
	for i := 0; i < maxFailures; i++ {
		if err := a.ChangePassword(ctx, "9.9.9.9", "wrong guess "+string(rune('a'+i)), "another password"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := a.ChangePassword(ctx, "9.9.9.9", pw, "another password"); !errors.Is(err, ErrLocked) {
		t.Fatalf("guessing the current password must lock like a login: %v", err)
	}
	if err := a.Login(ctx, "9.9.9.9", "admin", pw); !errors.Is(err, ErrLocked) {
		t.Fatalf("login from the same address: %v", err)
	}
}
