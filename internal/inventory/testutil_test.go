package inventory

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

var ctx = context.Background()

func newInv(t *testing.T) (*Inventory, *clock, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &clock{t: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	return New(st, c.now), c, st
}

func host(ip, mac string) lan.Host {
	return lan.Host{IP: netip.MustParseAddr(ip), MAC: mac}
}

var noGW netip.Addr

func countEvents(t *testing.T, st *store.Store, kind string) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = ?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustList(t *testing.T, inv *Inventory) []Device {
	t.Helper()
	d, err := inv.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
