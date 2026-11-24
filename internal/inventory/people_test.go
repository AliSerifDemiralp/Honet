package inventory

import (
	"strings"
	"testing"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
)

// seen adds a LAN device seen now and returns its id.
func seen(t *testing.T, inv *Inventory, ip, mac string) int64 {
	t.Helper()
	if _, err := inv.ApplyDiscovery(ctx, []lan.Host{host(ip, mac), host("192.168.1.250", "02:00:00:00:00:fe")}, noGW); err != nil {
		t.Fatal(err)
	}
	for _, d := range mustList(t, inv) {
		if d.MAC == mac {
			return d.ID
		}
	}
	t.Fatalf("device %s not found", mac)
	return 0
}

func person(t *testing.T, inv *Inventory, name string) Person {
	t.Helper()
	ps, err := inv.People(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("person %q not found", name)
	return Person{}
}

func TestPresenceHomeAway(t *testing.T) {
	inv, c, st := newInv(t)
	dev := seen(t, inv, "192.168.1.10", "aa:bb:cc:00:00:01")
	pid, err := inv.AddPerson(ctx, "Ayşe")
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.LinkDevice(ctx, pid, dev); err != nil {
		t.Fatal(err)
	}
	if err := inv.EvaluatePresence(ctx); err != nil {
		t.Fatal(err)
	}
	if p := person(t, inv, "Ayşe"); !p.Home || !p.Known {
		t.Fatalf("want home, got %+v", p)
	}
	if countEvents(t, st, EvPersonArrived)+countEvents(t, st, EvPersonLeft) != 0 {
		t.Fatal("first evaluation must not create an event")
	}
	c.advance(11 * time.Minute)
	inv.EvaluatePresence(ctx)
	inv.EvaluatePresence(ctx)
	if p := person(t, inv, "Ayşe"); p.Home {
		t.Fatal("want away after 11 minutes")
	}
	if countEvents(t, st, EvPersonLeft) != 1 {
		t.Fatalf("left events %d", countEvents(t, st, EvPersonLeft))
	}
	seen(t, inv, "192.168.1.10", "aa:bb:cc:00:00:01")
	inv.EvaluatePresence(ctx)
	if countEvents(t, st, EvPersonArrived) != 1 {
		t.Fatal("want one arrived event")
	}
	var detail string
	st.DB.QueryRow(`SELECT detail FROM events WHERE kind = ?`, EvPersonArrived).Scan(&detail)
	if detail != "Ayşe" {
		t.Fatalf("detail %q", detail)
	}
}

func TestPresenceAnyDevice(t *testing.T) {
	inv, c, _ := newInv(t)
	old := seen(t, inv, "192.168.1.10", "aa:bb:cc:00:00:01")
	c.advance(time.Hour)
	recent := seen(t, inv, "192.168.1.11", "aa:bb:cc:00:00:02")
	pid, _ := inv.AddPerson(ctx, "Ali")
	inv.LinkDevice(ctx, pid, old)
	inv.LinkDevice(ctx, pid, recent)
	inv.EvaluatePresence(ctx)
	p := person(t, inv, "Ali")
	if !p.Home || len(p.Devices) != 2 {
		t.Fatalf("%+v", p)
	}
}

func TestPresenceNoWriteWithBadClock(t *testing.T) {
	inv, c, st := newInv(t)
	dev := seen(t, inv, "192.168.1.10", "aa:bb:cc:00:00:01")
	pid, _ := inv.AddPerson(ctx, "Ali")
	inv.LinkDevice(ctx, pid, dev)
	c.t = time.Date(1970, 1, 1, 0, 5, 0, 0, time.UTC)
	if err := inv.EvaluatePresence(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM presence`).Scan(&n)
	if n != 0 {
		t.Fatalf("presence rows %d", n)
	}
}

func TestPresenceDaysSplitsAtMidnight(t *testing.T) {
	inv, c, st := newInv(t)
	pid, _ := inv.AddPerson(ctx, "Ali")
	c.t = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	ins := func(state string, at time.Time) {
		st.DB.Exec(`INSERT INTO presence(person_id, state, at) VALUES (?, ?, ?)`, pid, state, at.Format(time.RFC3339Nano))
	}
	ins("home", time.Date(2026, 11, 22, 22, 0, 0, 0, time.UTC))
	ins("away", time.Date(2026, 11, 23, 2, 0, 0, 0, time.UTC))
	days, err := inv.PresenceDays(ctx, pid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 2 {
		t.Fatalf("days %d", len(days))
	}
	h := func(hh int, d int) time.Time { return time.Date(2026, 11, d, hh, 0, 0, 0, time.UTC) }
	want0 := []Span{{h(22, 22), h(0, 23), true}}
	want1 := []Span{{h(0, 23), h(2, 23), true}, {h(2, 23), h(10, 23), false}}
	if !spansEq(days[0], want0) || !spansEq(days[1], want1) {
		t.Fatalf("got %+v", days)
	}
}

func spansEq(a, b []Span) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].From.Equal(b[i].From) || !a[i].To.Equal(b[i].To) || a[i].Home != b[i].Home {
			return false
		}
	}
	return true
}

func TestPrunePresenceKeepsLatest(t *testing.T) {
	inv, c, st := newInv(t)
	pid, _ := inv.AddPerson(ctx, "Ali")
	for i := 0; i < 3; i++ {
		st.DB.Exec(`INSERT INTO presence(person_id, state, at) VALUES (?, 'home', ?)`, pid,
			c.t.Add(-time.Duration(40+i)*24*time.Hour).Format(time.RFC3339Nano))
	}
	if err := inv.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM presence`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows %d, want the latest kept", n)
	}
}

func TestPersonDeviceDeletedCascades(t *testing.T) {
	inv, _, _ := newInv(t)
	dev := seen(t, inv, "192.168.1.10", "aa:bb:cc:00:00:01")
	pid, _ := inv.AddPerson(ctx, "Ali")
	inv.LinkDevice(ctx, pid, dev)
	if err := inv.Delete(ctx, dev); err != nil {
		t.Fatal(err)
	}
	if err := inv.EvaluatePresence(ctx); err != nil {
		t.Fatal(err)
	}
	p := person(t, inv, "Ali")
	if p.Home || len(p.Devices) != 0 {
		t.Fatalf("%+v", p)
	}
	if err := inv.LinkDevice(ctx, pid, 9999); err != ErrNotFound {
		t.Fatalf("link to missing device: %v", err)
	}
}

func TestAddPersonCleansName(t *testing.T) {
	inv, _, _ := newInv(t)
	if _, err := inv.AddPerson(ctx, "  \x07 "); err != ErrBadName {
		t.Fatalf("blank name: %v", err)
	}
	if _, err := inv.AddPerson(ctx, "<b>"+strings.Repeat("x", 100)+"\x00"); err != nil {
		t.Fatal(err)
	}
	ps, _ := inv.People(ctx)
	if len(ps) != 1 || len([]rune(ps[0].Name)) > 40 || strings.ContainsRune(ps[0].Name, 0) {
		t.Fatalf("%q", ps[0].Name)
	}
	if _, err := inv.AddPerson(ctx, ps[0].Name); err != ErrBadName {
		t.Fatalf("duplicate: %v", err)
	}
}
