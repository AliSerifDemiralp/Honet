package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// Presence event kinds.
const (
	EvPersonArrived = "person_arrived"
	EvPersonLeft    = "person_left"
)

// HomeWindow is how recently one of a person's devices must have been seen
// for the person to count as home.
const HomeWindow = 10 * time.Minute

// ErrBadName is returned for an empty or duplicate person name.
var ErrBadName = errors.New("name is empty or already used")

// Person is someone whose presence is derived from their devices.
type Person struct {
	ID      int64
	Name    string
	Home    bool
	Known   bool      // false until the first evaluation
	Since   time.Time // when the current state began
	Devices []Device
}

// Span is a stretch of time in one presence state.
type Span struct {
	From, To time.Time
	Home     bool
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// AddPerson creates a person and returns its id.
func (inv *Inventory) AddPerson(ctx context.Context, name string) (int64, error) {
	name = netutil.CleanText(name, 40)
	if name == "" {
		return 0, ErrBadName
	}
	res, err := inv.st.DB.ExecContext(ctx, `INSERT INTO people(name) VALUES (?) ON CONFLICT(name) DO NOTHING`, name)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrBadName
	}
	return res.LastInsertId()
}

// DeletePerson removes a person, their device links and presence history.
func (inv *Inventory) DeletePerson(ctx context.Context, id int64) error {
	return inv.execOne(ctx, `DELETE FROM people WHERE id = ?`, id)
}

// LinkDevice ties a LAN device to a person.
func (inv *Inventory) LinkDevice(ctx context.Context, personID, deviceID int64) error {
	var n int
	err := inv.st.DB.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM people WHERE id = ?) + (SELECT COUNT(*) FROM devices WHERE id = ?)`,
		personID, deviceID).Scan(&n)
	if err != nil {
		return err
	}
	if n != 2 {
		return ErrNotFound
	}
	_, err = inv.st.DB.ExecContext(ctx, `INSERT OR IGNORE INTO person_devices(person_id, device_id) VALUES (?, ?)`, personID, deviceID)
	return err
}

// UnlinkDevice removes a device from a person.
func (inv *Inventory) UnlinkDevice(ctx context.Context, personID, deviceID int64) error {
	return inv.execOne(ctx, `DELETE FROM person_devices WHERE person_id = ? AND device_id = ?`, personID, deviceID)
}

type presenceRow struct {
	home bool
	at   time.Time
}

func latestPresence(ctx context.Context, q rowQuerier, personID int64) (*presenceRow, error) {
	var state, at string
	err := q.QueryRowContext(ctx, `SELECT state, at FROM presence WHERE person_id = ? ORDER BY id DESC LIMIT 1`, personID).Scan(&state, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, _ := store.ParseTime(at)
	return &presenceRow{home: state == "home", at: t}, nil
}

func links(ctx context.Context, q rowQuerier) (map[int64][]int64, error) {
	rows, err := q.QueryContext(ctx, `SELECT person_id, device_id FROM person_devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64][]int64{}
	for rows.Next() {
		var p, d int64
		if err := rows.Scan(&p, &d); err != nil {
			return nil, err
		}
		m[p] = append(m[p], d)
	}
	return m, rows.Err()
}

type personRow struct {
	id   int64
	name string
}

func listPeople(ctx context.Context, q rowQuerier) ([]personRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM people ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []personRow
	for rows.Next() {
		var p personRow
		if err := rows.Scan(&p.id, &p.name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// People lists everyone with their current state and linked devices.
func (inv *Inventory) People(ctx context.Context) ([]Person, error) {
	ps, err := listPeople(ctx, inv.st.DB)
	if err != nil {
		return nil, err
	}
	lk, err := links(ctx, inv.st.DB)
	if err != nil {
		return nil, err
	}
	devs, err := inv.List(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	out := make([]Person, 0, len(ps))
	for _, pr := range ps {
		p := Person{ID: pr.id, Name: pr.name}
		for _, id := range lk[p.ID] {
			if d, ok := byID[id]; ok {
				p.Devices = append(p.Devices, d)
			}
		}
		last, err := latestPresence(ctx, inv.st.DB, p.ID)
		if err != nil {
			return nil, err
		}
		if last != nil {
			p.Known, p.Home, p.Since = true, last.home, last.at
		}
		out = append(out, p)
	}
	return out, nil
}

// EvaluatePresence records a state change for every person whose devices
// moved in or out of HomeWindow. A person's first state is recorded without
// an event. Nothing is written while the clock is unset.
func (inv *Inventory) EvaluatePresence(ctx context.Context) error {
	now := inv.now()
	if now.Year() < 2025 {
		return nil
	}
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		seen := map[int64]time.Time{}
		rows, err := tx.QueryContext(ctx, `SELECT id, last_seen FROM devices`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var ls string
			if err := rows.Scan(&id, &ls); err != nil {
				rows.Close()
				return err
			}
			seen[id], _ = store.ParseTime(ls)
		}
		rows.Close()
		lk, err := links(ctx, tx)
		if err != nil {
			return err
		}
		ps, err := listPeople(ctx, tx)
		if err != nil {
			return err
		}
		for _, p := range ps {
			home := false
			for _, d := range lk[p.id] {
				if t, ok := seen[d]; ok && !t.Before(now.Add(-HomeWindow)) {
					home = true
				}
			}
			last, err := latestPresence(ctx, tx, p.id)
			if err != nil {
				return err
			}
			if last != nil && last.home == home {
				continue
			}
			state, kind := "away", EvPersonLeft
			if home {
				state, kind = "home", EvPersonArrived
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO presence(person_id, state, at) VALUES (?, ?, ?)`,
				p.id, state, store.FormatTime(now)); err != nil {
				return err
			}
			if last == nil {
				continue
			}
			if err := addEvent(ctx, tx, now, kind, 0, p.name); err != nil {
				return err
			}
		}
		return nil
	})
}

// PresenceDays returns, for each of the last `days` local days (oldest
// first, today last), the presence spans clipped to that day. Today ends now.
func (inv *Inventory) PresenceDays(ctx context.Context, personID int64, days int) ([][]Span, error) {
	now := inv.now()
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT state, at FROM presence WHERE person_id = ? ORDER BY id`, personID)
	if err != nil {
		return nil, err
	}
	var hist []presenceRow
	for rows.Next() {
		var state, at string
		if err := rows.Scan(&state, &at); err != nil {
			rows.Close()
			return nil, err
		}
		t, _ := store.ParseTime(at)
		hist = append(hist, presenceRow{home: state == "home", at: t})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	loc := now.Location()
	y, m, d := now.Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, loc).AddDate(0, 0, -(days - 1))
	out := make([][]Span, days)
	for i := range out {
		ds := start.AddDate(0, 0, i)
		de := ds.AddDate(0, 0, 1)
		if de.After(now) {
			de = now
		}
		for k, h := range hist {
			from, to := h.at, now
			if k+1 < len(hist) {
				to = hist[k+1].at
			}
			if from.Before(ds) {
				from = ds
			}
			if to.After(de) {
				to = de
			}
			if to.After(from) {
				out[i] = append(out[i], Span{From: from.In(loc), To: to.In(loc), Home: h.home})
			}
		}
	}
	return out, nil
}

func prunePresence(ctx context.Context, db *sql.DB, cutoff time.Time) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM presence WHERE at < ? AND id NOT IN (SELECT MAX(id) FROM presence GROUP BY person_id)`,
		store.FormatTime(cutoff))
	return err
}
