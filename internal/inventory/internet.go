package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/netmon"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/speedtest"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// SpeedRow is one stored speed test; Error is set when it failed.
type SpeedRow struct {
	At       time.Time
	DownMbps float64
	UpMbps   float64
	LoadedMs float64
	Bytes    int64
	Error    string
}

// SaveSpeedTest stores a finished or failed speed test. Failures create no
// event: a stalled test server is not an internet outage.
func (inv *Inventory) SaveSpeedTest(ctx context.Context, at time.Time, r speedtest.Result, testErr error) error {
	msg := ""
	if testErr != nil {
		msg = netutil.CleanText(testErr.Error(), 200)
	}
	_, err := inv.st.DB.ExecContext(ctx,
		`INSERT INTO speedtests(at, down_mbps, up_mbps, loaded_ms, bytes, error) VALUES (?, ?, ?, ?, ?, ?)`,
		store.FormatTime(at), r.DownMbps, r.UpMbps, r.LoadedMs, r.Bytes, msg)
	return err
}

const speedCols = `at, down_mbps, up_mbps, loaded_ms, bytes, error`

func scanSpeed(r interface{ Scan(...any) error }) (SpeedRow, error) {
	var s SpeedRow
	var at string
	err := r.Scan(&at, &s.DownMbps, &s.UpMbps, &s.LoadedMs, &s.Bytes, &s.Error)
	s.At, _ = store.ParseTime(at)
	return s, err
}

// SpeedTests returns tests since the given time, oldest first.
func (inv *Inventory) SpeedTests(ctx context.Context, since time.Time) ([]SpeedRow, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT `+speedCols+` FROM speedtests WHERE at >= ? ORDER BY id`, store.FormatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpeedRow
	for rows.Next() {
		s, err := scanSpeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LastSpeedTest returns the newest test, or nil if there is none.
func (inv *Inventory) LastSpeedTest(ctx context.Context) (*SpeedRow, error) {
	s, err := scanSpeed(inv.st.DB.QueryRowContext(ctx, `SELECT `+speedCols+` FROM speedtests ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func pruneInternet(ctx context.Context, db *sql.DB, now time.Time) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM speedtests WHERE at < ?`, store.FormatTime(now.Add(-90*24*time.Hour))); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `DELETE FROM latency_5m WHERE at < ?`, store.FormatTime(now.Add(-30*24*time.Hour)))
	return err
}

// Internet event kinds.
const (
	EvInternetOutage   = "internet_outage"
	EvInternetRestored = "internet_restored"
)

const outageKey = "internet.outage_since"

// outageLoss is the packet loss at which a target counts as unreachable.
const outageLoss = 80

// SaveLatency stores the summaries of one window and records an outage
// when every internet target is unreachable while the gateway answers. If
// the gateway is unreachable too, this device lost the network, which is
// not an internet outage. Nothing is written while the clock is unset.
func (inv *Inventory) SaveLatency(ctx context.Context, sums []netmon.Summary) error {
	now := inv.now()
	if now.Year() < 2025 || len(sums) == 0 {
		return nil
	}
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		gwOK, inet, inetDown := false, 0, 0
		for _, s := range sums {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO latency_5m(at, target, min_ms, avg_ms, max_ms, jitter_ms, loss_pct, dns_ms)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, store.FormatTime(s.At), s.Target, s.MinMs, s.AvgMs, s.MaxMs, s.JitterMs, s.LossPct, s.DNSMs); err != nil {
				return err
			}
			if s.Target == netmon.GatewayTarget {
				gwOK = s.LossPct < outageLoss
				continue
			}
			inet++
			if s.LossPct >= outageLoss {
				inetDown++
			}
		}
		var since string
		err := tx.QueryRowContext(ctx, `SELECT value FROM kv WHERE key = ?`, outageKey).Scan(&since)
		open := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		switch {
		case inet == 0 && open:
			// The user removed every internet target: nothing can end the
			// outage any more, so close it instead of letting it run forever.
			if _, err := tx.ExecContext(ctx, `DELETE FROM kv WHERE key = ?`, outageKey); err != nil {
				return err
			}
			return addEvent(ctx, tx, now, EvInternetRestored, 0, "no longer monitored")
		case inet == 0:
			return nil
		case !open && gwOK && inetDown == inet:
			if _, err := tx.ExecContext(ctx, `INSERT INTO kv(key, value) VALUES (?, ?)`, outageKey, store.FormatTime(now)); err != nil {
				return err
			}
			return addEvent(ctx, tx, now, EvInternetOutage, 0, "")
		case open && inetDown < inet:
			if _, err := tx.ExecContext(ctx, `DELETE FROM kv WHERE key = ?`, outageKey); err != nil {
				return err
			}
			detail := ""
			if t, err := store.ParseTime(since); err == nil {
				detail = "after " + now.Sub(t).Round(time.Minute).String()
			}
			return addEvent(ctx, tx, now, EvInternetRestored, 0, detail)
		}
		return nil
	})
}

func (inv *Inventory) latency(ctx context.Context, where string, args ...any) ([]netmon.Summary, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT at, target, min_ms, avg_ms, max_ms, jitter_ms, loss_pct, dns_ms FROM latency_5m WHERE `+where+` ORDER BY at, target`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netmon.Summary
	for rows.Next() {
		var s netmon.Summary
		var at string
		if err := rows.Scan(&at, &s.Target, &s.MinMs, &s.AvgMs, &s.MaxMs, &s.JitterMs, &s.LossPct, &s.DNSMs); err != nil {
			return nil, err
		}
		s.At, _ = store.ParseTime(at)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Latency returns the summaries since the given time, oldest first.
func (inv *Inventory) Latency(ctx context.Context, since time.Time) ([]netmon.Summary, error) {
	return inv.latency(ctx, `at >= ?`, store.FormatTime(since))
}

// LatestLatency returns the newest window's summaries, one per target.
func (inv *Inventory) LatestLatency(ctx context.Context) ([]netmon.Summary, error) {
	return inv.latency(ctx, `at = (SELECT MAX(at) FROM latency_5m)`)
}

// OutageSpan is one internet outage; To is now for an ongoing one.
type OutageSpan struct{ From, To time.Time }

// Outages pairs outage and restore events since the given time.
func (inv *Inventory) Outages(ctx context.Context, since time.Time) ([]OutageSpan, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT at, kind FROM events WHERE kind IN (?, ?) AND at >= ? ORDER BY id`,
		EvInternetOutage, EvInternetRestored, store.FormatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutageSpan
	var open *time.Time
	for rows.Next() {
		var at, kind string
		if err := rows.Scan(&at, &kind); err != nil {
			return nil, err
		}
		t, _ := store.ParseTime(at)
		switch {
		case kind == EvInternetOutage:
			open = &t
		case open != nil:
			out = append(out, OutageSpan{*open, t})
			open = nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if open != nil {
		// An ongoing outage is only known up to the last measurement; if
		// the monitor was turned off, do not extend it to now.
		end := inv.now()
		var last sql.NullString
		if err := inv.st.DB.QueryRowContext(ctx, `SELECT MAX(at) FROM latency_5m`).Scan(&last); err != nil {
			return nil, err
		}
		if t, err := store.ParseTime(last.String); last.Valid && err == nil && t.Add(netmon.Window).Before(end) {
			end = t.Add(netmon.Window)
		}
		if end.Before(*open) {
			end = *open
		}
		out = append(out, OutageSpan{*open, end})
	}
	return out, nil
}
