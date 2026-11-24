package inventory

import (
	"context"
	"database/sql"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/store"
)

// SetWatch turns offline alerts for a device on or off. after = 0 uses the
// configured default; anything below one minute is raised to one minute.
func (inv *Inventory) SetWatch(ctx context.Context, id int64, on bool, after time.Duration) error {
	if after == 0 {
		s, err := inv.st.LoadSettings(ctx)
		if err != nil {
			return err
		}
		after = s.WatchAfter
	}
	if after < time.Minute {
		after = time.Minute
	}
	return inv.execOne(ctx, `UPDATE devices SET watched = ?, watch_after_s = ?, online = CASE WHEN ? THEN online ELSE 1 END WHERE id = ?`,
		on, int64(after/time.Second), on, id)
}

// EvaluateWatch marks watched devices offline when successful discoveries
// have kept missing them for longer than their threshold. lastGoodDiscovery
// is the time of the latest discovery that succeeded; without one recent
// enough nothing is marked, so a network outage cannot raise false alarms.
func (inv *Inventory) EvaluateWatch(ctx context.Context, lastGoodDiscovery time.Time) error {
	now := inv.now()
	if now.Year() < 2025 {
		return nil
	}
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT id, last_seen, watch_after_s FROM devices WHERE watched = 1 AND online = 1`)
	if err != nil {
		return err
	}
	type cand struct {
		id   int64
		seen time.Time
	}
	var off []cand
	for rows.Next() {
		var id, afterS int64
		var seenS string
		if err := rows.Scan(&id, &seenS, &afterS); err != nil {
			rows.Close()
			return err
		}
		seen, _ := store.ParseTime(seenS)
		if lastGoodDiscovery.After(seen.Add(time.Duration(afterS) * time.Second)) {
			off = append(off, cand{id, seen})
		}
	}
	rows.Close()
	if len(off) == 0 {
		return nil
	}
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		for _, c := range off {
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET online = 0 WHERE id = ?`, c.id); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, now, EvDeviceOffline, c.id, "last seen "+c.seen.Local().Format("02.01.2006 15:04")); err != nil {
				return err
			}
		}
		return nil
	})
}

// WatchedOffline lists watched devices currently marked offline.
func (inv *Inventory) WatchedOffline(ctx context.Context) ([]Device, error) {
	all, err := inv.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Device
	for _, d := range all {
		if d.Watched && !d.Online {
			out = append(out, d)
		}
	}
	return out, nil
}

// AckPort marks a risky open port as intentional (or clears the mark).
func (inv *Inventory) AckPort(ctx context.Context, id int64, port int, acked bool) error {
	return inv.execOne(ctx, `UPDATE device_ports SET acked = ? WHERE device_id = ? AND port = ?`, acked, id, port)
}

// ConfirmGateway accepts the pending gateway MAC as the new normal.
func (inv *Inventory) ConfirmGateway(ctx context.Context) error {
	_, err := inv.st.DB.ExecContext(ctx, `UPDATE gateway SET mac = pending_mac, pending_mac = '' WHERE id = 1 AND pending_mac <> ''`)
	return err
}

// Delete forgets a device, its ports, IP history and events.
func (inv *Inventory) Delete(ctx context.Context, id int64) error {
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE device_id = ?`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Prune deletes events older than 90 days and scan records older than 30 days.
func (inv *Inventory) Prune(ctx context.Context) error {
	now := inv.now()
	if now.Year() < 2025 {
		return nil
	}
	if _, err := inv.st.DB.ExecContext(ctx, `DELETE FROM events WHERE at < ?`, store.FormatTime(now.Add(-90*24*time.Hour))); err != nil {
		return err
	}
	if _, err := inv.st.DB.ExecContext(ctx, `DELETE FROM scans WHERE started < ?`, store.FormatTime(now.Add(-30*24*time.Hour))); err != nil {
		return err
	}
	if err := prunePresence(ctx, inv.st.DB, now.Add(-30*24*time.Hour)); err != nil {
		return err
	}
	return pruneInternet(ctx, inv.st.DB, now)
}
