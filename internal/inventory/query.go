package inventory

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/risk"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

const deviceCols = `id, mac, name, notes, vendor, hostname, http_info, is_gateway, ports_scanned, auto_type, manual_type, known, randomized, is_self,
	watched, online, watch_after_s, last_ip, first_seen, last_seen`

type scanner interface{ Scan(dest ...any) error }

func scanDevice(r scanner) (Device, error) {
	var d Device
	var lastIP, first, last string
	var watchS int64
	err := r.Scan(&d.ID, &d.MAC, &d.Name, &d.Notes, &d.Vendor, &d.Hostname, &d.HTTPInfo, &d.Gateway, &d.Probed, &d.AutoType, &d.ManualType,
		&d.Known, &d.Randomized, &d.Self, &d.Watched, &d.Online, &watchS, &lastIP, &first, &last)
	if err != nil {
		return d, err
	}
	if len(d.MAC) > 3 && d.MAC[:3] == "ip:" {
		d.MAC = ""
	}
	d.WatchAfter = time.Duration(watchS) * time.Second
	d.LastIP, _ = netip.ParseAddr(lastIP)
	d.FirstSeen, _ = store.ParseTime(first)
	d.LastSeen, _ = store.ParseTime(last)
	return d, nil
}

func (inv *Inventory) loadPorts(ctx context.Context) (map[int64][]Port, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT device_id, port, open, acked, first_seen, last_seen FROM device_ports ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]Port{}
	for rows.Next() {
		var id int64
		var p Port
		var first, last string
		if err := rows.Scan(&id, &p.Port, &p.Open, &p.Acked, &first, &last); err != nil {
			return nil, err
		}
		if r, ok := risk.Lookup(p.Port); ok {
			p.Risk = &r
		}
		p.FirstSeen, _ = store.ParseTime(first)
		p.LastSeen, _ = store.ParseTime(last)
		out[id] = append(out[id], p)
	}
	return out, rows.Err()
}

// List returns all devices, unrecognised ones first, then by IP.
func (inv *Inventory) List(ctx context.Context) ([]Device, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices`)
	if err != nil {
		return nil, err
	}
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	ports, err := inv.loadPorts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Ports = ports[out[i].ID]
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unknown() != out[j].Unknown() {
			return out[i].Unknown()
		}
		return out[i].LastIP.Less(out[j].LastIP)
	})
	return out, nil
}

// Get returns one device with its IP history and its last 50 events.
func (inv *Inventory) Get(ctx context.Context, id int64) (Device, []IPRecord, []Event, error) {
	d, err := scanDevice(inv.st.DB.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil, nil, ErrNotFound
	}
	if err != nil {
		return d, nil, nil, err
	}
	ports, err := inv.loadPorts(ctx)
	if err != nil {
		return d, nil, nil, err
	}
	d.Ports = ports[id]
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT ip, first_seen, last_seen FROM ip_history WHERE device_id = ? ORDER BY last_seen DESC`, id)
	if err != nil {
		return d, nil, nil, err
	}
	var ips []IPRecord
	for rows.Next() {
		var r IPRecord
		var ip, first, last string
		if err := rows.Scan(&ip, &first, &last); err != nil {
			rows.Close()
			return d, nil, nil, err
		}
		r.IP, _ = netip.ParseAddr(ip)
		r.FirstSeen, _ = store.ParseTime(first)
		r.LastSeen, _ = store.ParseTime(last)
		ips = append(ips, r)
	}
	rows.Close()
	evs, err := inv.queryEvents(ctx, `WHERE e.device_id = ?`, 50, id)
	return d, ips, evs, err
}

// OnlineIDs returns devices seen at or after since.
func (inv *Inventory) OnlineIDs(ctx context.Context, since time.Time) ([]int64, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT id FROM devices WHERE last_seen >= ? ORDER BY id`, store.FormatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// IPOf returns the last known IP of a device.
func (inv *Inventory) IPOf(ctx context.Context, id int64) (netip.Addr, error) {
	var ip string
	err := inv.st.DB.QueryRowContext(ctx, `SELECT last_ip FROM devices WHERE id = ?`, id).Scan(&ip)
	if errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, ErrNotFound
	}
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(ip)
}

func (inv *Inventory) queryEvents(ctx context.Context, where string, limit int, args ...any) ([]Event, error) {
	q := `SELECT e.id, e.at, e.kind, COALESCE(e.device_id, 0), COALESCE(d.name, ''), COALESCE(d.hostname, ''), COALESCE(d.last_ip, ''), e.detail, e.read
		FROM events e LEFT JOIN devices d ON d.id = e.device_id ` + where + ` ORDER BY e.at DESC, e.id DESC LIMIT ?`
	rows, err := inv.st.DB.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, name, host, ip string
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.DeviceID, &name, &host, &ip, &e.Detail, &e.Read); err != nil {
			return nil, err
		}
		e.At, _ = store.ParseTime(at)
		switch {
		case name != "":
			e.DeviceName = name
		case host != "":
			e.DeviceName = host
		default:
			e.DeviceName = ip
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Events returns the newest events.
func (inv *Inventory) Events(ctx context.Context, limit int) ([]Event, error) {
	return inv.queryEvents(ctx, "", limit)
}

// EventsSince returns the newest events at or after since.
func (inv *Inventory) EventsSince(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	return inv.queryEvents(ctx, "WHERE e.at >= ?", limit, store.FormatTime(since))
}

// EventCounts counts events per kind at or after since.
func (inv *Inventory) EventCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := inv.st.DB.QueryContext(ctx, `SELECT kind, COUNT(*) FROM events WHERE at >= ? GROUP BY kind`, store.FormatTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// UnreadCount returns how many events are unread.
func (inv *Inventory) UnreadCount(ctx context.Context) (int, error) {
	var n int
	err := inv.st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE read = 0`).Scan(&n)
	return n, err
}

// MarkAllRead marks every event read.
func (inv *Inventory) MarkAllRead(ctx context.Context) error {
	_, err := inv.st.DB.ExecContext(ctx, `UPDATE events SET read = 1 WHERE read = 0`)
	return err
}

// GatewayAlert returns the unconfirmed gateway MAC change, or nil.
func (inv *Inventory) GatewayAlert(ctx context.Context) (*GatewayAlert, error) {
	var ip, mac, pending string
	err := inv.st.DB.QueryRowContext(ctx, `SELECT ip, mac, pending_mac FROM gateway WHERE id = 1 AND pending_mac <> ''`).Scan(&ip, &mac, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := &GatewayAlert{OldMAC: mac, NewMAC: pending}
	a.IP, _ = netip.ParseAddr(ip)
	return a, nil
}
