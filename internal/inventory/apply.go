package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/classify"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
	"github.com/AliSerifDemiralp/honet/internal/risk"
	"github.com/AliSerifDemiralp/honet/internal/scan/lan"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

func deviceKey(h lan.Host) string {
	if h.MAC != "" {
		return h.MAC
	}
	return "ip:" + h.IP.String()
}

func addEvent(ctx context.Context, tx *sql.Tx, at time.Time, kind string, deviceID int64, detail string) error {
	var dev any
	if deviceID != 0 {
		dev = deviceID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO events(at, kind, device_id, detail) VALUES (?, ?, ?, ?)`,
		store.FormatTime(at), kind, dev, detail)
	return err
}

// ApplyDiscovery records a discovery result in one transaction and returns
// the ids of devices that need a port probe (new devices and IP changes).
func (inv *Inventory) ApplyDiscovery(ctx context.Context, hosts []lan.Host, gw netip.Addr) ([]int64, error) {
	others := 0
	for _, h := range hosts {
		if !h.Self {
			others++
		}
	}
	if others == 0 {
		return nil, ErrEmptyDiscovery
	}
	now := inv.now()
	ts := store.FormatTime(now)
	var need []int64
	err := inv.st.Tx(ctx, func(tx *sql.Tx) error {
		if err := recordConflicts(ctx, tx, hosts, now); err != nil {
			return err
		}
		// Without a known gateway (no route, or a range this host is not
		// attached to) no device is claimed to be the gateway.
		if err := clearGateway(ctx, tx, gw); err != nil {
			return err
		}
		for _, h := range hosts {
			id, needPorts, err := upsertDevice(ctx, tx, h, gw.IsValid() && h.IP == gw, now, ts)
			if err != nil {
				return err
			}
			if needPorts {
				need = append(need, id)
			}
		}
		if gw.IsValid() {
			return checkGateway(ctx, tx, hosts, gw, now)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return need, nil
}

func recordConflicts(ctx context.Context, tx *sql.Tx, hosts []lan.Host, now time.Time) error {
	byIP := map[netip.Addr][]string{}
	for _, h := range hosts {
		if h.MAC != "" && !contains(byIP[h.IP], h.MAC) {
			byIP[h.IP] = append(byIP[h.IP], h.MAC)
		}
	}
	for ip, macs := range byIP {
		if len(macs) < 2 {
			continue
		}
		sort.Strings(macs)
		detail := fmt.Sprintf("%s answered from %s", ip, strings.Join(macs, " and "))
		var n int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE kind = ? AND detail = ? AND at >= ?`,
			EvIPConflict, detail, store.FormatTime(now.Add(-time.Hour))).Scan(&n)
		if err != nil {
			return err
		}
		if n == 0 {
			if err := addEvent(ctx, tx, now, EvIPConflict, 0, detail); err != nil {
				return err
			}
		}
	}
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func upsertDevice(ctx context.Context, tx *sql.Tx, h lan.Host, isGW bool, now time.Time, ts string) (int64, bool, error) {
	key := deviceKey(h)
	var (
		id              int64
		lastIP          string
		online, watched bool
	)
	var probed bool
	err := tx.QueryRowContext(ctx, `SELECT id, last_ip, online, watched, ports_scanned FROM devices WHERE mac = ?`, key).
		Scan(&id, &lastIP, &online, &watched, &probed)
	needPorts := err == nil && !probed && !h.Self // an earlier port scan was interrupted
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `INSERT INTO devices(mac, vendor, hostname, last_ip, randomized, is_self, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, key, h.Vendor, h.Hostname, h.IP.String(), h.Randomized, h.Self, ts, ts)
		if err != nil {
			return 0, false, err
		}
		id, _ = res.LastInsertId()
		needPorts = true
		if !h.Self {
			if err := addEvent(ctx, tx, now, EvNewDevice, id, h.IP.String()); err != nil {
				return 0, false, err
			}
		}
	case err != nil:
		return 0, false, err
	default:
		if lastIP != h.IP.String() {
			needPorts = true
			if err := addEvent(ctx, tx, now, EvIPChanged, id, lastIP+" → "+h.IP.String()); err != nil {
				return 0, false, err
			}
		}
		if watched && !online {
			if err := addEvent(ctx, tx, now, EvDeviceOnline, id, h.IP.String()); err != nil {
				return 0, false, err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET last_ip = ?, last_seen = ?, online = 1, is_self = ?, randomized = ?,
			vendor = CASE WHEN ? <> '' THEN ? ELSE vendor END,
			hostname = CASE WHEN ? <> '' THEN ? ELSE hostname END
			WHERE id = ?`, h.IP.String(), ts, h.Self, h.Randomized, h.Vendor, h.Vendor, h.Hostname, h.Hostname, id)
		if err != nil {
			return 0, false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ip_history(device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = excluded.last_seen`, id, h.IP.String(), ts, ts); err != nil {
		return 0, false, err
	}
	if isGW {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET is_gateway = 1 WHERE id = ?`, id); err != nil {
			return 0, false, err
		}
	}
	return id, needPorts, reclassify(ctx, tx, id)
}

// clearGateway drops the gateway flag from every device but the one at gw
// (all of them if gw is unknown) and updates their type guess.
func clearGateway(ctx context.Context, tx *sql.Tx, gw netip.Addr) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM devices WHERE is_gateway = 1 AND last_ip <> ?`, gw.String())
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET is_gateway = 0 WHERE id = ?`, id); err != nil {
			return err
		}
		if err := reclassify(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

func reclassify(ctx context.Context, tx *sql.Tx, id int64) error {
	var in classify.Input
	if err := tx.QueryRowContext(ctx, `SELECT vendor, hostname, http_info, randomized, is_gateway FROM devices WHERE id = ?`, id).
		Scan(&in.Vendor, &in.Hostname, &in.HTTP, &in.Randomized, &in.Gateway); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT port FROM device_ports WHERE device_id = ? AND open = 1 ORDER BY port`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		in.Ports = append(in.Ports, p)
	}
	rows.Close()
	_, err = tx.ExecContext(ctx, `UPDATE devices SET auto_type = ? WHERE id = ?`, classify.Classify(in), id)
	return err
}

// SetHTTPInfo stores the device's web page title (or Server header) and
// updates its type guess.
func (inv *Inventory) SetHTTPInfo(ctx context.Context, id int64, info string) error {
	info = netutil.CleanText(info, 64)
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE devices SET http_info = ? WHERE id = ?`, info, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return reclassify(ctx, tx, id)
	})
}

func checkGateway(ctx context.Context, tx *sql.Tx, hosts []lan.Host, gw netip.Addr, now time.Time) error {
	var seen []string
	for _, h := range hosts {
		if h.IP == gw && h.MAC != "" && !h.Self {
			seen = append(seen, h.MAC)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	var ip, mac, pending string
	err := tx.QueryRowContext(ctx, `SELECT ip, mac, pending_mac FROM gateway WHERE id = 1`).Scan(&ip, &mac, &pending)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && ip != gw.String()) {
		_, err := tx.ExecContext(ctx, `INSERT INTO gateway(id, ip, mac, pending_mac) VALUES (1, ?, ?, '')
			ON CONFLICT(id) DO UPDATE SET ip = excluded.ip, mac = excluded.mac, pending_mac = ''`, gw.String(), seen[0])
		return err
	}
	if err != nil {
		return err
	}
	for _, m := range seen {
		if m == mac || m == pending {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE gateway SET pending_mac = ? WHERE id = 1`, m); err != nil {
			return err
		}
		return addEvent(ctx, tx, now, EvGatewayMACChanged, 0, fmt.Sprintf("%s: %s → %s", gw, mac, m))
	}
	return nil
}

// ApplyPorts records a port probe of one device.
func (inv *Inventory) ApplyPorts(ctx context.Context, id int64, open []int) error {
	return inv.ApplyPortScan(ctx, id, nil, open)
}

// ApplyPortScan records a scan of the probed ports (nil: every known port)
// that found open open. Ports outside probed keep their state.
func (inv *Inventory) ApplyPortScan(ctx context.Context, id int64, probed, open []int) error {
	now := inv.now()
	ts := store.FormatTime(now)
	return inv.st.Tx(ctx, func(tx *sql.Tx) error {
		var scanned bool
		if err := tx.QueryRowContext(ctx, `SELECT ports_scanned FROM devices WHERE id = ?`, id).Scan(&scanned); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT port, open FROM device_ports WHERE device_id = ?`, id)
		if err != nil {
			return err
		}
		existing := map[int]bool{}
		for rows.Next() {
			var p int
			var o bool
			if err := rows.Scan(&p, &o); err != nil {
				rows.Close()
				return err
			}
			existing[p] = o
		}
		rows.Close()
		nowOpen := map[int]bool{}
		for _, p := range open {
			nowOpen[p] = true
			wasOpen, known := existing[p]
			if _, err := tx.ExecContext(ctx, `INSERT INTO device_ports(device_id, port, open, first_seen, last_seen) VALUES (?, ?, 1, ?, ?)
				ON CONFLICT(device_id, port) DO UPDATE SET open = 1, last_seen = excluded.last_seen`, id, p, ts, ts); err != nil {
				return err
			}
			if scanned && (!known || !wasOpen) {
				if err := addEvent(ctx, tx, now, EvPortOpened, id, portLabel(p)); err != nil {
					return err
				}
			}
		}
		inScan := func(p int) bool { return probed == nil || slices.Contains(probed, p) }
		for p, wasOpen := range existing {
			if wasOpen && !nowOpen[p] && inScan(p) {
				if _, err := tx.ExecContext(ctx, `UPDATE device_ports SET open = 0, last_seen = ? WHERE device_id = ? AND port = ?`, ts, id, p); err != nil {
					return err
				}
				if err := addEvent(ctx, tx, now, EvPortClosed, id, portLabel(p)); err != nil {
					return err
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET ports_scanned = 1 WHERE id = ?`, id); err != nil {
			return err
		}
		return reclassify(ctx, tx, id)
	})
}

func portLabel(p int) string {
	if r, ok := risk.Lookup(p); ok {
		return fmt.Sprintf("port %d (%s)", p, r.Name)
	}
	return fmt.Sprintf("port %d", p)
}
