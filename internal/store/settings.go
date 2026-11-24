package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Settings are the user-editable options, stored in the kv table.
type Settings struct {
	CIDR              string // "" = the interface's own subnet
	Interface         string // "" = default-route interface
	DiscoveryInterval time.Duration
	PortInterval      time.Duration
	SessionIdle       time.Duration
	WatchAfter        time.Duration
	TrustedProxies    []netip.Prefix
	SpeedInterval     time.Duration // 0 = no scheduled speed tests
	LatencyInterval   time.Duration // 0 = latency monitor off
	LatencyTargets    []string      // IP addresses pinged besides the gateway
	PiLimitMbps       float64       // results near this are flagged as Pi-limited
}

// DefaultSettings returns the settings used when nothing is stored.
func DefaultSettings() Settings {
	return Settings{
		DiscoveryInterval: 5 * time.Minute,
		PortInterval:      time.Hour,
		SessionIdle:       15 * time.Minute,
		WatchAfter:        15 * time.Minute,
		SpeedInterval:     3 * time.Hour,
		LatencyInterval:   time.Minute,
		LatencyTargets:    []string{"1.1.1.1", "8.8.8.8"},
		PiLimitMbps:       25,
	}
}

// GetKV returns the value for key and whether it exists.
func (s *Store) GetKV(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetKV stores value under key.
func (s *Store) SetKV(ctx context.Context, key, val string) error {
	_, err := s.DB.ExecContext(ctx, upsertKV, key, val)
	return err
}

// DeleteKV removes key.
func (s *Store) DeleteKV(ctx context.Context, key string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM kv WHERE key = ?`, key)
	return err
}

const upsertKV = `INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`

type durKey struct {
	key string
	ptr func(*Settings) *time.Duration
}

var durKeys = []durKey{
	{"settings.discovery_interval_s", func(s *Settings) *time.Duration { return &s.DiscoveryInterval }},
	{"settings.port_interval_s", func(s *Settings) *time.Duration { return &s.PortInterval }},
	{"settings.session_idle_s", func(s *Settings) *time.Duration { return &s.SessionIdle }},
	{"settings.watch_after_s", func(s *Settings) *time.Duration { return &s.WatchAfter }},
	{"settings.speed_interval_s", func(s *Settings) *time.Duration { return &s.SpeedInterval }},
	{"settings.latency_interval_s", func(s *Settings) *time.Duration { return &s.LatencyInterval }},
}

// LoadSettings returns stored settings, with defaults for missing keys.
func (s *Store) LoadSettings(ctx context.Context) (Settings, error) {
	v := DefaultSettings()
	rows, err := s.DB.QueryContext(ctx, `SELECT key, value FROM kv WHERE key LIKE 'settings.%'`)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, val string
		if err := rows.Scan(&k, &val); err != nil {
			return v, err
		}
		m[k] = val
	}
	if err := rows.Err(); err != nil {
		return v, err
	}
	v.CIDR = m["settings.cidr"]
	v.Interface = m["settings.interface"]
	for _, d := range durKeys {
		if raw, ok := m[d.key]; ok {
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
				*d.ptr(&v) = time.Duration(n) * time.Second
			}
		}
	}
	if raw := m["settings.trusted_proxies"]; raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if pf, err := netip.ParsePrefix(p); err == nil {
				v.TrustedProxies = append(v.TrustedProxies, pf)
			}
		}
	}
	if raw, ok := m["settings.latency_targets"]; ok {
		v.LatencyTargets = nil
		if raw != "" {
			v.LatencyTargets = strings.Split(raw, ",")
		}
	}
	if raw, ok := m["settings.pi_limit_mbps"]; ok {
		if f, err := strconv.ParseFloat(raw, 64); err == nil {
			v.PiLimitMbps = f
		}
	}
	return v, nil
}

// SaveSettings stores all settings in one transaction.
func (s *Store) SaveSettings(ctx context.Context, v Settings) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		proxies := make([]string, len(v.TrustedProxies))
		for i, p := range v.TrustedProxies {
			proxies[i] = p.String()
		}
		kvs := [][2]string{
			{"settings.cidr", v.CIDR},
			{"settings.interface", v.Interface},
			{"settings.trusted_proxies", strings.Join(proxies, ",")},
			{"settings.latency_targets", strings.Join(v.LatencyTargets, ",")},
			{"settings.pi_limit_mbps", strconv.FormatFloat(v.PiLimitMbps, 'g', -1, 64)},
		}
		for _, d := range durKeys {
			kvs = append(kvs, [2]string{d.key, strconv.FormatInt(int64(*d.ptr(&v)/time.Second), 10)})
		}
		for _, kv := range kvs {
			if _, err := tx.ExecContext(ctx, upsertKV, kv[0], kv[1]); err != nil {
				return err
			}
		}
		return nil
	})
}
